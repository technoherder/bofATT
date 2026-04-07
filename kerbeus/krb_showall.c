/*
 * krb_showall - Show all Kerberos tickets from all logon sessions
 *
 * Enumerates all logon sessions and displays their cached Kerberos tickets.
 * Requires elevation for sessions other than the current user's.
 *
 * Usage: krb_showall [/service:FILTER] [/client:FILTER]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"


DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);

/* Format FILETIME to string */
static void format_filetime(LARGE_INTEGER* ft, char* buf, size_t bufsize) {
    FILETIME fileTime;
    SYSTEMTIME sysTime;

    fileTime.dwLowDateTime = ft->LowPart;
    fileTime.dwHighDateTime = ft->HighPart;

    if (ft->QuadPart == 0) {
        strcpy(buf, "N/A");
        return;
    }

    if (KERNEL32$FileTimeToSystemTime(&fileTime, &sysTime)) {
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
            sysTime.wYear, sysTime.wMonth, sysTime.wDay,
            sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
    } else {
        strcpy(buf, "Invalid");
    }
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

/* Get ticket flags as string */
static void format_ticket_flags(ULONG flags, char* buf, size_t bufsize) {
    buf[0] = '\0';
    if (flags & TICKETFLAG_FORWARDABLE) strcat(buf, "forwardable ");
    if (flags & TICKETFLAG_FORWARDED) strcat(buf, "forwarded ");
    if (flags & TICKETFLAG_PROXIABLE) strcat(buf, "proxiable ");
    if (flags & TICKETFLAG_PROXY) strcat(buf, "proxy ");
    if (flags & TICKETFLAG_RENEWABLE) strcat(buf, "renewable ");
    if (flags & TICKETFLAG_INITIAL) strcat(buf, "initial ");
    if (flags & TICKETFLAG_PRE_AUTHENT) strcat(buf, "pre_authent ");
    if (flags & TICKETFLAG_OK_AS_DELEGATE) strcat(buf, "ok_as_delegate ");
    if (buf[0] == '\0') strcpy(buf, "none");
}

/* Query tickets for a single LUID */
static int query_session_tickets(HANDLE hLsa, ULONG authPackage, PLUID luid,
                                  const char* service_filter, const char* client_filter,
                                  formatp* output, int* ticket_count) {
    NTSTATUS status, subStatus;
    KERB_QUERY_TKT_CACHE_REQUEST request;
    PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
    ULONG responseSize = 0;
    int session_tickets = 0;

    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    request.LogonId = *luid;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, &request, sizeof(request),
        (PVOID*)&response, &responseSize, &subStatus);

    if (status != 0 || !response) {
        return 0;
    }

    for (ULONG i = 0; i < response->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO* ticket = &response->Tickets[i];
        char* serverName = unicode_to_char(&ticket->ServerName);
        char* realmName = unicode_to_char(&ticket->RealmName);
        char startTime[32], endTime[32], renewTime[32];
        char flags[256];

        if (!serverName) continue;

        /* Apply filters */
        if (service_filter && !strstr(serverName, service_filter)) {
            if (serverName) free(serverName);
            if (realmName) free(realmName);
            continue;
        }

        format_filetime(&ticket->StartTime, startTime, sizeof(startTime));
        format_filetime(&ticket->EndTime, endTime, sizeof(endTime));
        format_filetime(&ticket->RenewTime, renewTime, sizeof(renewTime));
        format_ticket_flags(ticket->TicketFlags, flags, sizeof(flags));

        BeaconFormatPrintf(output, "    [%d]\n", session_tickets);
        BeaconFormatPrintf(output, "      Server Name  : %s @ %s\n",
            serverName ? serverName : "?", realmName ? realmName : "?");
        BeaconFormatPrintf(output, "      Start Time   : %s\n", startTime);
        BeaconFormatPrintf(output, "      End Time     : %s\n", endTime);
        BeaconFormatPrintf(output, "      Renew Time   : %s\n", renewTime);
        BeaconFormatPrintf(output, "      Encryption   : %s (%d)\n",
            etype_string(ticket->EncryptionType), ticket->EncryptionType);
        BeaconFormatPrintf(output, "      Flags        : 0x%08X (%s)\n", ticket->TicketFlags, flags);
        BeaconFormatPrintf(output, "\n");

        session_tickets++;
        (*ticket_count)++;

        if (serverName) free(serverName);
        if (realmName) free(realmName);
    }

    if (response) {
        SECUR32$LsaFreeReturnBuffer(response);
    }

    return session_tickets;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* service_filter = NULL;
    char* client_filter = NULL;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    ULONG sessionCount = 0;
    PLUID sessions = NULL;
    int total_tickets = 0;
    int total_sessions = 0;
    LSA_STRING kerbName;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Show All Kerberos Tickets\n\n");


    service_filter = arg_get(&parser, "service");
    client_filter = arg_get(&parser, "client");

    if (service_filter) {
        BeaconFormatPrintf(&output, "[*] Service filter: %s\n", service_filter);
    }
    if (client_filter) {
        BeaconFormatPrintf(&output, "[*] Client filter: %s\n", client_filter);
    }


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

    /* Enumerate all logon sessions */
    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessions);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to enumerate logon sessions: 0x%08X\n", status);
        BeaconFormatPrintf(&output, "[!] Note: Elevation may be required to see other sessions\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Found %d logon sessions\n\n", sessionCount);

    /* Process each session */
    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        int session_ticket_count = 0;

        status = SECUR32$LsaGetLogonSessionData(&sessions[i], &sessionData);
        if (status != 0 || !sessionData) continue;

        /* Get session info */
        char* userName = unicode_to_char(&sessionData->UserName);
        char* domain = unicode_to_char(&sessionData->LogonDomain);
        char* authPkg = unicode_to_char(&sessionData->AuthenticationPackage);

        BeaconFormatPrintf(&output, "=== Session [%d] ===\n", i);
        BeaconFormatPrintf(&output, "  LUID           : 0x%X:0x%X\n",
            sessions[i].HighPart, sessions[i].LowPart);
        BeaconFormatPrintf(&output, "  User           : %s\\%s\n",
            domain ? domain : "?", userName ? userName : "?");
        BeaconFormatPrintf(&output, "  Auth Package   : %s\n", authPkg ? authPkg : "?");
        BeaconFormatPrintf(&output, "  Logon Type     : %d\n", sessionData->LogonType);
        BeaconFormatPrintf(&output, "  Session ID     : %d\n", sessionData->Session);
        BeaconFormatPrintf(&output, "\n");

        /* Query tickets for this session */
        session_ticket_count = query_session_tickets(hLsa, authPackage, &sessions[i],
            service_filter, client_filter, &output, &total_tickets);

        if (session_ticket_count == 0) {
            BeaconFormatPrintf(&output, "    (No cached tickets)\n\n");
        }

        total_sessions++;

        if (userName) free(userName);
        if (domain) free(domain);
        if (authPkg) free(authPkg);

        SECUR32$LsaFreeReturnBuffer(sessionData);
    }

    BeaconFormatPrintf(&output, "========================================\n");
    BeaconFormatPrintf(&output, "[*] Total: %d tickets across %d sessions\n", total_tickets, total_sessions);

cleanup:
    if (sessions) {
        SECUR32$LsaFreeReturnBuffer(sessions);
    }
    if (hLsa) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
    }
    if (service_filter) free(service_filter);
    if (client_filter) free(client_filter);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
