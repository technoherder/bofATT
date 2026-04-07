/*
 * krb_klist - List Kerberos tickets in current or specified logon session
 *
 * Usage: krb_klist [/luid:LOGONID] [/user:USER] [/service:SERVICE] [/client:CLIENT]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <ntsecapi.h>

/* Kerberos message types for LSA */
#define KerbQueryTicketCacheMessage     1
#define KerbQueryTicketCacheExMessage   14
#define KerbQueryTicketCacheEx2Message  18
#define KerbRetrieveTicketMessage       2
#define KerbRetrieveEncodedTicketMessage 8

/* LSA string init helper */
static void init_lsa_string(PLSA_STRING lsaStr, const char* str) {
    lsaStr->Buffer = (PCHAR)str;
    lsaStr->Length = (USHORT)strlen(str);
    lsaStr->MaximumLength = lsaStr->Length + 1;
}

/* Convert FILETIME to readable string */
static void filetime_to_string(FILETIME ft, char* buf, size_t bufsize) {
    SYSTEMTIME st;
    if (KERNEL32$FileTimeToSystemTime(&ft, &st)) {
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
    } else {
        strcpy(buf, "Invalid");
    }
}

static int list_tickets(LUID* target_luid, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LSA_STRING kerbName;
    int ticket_count = 0;

    init_lsa_string(&kerbName, "Kerberos");

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

    KERB_QUERY_TKT_CACHE_REQUEST request;
    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    if (target_luid) {
        request.LogonId = *target_luid;
    }

    PVOID response = NULL;
    ULONG responseLen = 0;
    NTSTATUS subStatus;

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &request,
                                                   sizeof(request), &response, &responseLen, &subStatus);

    if (status != 0 || subStatus != 0) {
        BeaconFormatPrintf(output, "[-] Failed to query ticket cache: 0x%08X / 0x%08X\n", status, subStatus);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    if (response) {
        PKERB_QUERY_TKT_CACHE_RESPONSE cache = (PKERB_QUERY_TKT_CACHE_RESPONSE)response;

        BeaconFormatPrintf(output, "\n[*] Cached Tickets: %d\n\n", cache->CountOfTickets);
        ticket_count = cache->CountOfTickets;

        for (ULONG i = 0; i < cache->CountOfTickets; i++) {
            KERB_TICKET_CACHE_INFO* ticket = &cache->Tickets[i];

            BeaconFormatPrintf(output, "  [%d]\n", i);

            char server_name[512];
            MSVCRT$wcstombs(server_name, ticket->ServerName.Buffer,
                           min(sizeof(server_name)-1, ticket->ServerName.Length/2 + 1));
            server_name[ticket->ServerName.Length/2] = '\0';
            BeaconFormatPrintf(output, "      Server Name     : %s\n", server_name);

            char realm[256];
            MSVCRT$wcstombs(realm, ticket->RealmName.Buffer,
                           min(sizeof(realm)-1, ticket->RealmName.Length/2 + 1));
            realm[ticket->RealmName.Length/2] = '\0';
            BeaconFormatPrintf(output, "      Realm Name      : %s\n", realm);

            char time_buf[64];
            filetime_to_string(*(FILETIME*)&ticket->StartTime, time_buf, sizeof(time_buf));
            BeaconFormatPrintf(output, "      Start Time      : %s\n", time_buf);

            filetime_to_string(*(FILETIME*)&ticket->EndTime, time_buf, sizeof(time_buf));
            BeaconFormatPrintf(output, "      End Time        : %s\n", time_buf);

            filetime_to_string(*(FILETIME*)&ticket->RenewTime, time_buf, sizeof(time_buf));
            BeaconFormatPrintf(output, "      Renew Time      : %s\n", time_buf);

            BeaconFormatPrintf(output, "      Encryption Type : %s (%d)\n",
                              etype_string(ticket->EncryptionType), ticket->EncryptionType);

            BeaconFormatPrintf(output, "      Ticket Flags    : 0x%08X\n", ticket->TicketFlags);

            BeaconFormatPrintf(output, "\n");
        }

        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);
    return ticket_count;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 64 * 1024);
    arg_init(&parser, args, alen);

    char* luid_str = arg_get(&parser, "luid");
    char* user = arg_get(&parser, "user");
    char* service = arg_get(&parser, "service");
    char* client = arg_get(&parser, "client");

    BeaconFormatPrintf(&output, "[*] Action: List Kerberos Tickets (klist)\n");

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
        BeaconFormatPrintf(&output, "[*] Current logon session\n");
    }

    if (user) BeaconFormatPrintf(&output, "[*] Filter by user: %s\n", user);
    if (service) BeaconFormatPrintf(&output, "[*] Filter by service: %s\n", service);
    if (client) BeaconFormatPrintf(&output, "[*] Filter by client: %s\n", client);

    int count = list_tickets(target_luid, &output);
    BeaconFormatPrintf(&output, "[*] Total tickets listed: %d\n", count);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    if (luid_str) free(luid_str);
    if (user) free(user);
    if (service) free(service);
    if (client) free(client);
}
