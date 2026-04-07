/*
 * krb_triage - Display a summary table of all Kerberos tickets
 *
 * Usage: krb_triage [/luid:LOGONID] [/user:USER] [/service:SERVICE] [/client:CLIENT]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <ntsecapi.h>

#define KerbQueryTicketCacheMessage 1

static int triage_tickets(LUID* target_luid, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LSA_STRING kerbName;
    int ticket_count = 0;

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

    if (status != 0 || subStatus != 0 || !response) {
        BeaconFormatPrintf(output, "[-] Failed to query ticket cache: 0x%08X / 0x%08X\n", status, subStatus);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    PKERB_QUERY_TKT_CACHE_RESPONSE cache = (PKERB_QUERY_TKT_CACHE_RESPONSE)response;
    ticket_count = cache->CountOfTickets;

    BeaconFormatPrintf(output, "\n");
    BeaconFormatPrintf(output, " %-4s | %-50s | %-10s | %-20s | %-20s\n",
                       "#", "Server", "EncType", "Start Time", "End Time");
    BeaconFormatPrintf(output, " %-4s-+-%-50s-+-%-10s-+-%-20s-+-%-20s\n",
                       "----", "--------------------------------------------------", "----------",
                       "--------------------", "--------------------");

    for (ULONG i = 0; i < cache->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO* ticket = &cache->Tickets[i];

        char server_name[52];
        memset(server_name, 0, sizeof(server_name));
        size_t maxcopy = min(50, ticket->ServerName.Length / 2);
        MSVCRT$wcstombs(server_name, ticket->ServerName.Buffer, maxcopy);

        const char* etype_str = etype_string(ticket->EncryptionType);

        char start_time[24], end_time[24];
        SYSTEMTIME st;

        if (KERNEL32$FileTimeToSystemTime((FILETIME*)&ticket->StartTime, &st)) {
            sprintf(start_time, "%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        } else {
            strcpy(start_time, "N/A");
        }

        if (KERNEL32$FileTimeToSystemTime((FILETIME*)&ticket->EndTime, &st)) {
            sprintf(end_time, "%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        } else {
            strcpy(end_time, "N/A");
        }

        BeaconFormatPrintf(output, " %-4d | %-50s | %-10s | %-20s | %-20s\n",
                          i, server_name, etype_str, start_time, end_time);
    }

    BeaconFormatPrintf(output, "\n");

    SECUR32$LsaFreeReturnBuffer(response);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    return ticket_count;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* luid_str = arg_get(&parser, "luid");
    char* user = arg_get(&parser, "user");
    char* service = arg_get(&parser, "service");
    char* client = arg_get(&parser, "client");

    BeaconFormatPrintf(&output, "[*] Action: Triage Kerberos Tickets\n");

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
    }

    int count = triage_tickets(target_luid, &output);
    BeaconFormatPrintf(&output, "[*] Total tickets: %d\n", count);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    if (luid_str) free(luid_str);
    if (user) free(user);
    if (service) free(service);
    if (client) free(client);
}
