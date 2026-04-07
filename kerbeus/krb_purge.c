/*
 * krb_purge - Purge all Kerberos tickets from a logon session
 *
 * Usage: krb_purge [/luid:LOGONID]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <ntsecapi.h>

#define KerbPurgeTicketCacheMessage 7


DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* Purge ticket cache */
static int purge_tickets(LUID* target_luid, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status, subStatus;
    LSA_STRING kerbName;

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

    /* Build purge request */
    KERB_PURGE_TKT_CACHE_REQUEST request;
    memset(&request, 0, sizeof(request));
    request.MessageType = KerbPurgeTicketCacheMessage;
    if (target_luid) {
        request.LogonId = *target_luid;
    }
    /* ServerName and RealmName empty = purge all */
    request.ServerName.Buffer = NULL;
    request.ServerName.Length = 0;
    request.ServerName.MaximumLength = 0;
    request.RealmName.Buffer = NULL;
    request.RealmName.Length = 0;
    request.RealmName.MaximumLength = 0;

    PVOID response = NULL;
    ULONG responseLen = 0;

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &request,
                                                   sizeof(request), &response, &responseLen, &subStatus);

    if (response) {
        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);

    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaCallAuthenticationPackage failed: 0x%08X\n", status);
        return 0;
    }

    if (subStatus != 0) {
        BeaconFormatPrintf(output, "[-] Ticket purge failed: 0x%08X\n", subStatus);
        return 0;
    }

    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 4 * 1024);
    arg_init(&parser, args, alen);

    char* luid_str = arg_get(&parser, "luid");

    BeaconFormatPrintf(&output, "[*] Action: Purge Kerberos Tickets\n");

    LUID* target_luid = NULL;
    LUID luid_val;
    HANDLE hToken = NULL;
    TOKEN_STATISTICS tokenStats;
    DWORD dwSize = 0;

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
        /* Get current session LUID from process token */
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            if (ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwSize)) {
                luid_val = tokenStats.AuthenticationId;
                target_luid = &luid_val;
                BeaconFormatPrintf(&output, "[*] Current session LUID: 0x%X:0x%X\n", luid_val.HighPart, luid_val.LowPart);
            }
            KERNEL32$CloseHandle(hToken);
        }
        if (!target_luid) {
            BeaconFormatPrintf(&output, "[-] Failed to get current session LUID\n");
            goto cleanup;
        }
        BeaconFormatPrintf(&output, "[*] Purging current logon session tickets\n");
    }

    if (purge_tickets(target_luid, &output)) {
        BeaconFormatPrintf(&output, "[+] All Kerberos tickets have been purged!\n");
    }

cleanup:
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    if (luid_str) free(luid_str);
}
