/*
 * krb_currentluid - Display current logon session LUID
 *
 * Usage: krb_currentluid
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* Token types - defined here if not in windows.h */
#ifndef TokenPrimary
#define TokenPrimary 1
#define TokenImpersonation 2
#endif

/* Token statistics structure */
typedef struct _TOKEN_STATISTICS_BOF {
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    DWORD TokenType;
    DWORD ImpersonationLevel;
    DWORD DynamicCharged;
    DWORD DynamicAvailable;
    DWORD GroupCount;
    DWORD PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS_BOF;

void go(char* args, int alen) {
    formatp output;
    HANDLE hToken = NULL;
    TOKEN_STATISTICS_BOF tokenStats;
    DWORD dwSize = 0;

    BeaconFormatAlloc(&output, 4096);

    BeaconFormatPrintf(&output, "[*] Action: Get Current LUID\n\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconFormatPrintf(&output, "[-] Failed to open process token: %d\n", KERNEL32$GetLastError());
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        BeaconFormatFree(&output);
        return;
    }

    /* Get token statistics which contains the LUID - TokenStatistics = 10 */
    if (!ADVAPI32$GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)10, &tokenStats, sizeof(tokenStats), &dwSize)) {
        BeaconFormatPrintf(&output, "[-] Failed to get token information: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        BeaconFormatFree(&output);
        return;
    }

    KERNEL32$CloseHandle(hToken);

    BeaconFormatPrintf(&output, "[+] Current LogonId (LUID):\n");
    BeaconFormatPrintf(&output, "    High Part : 0x%08X\n", tokenStats.AuthenticationId.HighPart);
    BeaconFormatPrintf(&output, "    Low Part  : 0x%08X\n", tokenStats.AuthenticationId.LowPart);
    BeaconFormatPrintf(&output, "    Decimal   : %u\n", tokenStats.AuthenticationId.LowPart);
    BeaconFormatPrintf(&output, "    Hex       : 0x%X\n\n", tokenStats.AuthenticationId.LowPart);

    BeaconFormatPrintf(&output, "[*] Token Information:\n");
    BeaconFormatPrintf(&output, "    Token ID     : 0x%X:0x%X\n",
        tokenStats.TokenId.HighPart, tokenStats.TokenId.LowPart);
    BeaconFormatPrintf(&output, "    Token Type   : %s\n",
        tokenStats.TokenType == TokenPrimary ? "Primary" : "Impersonation");
    BeaconFormatPrintf(&output, "    Groups       : %d\n", tokenStats.GroupCount);
    BeaconFormatPrintf(&output, "    Privileges   : %d\n", tokenStats.PrivilegeCount);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
