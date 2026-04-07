/*
 * krb_logonsession - Enumerate logon sessions with detailed information
 *
 * Usage: krb_logonsession [/current] [/luid:LUID]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>


DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* Logon type to string */
static const char* logon_type_string(ULONG logonType) {
    switch (logonType) {
        case 0: return "Undefined (0)";
        case 2: return "Interactive";
        case 3: return "Network";
        case 4: return "Batch";
        case 5: return "Service";
        case 6: return "Proxy";
        case 7: return "Unlock";
        case 8: return "NetworkCleartext";
        case 9: return "NewCredentials";
        case 10: return "RemoteInteractive";
        case 11: return "CachedInteractive";
        case 12: return "CachedRemoteInteractive";
        case 13: return "CachedUnlock";
        default: return "Unknown";
    }
}

/* Format FILETIME as string */
static void format_filetime(LARGE_INTEGER* ft, char* buf, size_t bufsize) {
    FILETIME fileTime;
    SYSTEMTIME sysTime;

    fileTime.dwLowDateTime = ft->LowPart;
    fileTime.dwHighDateTime = ft->HighPart;

    if (ft->QuadPart == 0) {
        strcpy(buf, "Never");
        return;
    }

    if (ft->QuadPart == 0x7FFFFFFFFFFFFFFF) {
        strcpy(buf, "Infinite");
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

/* Print session info */
static void print_session(formatp* output, PSECURITY_LOGON_SESSION_DATA sessionData) {
    char timeBuf[64];
    char userDomain[512];
    char logonServer[256];
    char dnsDomain[256];
    char upn[512];

    /* Convert wide strings to ANSI */
    userDomain[0] = '\0';
    logonServer[0] = '\0';
    dnsDomain[0] = '\0';
    upn[0] = '\0';

    if (sessionData->UserName.Buffer && sessionData->UserName.Length > 0) {
        MSVCRT$wcstombs(userDomain, sessionData->UserName.Buffer,
            sessionData->UserName.Length / sizeof(WCHAR));
        userDomain[sessionData->UserName.Length / sizeof(WCHAR)] = '\0';
    }

    BeaconFormatPrintf(output, "  LUID           : 0x%X:0x%X (%u)\n",
        sessionData->LogonId.HighPart, sessionData->LogonId.LowPart,
        sessionData->LogonId.LowPart);

    if (sessionData->UserName.Buffer) {
        char username[256] = {0};
        MSVCRT$wcstombs(username, sessionData->UserName.Buffer,
            min(sizeof(username)-1, sessionData->UserName.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  UserName       : %s\n", username);
    }

    if (sessionData->LogonDomain.Buffer) {
        char domain[256] = {0};
        MSVCRT$wcstombs(domain, sessionData->LogonDomain.Buffer,
            min(sizeof(domain)-1, sessionData->LogonDomain.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  LogonDomain    : %s\n", domain);
    }

    if (sessionData->AuthenticationPackage.Buffer) {
        char authPkg[128] = {0};
        MSVCRT$wcstombs(authPkg, sessionData->AuthenticationPackage.Buffer,
            min(sizeof(authPkg)-1, sessionData->AuthenticationPackage.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  AuthPackage    : %s\n", authPkg);
    }

    BeaconFormatPrintf(output, "  LogonType      : %s (%d)\n",
        logon_type_string(sessionData->LogonType), sessionData->LogonType);

    BeaconFormatPrintf(output, "  Session        : %d\n", sessionData->Session);

    /* SID */
    if (sessionData->Sid) {
        BeaconFormatPrintf(output, "  SID            : (present)\n");
    }

    /* Logon time */
    format_filetime(&sessionData->LogonTime, timeBuf, sizeof(timeBuf));
    BeaconFormatPrintf(output, "  LogonTime      : %s\n", timeBuf);

    if (sessionData->LogonServer.Buffer) {
        char server[256] = {0};
        MSVCRT$wcstombs(server, sessionData->LogonServer.Buffer,
            min(sizeof(server)-1, sessionData->LogonServer.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  LogonServer    : %s\n", server);
    }

    if (sessionData->DnsDomainName.Buffer) {
        char dnsDom[256] = {0};
        MSVCRT$wcstombs(dnsDom, sessionData->DnsDomainName.Buffer,
            min(sizeof(dnsDom)-1, sessionData->DnsDomainName.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  DnsDomainName  : %s\n", dnsDom);
    }

    if (sessionData->Upn.Buffer) {
        char userUpn[512] = {0};
        MSVCRT$wcstombs(userUpn, sessionData->Upn.Buffer,
            min(sizeof(userUpn)-1, sessionData->Upn.Length / sizeof(WCHAR)));
        BeaconFormatPrintf(output, "  UPN            : %s\n", userUpn);
    }

    BeaconFormatPrintf(output, "\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    NTSTATUS status;
    ULONG sessionCount = 0;
    PLUID sessionList = NULL;
    HANDLE hToken = NULL;
    TOKEN_STATISTICS tokenStats;
    DWORD dwSize = 0;

    BeaconFormatAlloc(&output, 64 * 1024);
    arg_init(&parser, args, alen);

    BOOL current_only = arg_exists(&parser, "current");
    char* luid_str = arg_get(&parser, "luid");

    BeaconFormatPrintf(&output, "[*] Action: Enumerate Logon Sessions\n\n");

    /* If /current, get current LUID and show only that session */
    if (current_only) {
        if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            BeaconFormatPrintf(&output, "[-] Failed to open process token\n");
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwSize)) {
            BeaconFormatPrintf(&output, "[-] Failed to get token information\n");
            KERNEL32$CloseHandle(hToken);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }
        KERNEL32$CloseHandle(hToken);

        BeaconFormatPrintf(&output, "[+] Current Session:\n\n");

        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&tokenStats.AuthenticationId, &sessionData);
        if (status == 0 && sessionData) {
            print_session(&output, sessionData);
            SECUR32$LsaFreeReturnBuffer(sessionData);
        } else {
            BeaconFormatPrintf(&output, "[-] Failed to get session data: 0x%X\n", status);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    /* If /luid specified, show only that session */
    if (luid_str) {
        LUID targetLuid = {0};
        targetLuid.LowPart = strtol(luid_str, NULL, 0);

        BeaconFormatPrintf(&output, "[+] Session for LUID 0x%X:\n\n", targetLuid.LowPart);

        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&targetLuid, &sessionData);
        if (status == 0 && sessionData) {
            print_session(&output, sessionData);
            SECUR32$LsaFreeReturnBuffer(sessionData);
        } else {
            BeaconFormatPrintf(&output, "[-] Failed to get session data: 0x%X\n", status);
        }

        free(luid_str);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    /* Enumerate all sessions (requires elevation for other sessions) */
    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to enumerate logon sessions: 0x%X\n", status);
        BeaconFormatPrintf(&output, "[*] Note: Enumerating all sessions may require elevation\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Found %d logon sessions:\n\n", sessionCount);

    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&sessionList[i], &sessionData);

        if (status == 0 && sessionData) {
            BeaconFormatPrintf(&output, "[Session %d]\n", i);
            print_session(&output, sessionData);
            SECUR32$LsaFreeReturnBuffer(sessionData);
        }
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
}
