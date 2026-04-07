/*
 * Kerberos Utility Functions
 * ASN.1 encoding/decoding, crypto wrappers, and common helpers
 */

#ifndef _KRB5_UTILS_H_
#define _KRB5_UTILS_H_

/* krb5_struct.h includes winsock2.h and windows.h in correct order */
#include "krb5_struct.h"

/* Windows API Declarations */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT u_long WSAAPI WS2_32$htonl(u_long);
DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT int WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SystemTimeToFileTime(const SYSTEMTIME*, LPFILETIME);

DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strrchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_strnicmp(const char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$_strupr(char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char*);
DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char*, char**, int);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$strtoul(const char*, char**, int);
DECLSPEC_IMPORT long __cdecl MSVCRT$atol(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$_strdup(const char*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memmove(void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcstombs(char*, const wchar_t*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$mbstowcs(wchar_t*, const char*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsncpy(wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcschr(const wchar_t*, wchar_t);

/* Crypto API */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDeriveKey(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptEncrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);

/* SSPI declarations */
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(LPSTR, LPSTR, unsigned long, void*, void*, SEC_GET_KEY_FN, void*, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, LPSTR, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$QueryContextAttributesA(PCtxtHandle, unsigned long, void*);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaEnumerateLogonSessions(PULONG, PLUID*);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA*);

/* Macros */
#define malloc      MSVCRT$malloc
#define realloc     MSVCRT$realloc
#define calloc      MSVCRT$calloc
#define free        MSVCRT$free
#define memset      MSVCRT$memset
#define memcpy      MSVCRT$memcpy
#define memcmp      MSVCRT$memcmp
#define strlen      MSVCRT$strlen
#define strcpy      MSVCRT$strcpy
#define strncpy     MSVCRT$strncpy
#define strcat      MSVCRT$strcat
#define strchr      MSVCRT$strchr
#define strrchr     MSVCRT$strrchr
#define strstr      MSVCRT$strstr
#define strcmp      MSVCRT$strcmp
#define stricmp     MSVCRT$_stricmp
#define strnicmp    MSVCRT$_strnicmp
#define strupr      MSVCRT$_strupr
#define sprintf     MSVCRT$sprintf
#define sscanf      MSVCRT$sscanf
#define atoi        MSVCRT$atoi
#define atol        MSVCRT$atol
#define strtol      MSVCRT$strtol
#define strtoul     MSVCRT$strtoul
#define strtok      MSVCRT$strtok
#define _strdup     MSVCRT$_strdup
#define strdup      MSVCRT$_strdup
#define memmove     MSVCRT$memmove
#define wcscpy      MSVCRT$wcscpy
#define wcsncpy     MSVCRT$wcsncpy
#define wcscat      MSVCRT$wcscat
#define wcslen      MSVCRT$wcslen
#define wcscmp      MSVCRT$wcscmp
#define wcsicmp     MSVCRT$_wcsicmp
#define swprintf    MSVCRT$swprintf
#define _snwprintf  MSVCRT$_snwprintf
#define wcsstr      MSVCRT$wcsstr
#define wcschr      MSVCRT$wcschr

/* Base64 encoding table */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 decoding table */
static const unsigned char b64_decode_table[256] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
};

/* Buffer functions */
static void buf_init(KRB_BUFFER* b, size_t cap) {
    b->data = (BYTE*)malloc(cap);
    b->length = 0;
    b->capacity = cap;
    if (b->data) memset(b->data, 0, cap);
}

static void buf_free(KRB_BUFFER* b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->length = 0;
    b->capacity = 0;
}

static void buf_ensure(KRB_BUFFER* b, size_t additional) {
    if (b->length + additional > b->capacity) {
        size_t newcap = (b->length + additional) * 2;
        b->data = (BYTE*)realloc(b->data, newcap);
        b->capacity = newcap;
    }
}

static void buf_append(KRB_BUFFER* b, const void* data, size_t len) {
    buf_ensure(b, len);
    memcpy(b->data + b->length, data, len);
    b->length += len;
}

static void buf_append_byte(KRB_BUFFER* b, BYTE byte) {
    buf_append(b, &byte, 1);
}

static void buf_reset(KRB_BUFFER* b) {
    b->length = 0;
}

/* Base64 encoding */
static size_t base64_encode(const BYTE* input, size_t len, char* output) {
    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        unsigned int a = i < len ? input[i++] : 0;
        unsigned int b = i < len ? input[i++] : 0;
        unsigned int c = i < len ? input[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;
        output[j++] = b64_table[(triple >> 18) & 0x3F];
        output[j++] = b64_table[(triple >> 12) & 0x3F];
        output[j++] = b64_table[(triple >> 6) & 0x3F];
        output[j++] = b64_table[triple & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) { output[j-1] = '='; output[j-2] = '='; }
    else if (mod == 2) { output[j-1] = '='; }
    output[j] = '\0';
    return j;
}

/* Base64 decoding */
static size_t base64_decode(const char* input, size_t len, BYTE* output) {
    size_t i, j;
    if (len % 4 != 0) return 0;

    size_t out_len = len / 4 * 3;
    if (input[len-1] == '=') out_len--;
    if (input[len-2] == '=') out_len--;

    for (i = 0, j = 0; i < len; ) {
        unsigned int a = b64_decode_table[(unsigned char)input[i++]];
        unsigned int b = b64_decode_table[(unsigned char)input[i++]];
        unsigned int c = b64_decode_table[(unsigned char)input[i++]];
        unsigned int d = b64_decode_table[(unsigned char)input[i++]];

        if (a == 64 || b == 64) break;

        unsigned int triple = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < out_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) output[j++] = triple & 0xFF;
    }
    return j;
}

/* ASN.1 length encoding */
static void asn1_encode_length(KRB_BUFFER* b, size_t len) {
    if (len < 128) {
        buf_append_byte(b, (BYTE)len);
    } else if (len < 256) {
        buf_append_byte(b, 0x81);
        buf_append_byte(b, (BYTE)len);
    } else if (len < 65536) {
        buf_append_byte(b, 0x82);
        buf_append_byte(b, (BYTE)(len >> 8));
        buf_append_byte(b, (BYTE)(len & 0xFF));
    } else {
        buf_append_byte(b, 0x83);
        buf_append_byte(b, (BYTE)(len >> 16));
        buf_append_byte(b, (BYTE)((len >> 8) & 0xFF));
        buf_append_byte(b, (BYTE)(len & 0xFF));
    }
}

/* ASN.1 length decoding */
static size_t asn1_decode_length(const BYTE* data, size_t* offset) {
    BYTE b = data[*offset];
    (*offset)++;
    if (b < 128) return b;
    int num = b & 0x7F;
    size_t len = 0;
    for (int i = 0; i < num; i++) {
        len = (len << 8) | data[*offset];
        (*offset)++;
    }
    return len;
}

/* ASN.1 wrap with tag */
static void asn1_wrap(KRB_BUFFER* out, BYTE tag, const KRB_BUFFER* inner) {
    buf_append_byte(out, tag);
    asn1_encode_length(out, inner->length);
    buf_append(out, inner->data, inner->length);
}

/* ASN.1 context wrap */
static void asn1_context_wrap(KRB_BUFFER* out, int ctx, const KRB_BUFFER* inner) {
    asn1_wrap(out, (BYTE)(ASN1_CONTEXT(ctx)), inner);
}

/* ASN.1 integer */
static void asn1_encode_integer(KRB_BUFFER* b, int value) {
    KRB_BUFFER inner;
    buf_init(&inner, 8);

    if (value == 0) {
        buf_append_byte(&inner, 0);
    } else if (value > 0 && value < 128) {
        buf_append_byte(&inner, (BYTE)value);
    } else if (value > 0 && value < 256) {
        buf_append_byte(&inner, 0);
        buf_append_byte(&inner, (BYTE)value);
    } else {
        BYTE bytes[4];
        int n = 0;
        unsigned int uval = (unsigned int)value;
        while (uval > 0 || n == 0) {
            bytes[3-n] = uval & 0xFF;
            uval >>= 8;
            n++;
        }
        if (bytes[4-n] & 0x80) {
            buf_append_byte(&inner, 0);
        }
        for (int i = 4-n; i < 4; i++) {
            buf_append_byte(&inner, bytes[i]);
        }
    }

    asn1_wrap(b, ASN1_INTEGER, &inner);
    buf_free(&inner);
}

/* ASN.1 general string */
static void asn1_encode_general_string(KRB_BUFFER* b, const char* str) {
    KRB_BUFFER inner;
    buf_init(&inner, strlen(str) + 1);
    buf_append(&inner, str, strlen(str));
    asn1_wrap(b, ASN1_GENERALSTRING, &inner);
    buf_free(&inner);
}

/* ASN.1 octet string */
static void asn1_encode_octet_string(KRB_BUFFER* b, const BYTE* data, size_t len) {
    KRB_BUFFER inner;
    buf_init(&inner, len);
    buf_append(&inner, data, len);
    asn1_wrap(b, ASN1_OCTETSTRING, &inner);
    buf_free(&inner);
}

/* ASN.1 bit string */
static void asn1_encode_bit_string(KRB_BUFFER* b, const BYTE* data, size_t len, int unused) {
    buf_append_byte(b, ASN1_BITSTRING);
    asn1_encode_length(b, len + 1);
    buf_append_byte(b, (BYTE)unused);
    buf_append(b, data, len);
}

/* ASN.1 generalized time */
static void asn1_encode_generalized_time(KRB_BUFFER* b, const char* time_str) {
    buf_append_byte(b, ASN1_GENERALIZEDTIME);
    buf_append_byte(b, (BYTE)strlen(time_str));
    buf_append(b, time_str, strlen(time_str));
}

/* Hex dump for debugging */
static void hex_dump(const BYTE* data, size_t len, char* output, size_t output_size) {
    const char hex[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < len && j < output_size - 3; i++) {
        output[j++] = hex[(data[i] >> 4) & 0xF];
        output[j++] = hex[data[i] & 0xF];
    }
    output[j] = '\0';
}

/* Parse command line arguments in /key:value format */
typedef struct _ARG_PARSER {
    char* buffer;
    size_t buflen;
} ARG_PARSER;

static void arg_init(ARG_PARSER* p, char* args, int len) {
    p->buffer = args;
    p->buflen = len;
}

static char* arg_get(ARG_PARSER* p, const char* key) {
    char pattern[64];
    sprintf(pattern, "/%s:", key);
    char* found = strstr(p->buffer, pattern);
    if (!found) return NULL;

    char* value = found + strlen(pattern);
    char* end = strchr(value, ' ');
    if (!end) end = value + strlen(value);

    size_t vlen = end - value;
    char* result = (char*)malloc(vlen + 1);
    strncpy(result, value, vlen);
    result[vlen] = '\0';
    return result;
}

static BOOL arg_exists(ARG_PARSER* p, const char* key) {
    char pattern[64];
    sprintf(pattern, "/%s", key);
    return strstr(p->buffer, pattern) != NULL ? TRUE : FALSE;
}

/* Get current domain from environment */
static char* get_domain_from_env(void) {
    char* domain = (char*)malloc(256);
    if (KERNEL32$GetEnvironmentVariableA("USERDNSDOMAIN", domain, 256) == 0) {
        if (KERNEL32$GetEnvironmentVariableA("USERDOMAIN", domain, 256) == 0) {
            free(domain);
            return NULL;
        }
    }
    return domain;
}

/* Get username from environment */
static char* get_username_from_env(void) {
    char* username = (char*)malloc(256);
    if (KERNEL32$GetEnvironmentVariableA("USERNAME", username, 256) == 0) {
        free(username);
        return NULL;
    }
    return username;
}

/* Connect to KDC */
static SOCKET connect_to_kdc(const char* dc_ip, int port) {
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    /* Set receive timeout to 10 seconds */
    DWORD timeout = 10000;
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = WS2_32$htons((u_short)port);
    server.sin_addr.s_addr = WS2_32$inet_addr(dc_ip);

    if (WS2_32$connect(sock, (struct sockaddr*)&server, sizeof(server)) != 0) {
        WS2_32$closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

/* Send Kerberos message (with 4-byte length prefix for TCP) */
static int send_krb_msg(SOCKET sock, const BYTE* data, size_t len) {
    BYTE* packet = (BYTE*)malloc(len + 4);
    if (!packet) return -1;

    packet[0] = (BYTE)((len >> 24) & 0xFF);
    packet[1] = (BYTE)((len >> 16) & 0xFF);
    packet[2] = (BYTE)((len >> 8) & 0xFF);
    packet[3] = (BYTE)(len & 0xFF);
    memcpy(packet + 4, data, len);

    int sent = WS2_32$send(sock, (char*)packet, (int)(len + 4), 0);
    free(packet);
    return sent;
}

/* Receive Kerberos message with proper TCP framing */
static int recv_krb_msg(SOCKET sock, BYTE* buffer, size_t bufsize) {
    int total = 0;
    int remaining = (int)bufsize;

    /* First read the 4-byte length prefix */
    while (total < 4) {
        int n = WS2_32$recv(sock, (char*)(buffer + total), 4 - total, 0);
        if (n <= 0) return total;
        total += n;
    }

    /* Parse the expected message length */
    DWORD msg_len = ((DWORD)buffer[0] << 24) | ((DWORD)buffer[1] << 16) |
                    ((DWORD)buffer[2] << 8) | (DWORD)buffer[3];

    /* Sanity check */
    if (msg_len > bufsize - 4) msg_len = (DWORD)(bufsize - 4);

    /* Read the rest of the message */
    remaining = (int)msg_len;
    while (remaining > 0) {
        int n = WS2_32$recv(sock, (char*)(buffer + total), remaining, 0);
        if (n <= 0) break;
        total += n;
        remaining -= n;
    }

    return total;
}

#endif /* _KRB5_UTILS_H_ */
