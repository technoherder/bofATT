/*
 * adcs_utils.h - Active Directory Certificate Services Utility Functions
 *
 * Common utilities for AD CS enumeration and abuse BOFs
 */

#ifndef ADCS_UTILS_H
#define ADCS_UTILS_H

#include "adcs_struct.h"

/* BOF Imports - LDAP */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR* WINAPI WLDAP32$ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_values_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT PWSTR WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_memfreeW(PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, void*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$LdapGetLastError(void);

/* BOF Imports - Crypto */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT DWORD WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*, DWORD*, BOOL*);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);

/* BOF Imports - Advapi32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSignHashA(HCRYPTHASH, DWORD, LPCSTR, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR, PSID*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL*, LPBOOL);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAclInformation(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

/* BOF Imports - Kernel32 */
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);

/* BOF Imports - MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memmove(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strrchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char*, const char*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_strnicmp(const char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$_strupr(char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char*);
DECLSPEC_IMPORT long __cdecl MSVCRT$atol(const char*);
DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char*, char**, int);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$strtoul(const char*, char**, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$_strdup(const char*);
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

/* MSVCRT macros */
#define malloc      MSVCRT$malloc
#define realloc     MSVCRT$realloc
#define calloc      MSVCRT$calloc
#define free        MSVCRT$free
#define memset      MSVCRT$memset
#define memcpy      MSVCRT$memcpy
#define memmove     MSVCRT$memmove
#define memcmp      MSVCRT$memcmp
#define strlen      MSVCRT$strlen
#define strcpy      MSVCRT$strcpy
#define strncpy     MSVCRT$strncpy
#define strcat      MSVCRT$strcat
#define strchr      MSVCRT$strchr
#define strrchr     MSVCRT$strrchr
#define strstr      MSVCRT$strstr
#define strcmp      MSVCRT$strcmp
#define strncmp     MSVCRT$strncmp
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
#define wcstombs    MSVCRT$wcstombs
#define mbstowcs    MSVCRT$mbstowcs
#define wcscpy      MSVCRT$wcscpy
#define wcsncpy     MSVCRT$wcsncpy
#define wcscat      MSVCRT$wcscat
#define wcslen      MSVCRT$wcslen
#define wcscmp      MSVCRT$wcscmp
#define wcsicmp     MSVCRT$_wcsicmp
#define swprintf    MSVCRT$_snwprintf
#define _snwprintf  MSVCRT$_snwprintf
#define wcsstr      MSVCRT$wcsstr
#define wcschr      MSVCRT$wcschr

/* BOF Imports - OLE32 (for ICertRequest) */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT void WINAPI OLE32$CoTaskMemFree(LPVOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromProgID(LPCOLESTR, LPCLSID);

/* LDAP Options */
#ifndef LDAP_OPT_PROTOCOL_VERSION
#define LDAP_OPT_PROTOCOL_VERSION 0x11
#endif
#ifndef LDAP_OPT_REFERRALS
#define LDAP_OPT_REFERRALS 0x08
#endif
#ifndef LDAP_VERSION3
#define LDAP_VERSION3 3
#endif
#ifndef LDAP_AUTH_NEGOTIATE
#define LDAP_AUTH_NEGOTIATE 0x0486
#endif
#ifndef LDAP_SCOPE_SUBTREE
#define LDAP_SCOPE_SUBTREE 0x02
#endif
#ifndef LDAP_SCOPE_ONELEVEL
#define LDAP_SCOPE_ONELEVEL 0x01
#endif
#ifndef LDAP_SCOPE_BASE
#define LDAP_SCOPE_BASE 0x00
#endif

/* Base64 encoding/decoding */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const BYTE* input, size_t len, char* output) {
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        DWORD val = input[i] << 16;
        if (i + 1 < len) val |= input[i + 1] << 8;
        if (i + 2 < len) val |= input[i + 2];

        output[j++] = b64_table[(val >> 18) & 0x3F];
        output[j++] = b64_table[(val >> 12) & 0x3F];
        output[j++] = (i + 1 < len) ? b64_table[(val >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < len) ? b64_table[val & 0x3F] : '=';
    }
    output[j] = '\0';
    return j;
}

static int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char* input, size_t len, BYTE* output) {
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4) {
        int v1 = b64_char_value(input[i]);
        int v2 = b64_char_value(input[i + 1]);
        int v3 = (input[i + 2] != '=') ? b64_char_value(input[i + 2]) : 0;
        int v4 = (input[i + 3] != '=') ? b64_char_value(input[i + 3]) : 0;

        if (v1 < 0 || v2 < 0) break;

        output[j++] = (v1 << 2) | (v2 >> 4);
        if (input[i + 2] != '=') output[j++] = ((v2 & 0x0F) << 4) | (v3 >> 2);
        if (input[i + 3] != '=') output[j++] = ((v3 & 0x03) << 6) | v4;
    }
    return j;
}

/* Wide string helper */
static WCHAR* str_to_wstr(const char* str) {
    int len = strlen(str) + 1;
    WCHAR* wstr = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len * sizeof(WCHAR));
    if (wstr) {
        KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
    }
    return wstr;
}

static char* wstr_to_str(const WCHAR* wstr) {
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* str = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (str) {
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
    }
    return str;
}

/* Connect to LDAP - named adcs_ldap_connect to avoid conflict with SDK */
static LDAP* adcs_ldap_connect(const WCHAR* server) {
    LDAP* ld = WLDAP32$ldap_initW((PWSTR)server, LDAP_PORT);
    if (!ld) return NULL;

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG referrals = 0;
    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &referrals);

    ULONG result = WLDAP32$ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        WLDAP32$ldap_unbind(ld);
        return NULL;
    }

    return ld;
}

/* Alias for backward compatibility */
#define ldap_connect adcs_ldap_connect

/* Get domain DN from environment */
static WCHAR* get_domain_dn(void) {
    WCHAR domain[256];
    if (KERNEL32$GetEnvironmentVariableW(L"USERDNSDOMAIN", domain, 256) == 0) {
        return NULL;
    }

    /* Convert domain.com to DC=domain,DC=com */
    static WCHAR dn[512];
    WCHAR* p = domain;
    WCHAR* out = dn;

    wcscpy(out, L"DC=");
    out += 3;

    while (*p) {
        if (*p == L'.') {
            wcscpy(out, L",DC=");
            out += 4;
        } else {
            *out++ = *p;
        }
        p++;
    }
    *out = L'\0';

    return dn;
}

/* Get configuration DN */
static WCHAR* get_config_dn(void) {
    WCHAR* domainDn = get_domain_dn();
    if (!domainDn) return NULL;

    static WCHAR configDn[512];
    swprintf(configDn, 512, L"CN=Configuration,%s", domainDn);
    return configDn;
}

/* Get configuration DN for a specific domain (e.g. "sevenkingdoms.local" -> "CN=Configuration,DC=sevenkingdoms,DC=local") */
static WCHAR* get_config_dn_for_domain(const char* domain) {
    if (!domain) return get_config_dn();

    static WCHAR configDn[512];
    WCHAR domainW[256];

    /* Convert domain to wide string */
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, domain, -1, domainW, 256);

    /* Build DN: domain.com -> DC=domain,DC=com */
    WCHAR dn[512];
    WCHAR* p = domainW;
    WCHAR* out = dn;

    wcscpy(out, L"DC=");
    out += 3;

    while (*p) {
        if (*p == L'.') {
            wcscpy(out, L",DC=");
            out += 4;
        } else {
            *out++ = *p;
        }
        p++;
    }
    *out = L'\0';

    swprintf(configDn, 512, L"CN=Configuration,%s", dn);
    return configDn;
}

/* Check if template has specific EKU */
static BOOL has_eku(WCHAR** ekus, DWORD count, const WCHAR* targetEku) {
    for (DWORD i = 0; i < count; i++) {
        if (wcscmp(ekus[i], targetEku) == 0) return TRUE;
    }
    return FALSE;
}

/* Check for client authentication EKU */
static BOOL has_client_auth_eku(WCHAR** ekus, DWORD count) {
    if (count == 0) return TRUE;  /* No EKU = any purpose */

    for (DWORD i = 0; i < count; i++) {
        if (wcscmp(ekus[i], L"1.3.6.1.5.5.7.3.2") == 0 ||      /* Client Auth */
            wcscmp(ekus[i], L"1.3.6.1.4.1.311.20.2.2") == 0 || /* Smart Card Logon */
            wcscmp(ekus[i], L"1.3.6.1.4.1.311.10.3.4") == 0 || /* Any Purpose */
            wcscmp(ekus[i], L"2.5.29.37.0") == 0) {            /* Any EKU */
            return TRUE;
        }
    }
    return FALSE;
}

/* Format vulnerability name */
static const char* get_vuln_name(VULN_TYPE vuln) {
    switch (vuln) {
        case VULN_ESC1: return "ESC1";
        case VULN_ESC2: return "ESC2";
        case VULN_ESC3: return "ESC3";
        case VULN_ESC4: return "ESC4";
        case VULN_ESC5: return "ESC5";
        case VULN_ESC6: return "ESC6";
        case VULN_ESC7: return "ESC7";
        case VULN_ESC8: return "ESC8";
        case VULN_ESC9: return "ESC9";
        case VULN_ESC10: return "ESC10";
        case VULN_ESC11: return "ESC11";
        case VULN_ESC13: return "ESC13";
        case VULN_ESC14: return "ESC14";
        case VULN_ESC15: return "ESC15";
        default: return "UNKNOWN";
    }
}

#endif /* ADCS_UTILS_H */
