/*
 * krb_kdcproxy - KDC Proxy (MS-KKDCP) Support
 *
 * Sends Kerberos messages through an HTTPS KDC Proxy using the
 * MS-KKDCP (Kerberos Key Distribution Center Proxy Protocol).
 * Useful for environments where direct KDC access is blocked.
 *
 * Usage: krb_kdcproxy /proxyurl:URL /user:USER /password:PASS [/domain:DOMAIN]
 *        krb_kdcproxy /proxyurl:URL /user:USER /rc4:HASH [/domain:DOMAIN]
 *
 * Example: krb_kdcproxy /proxyurl:https://kdc.domain.com/KdcProxy /user:admin /password:pass
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* WinHTTP types */
typedef LPVOID HINTERNET;
typedef WORD INTERNET_PORT;

/* WinHTTP declarations */
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpQueryDataAvailable(HINTERNET, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSetOption(HINTERNET, DWORD, LPVOID, DWORD);

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_FLAG_SECURE 0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000

/* Helper: allocate and base64 encode using krb5_utils functions */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Parse hex string to bytes */
static BYTE* hex_to_bytes(const char* hex, size_t* out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;

    *out_len = len / 2;
    BYTE* bytes = (BYTE*)malloc(*out_len);
    if (!bytes) return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bytes[i] = (BYTE)strtoul(byte_str, NULL, 16);
    }

    return bytes;
}

/* HMAC-MD5 */
static void hmac_md5(const BYTE* key, size_t keyLen, const BYTE* data, size_t dataLen, BYTE* out) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE ipad[64], opad[64], keyBlock[64];
    DWORD hashLen = 16;

    memset(keyBlock, 0, 64);
    if (keyLen <= 64) memcpy(keyBlock, key, keyLen);

    for (int i = 0; i < 64; i++) {
        ipad[i] = keyBlock[i] ^ 0x36;
        opad[i] = keyBlock[i] ^ 0x5C;
    }

    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE innerHash[16];
        if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, ipad, 64, 0);
            ADVAPI32$CryptHashData(hHash, data, (DWORD)dataLen, 0);
            hashLen = 16;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, innerHash, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }
        if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, opad, 64, 0);
            ADVAPI32$CryptHashData(hHash, innerHash, 16, 0);
            hashLen = 16;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, out, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }
}

/* RC4 */
static void rc4_crypt(const BYTE* key, size_t keyLen, BYTE* data, size_t dataLen) {
    BYTE S[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    i = j = 0;
    for (size_t n = 0; n < dataLen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

/* Compute NTLM hash */
static void compute_ntlm_hash(const char* password, BYTE* hash) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD hashLen = 16;
    int pwLen = strlen(password);
    WCHAR* pwUnicode = (WCHAR*)malloc((pwLen + 1) * sizeof(WCHAR));
    for (int i = 0; i < pwLen; i++) pwUnicode[i] = (WCHAR)password[i];
    pwUnicode[pwLen] = 0;

    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (ADVAPI32$CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, (BYTE*)pwUnicode, pwLen * sizeof(WCHAR), 0);
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }
    free(pwUnicode);
}

/* Build RC4 encrypted timestamp */
static size_t build_rc4_timestamp(const BYTE* ntHash, BYTE* out, size_t maxLen) {
    SYSTEMTIME st;
    KERNEL32$GetSystemTime(&st);

    char timeStr[20];
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    KRB_BUFFER paTs, tmp;
    buf_init(&paTs, 64);
    buf_init(&tmp, 32);

    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&paTs, 0, &tmp);
    buf_reset(&tmp);

    asn1_encode_integer(&tmp, (st.wMilliseconds * 1000) % 1000000);
    asn1_context_wrap(&paTs, 1, &tmp);
    buf_reset(&tmp);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &paTs);

    BYTE usageBytes[4] = { 1, 0, 0, 0 };
    BYTE K1[16];
    hmac_md5(ntHash, 16, usageBytes, 4, K1);

    BYTE confounder[8];
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, 8, confounder);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }

    size_t plainLen = 8 + tmp.length;
    BYTE* plainData = (BYTE*)malloc(plainLen + 16);
    memcpy(plainData + 16, confounder, 8);
    memcpy(plainData + 16 + 8, tmp.data, tmp.length);

    BYTE K2[16];
    hmac_md5(K1, 16, plainData + 16, plainLen, K2);
    memcpy(plainData, K2, 16);

    BYTE K3[16];
    hmac_md5(K1, 16, K2, 16, K3);
    rc4_crypt(K3, 16, plainData + 16, plainLen);

    KRB_BUFFER encData, etypeInt, cipher;
    buf_init(&encData, 256);
    buf_init(&etypeInt, 16);
    buf_init(&cipher, 256);

    asn1_encode_integer(&etypeInt, ETYPE_RC4_HMAC);
    asn1_context_wrap(&encData, 0, &etypeInt);

    asn1_encode_octet_string(&cipher, plainData, 16 + plainLen);
    asn1_context_wrap(&encData, 2, &cipher);

    buf_reset(&tmp);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &encData);

    size_t result = 0;
    if (tmp.length <= maxLen) {
        memcpy(out, tmp.data, tmp.length);
        result = tmp.length;
    }

    free(plainData);
    buf_free(&paTs);
    buf_free(&tmp);
    buf_free(&encData);
    buf_free(&etypeInt);
    buf_free(&cipher);

    return result;
}

/* Build AS-REQ */
static void build_asreq(KRB_BUFFER* out, const char* user, const char* domain, const BYTE* ntHash) {
    KRB_BUFFER asreq, pvno, msg_type, padata, req_body, body, tmp, etype_seq, etype_list;
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

    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* PA-DATA */
    {
        KRB_BUFFER pa_list, pa_enc_ts, pa_type, pa_value;
        buf_init(&pa_list, 512);
        buf_init(&pa_enc_ts, 256);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 256);

        asn1_encode_integer(&pa_type, PADATA_ENC_TIMESTAMP);
        asn1_context_wrap(&pa_enc_ts, 1, &pa_type);

        BYTE encTs[256];
        size_t encTsLen = build_rc4_timestamp(ntHash, encTs, sizeof(encTs));
        if (encTsLen > 0) {
            asn1_encode_octet_string(&pa_value, encTs, encTsLen);
            asn1_context_wrap(&pa_enc_ts, 2, &pa_value);
        }

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_enc_ts);
        buf_append(&pa_list, tmp.data, tmp.length);
        buf_reset(&tmp);

        asn1_wrap(&padata, ASN1_SEQUENCE, &pa_list);
        asn1_context_wrap(&asreq, 3, &padata);

        buf_free(&pa_list);
        buf_free(&pa_enc_ts);
        buf_free(&pa_type);
        buf_free(&pa_value);
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

    /* cname */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, user);
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

    /* realm */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* sname (krbtgt) */
    {
        KRB_BUFFER name_type, name_string, name_seq, realm_str;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);
        buf_init(&realm_str, 128);

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, "krbtgt");
        asn1_encode_general_string(&realm_str, domain);
        buf_append(&tmp, realm_str.data, realm_str.length);
        asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
        asn1_context_wrap(&name_seq, 1, &name_string);

        buf_reset(&tmp);
        asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
        asn1_context_wrap(&body, 3, &tmp);

        buf_free(&name_type);
        buf_free(&name_string);
        buf_free(&name_seq);
        buf_free(&realm_str);
    }
    buf_reset(&tmp);

    /* till */
    asn1_encode_generalized_time(&tmp, "20370913024805Z");
    asn1_context_wrap(&body, 5, &tmp);
    buf_reset(&tmp);

    /* nonce */
    asn1_encode_integer(&tmp, KERNEL32$GetTickCount());
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype */
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
}

/* Build KDC Proxy Message (MS-KKDCP) */
static BYTE* build_kkdcp_message(BYTE* krbMsg, size_t krbMsgLen, const char* realm,
                                  size_t* outLen) {
    /*
     * KDC-PROXY-MESSAGE ::= SEQUENCE {
     *   kerb-message [0] OCTET STRING
     *   target-domain [1] Realm OPTIONAL
     *   dclocator-hint [2] INTEGER OPTIONAL
     * }
     */
    KRB_BUFFER msg, tmp, kerbMessage, targetDomain;
    buf_init(&msg, krbMsgLen + 256);
    buf_init(&tmp, krbMsgLen + 64);
    buf_init(&kerbMessage, krbMsgLen + 32);
    buf_init(&targetDomain, 128);

    /* kerb-message [0] - includes 4-byte length prefix */
    BYTE lenPrefix[4];
    lenPrefix[0] = (krbMsgLen >> 24) & 0xFF;
    lenPrefix[1] = (krbMsgLen >> 16) & 0xFF;
    lenPrefix[2] = (krbMsgLen >> 8) & 0xFF;
    lenPrefix[3] = krbMsgLen & 0xFF;

    buf_append(&tmp, lenPrefix, 4);
    buf_append(&tmp, krbMsg, krbMsgLen);

    asn1_encode_octet_string(&kerbMessage, tmp.data, tmp.length);
    asn1_context_wrap(&msg, 0, &kerbMessage);
    buf_reset(&tmp);

    /* target-domain [1] */
    if (realm && realm[0]) {
        asn1_encode_general_string(&targetDomain, realm);
        asn1_context_wrap(&msg, 1, &targetDomain);
    }


    asn1_wrap(&tmp, ASN1_SEQUENCE, &msg);

    BYTE* result = (BYTE*)malloc(tmp.length);
    if (result) {
        memcpy(result, tmp.data, tmp.length);
        *outLen = tmp.length;
    }

    buf_free(&msg);
    buf_free(&tmp);
    buf_free(&kerbMessage);
    buf_free(&targetDomain);

    return result;
}

/* Parse KDC Proxy Response */
static BYTE* parse_kkdcp_response(BYTE* response, size_t responseLen, size_t* krbMsgLen) {
    /* KDC-PROXY-MESSAGE with kerb-message [0] */
    if (response[0] != ASN1_SEQUENCE) return NULL;

    size_t offset = 1;
    asn1_decode_length(response, &offset);

    /* Find kerb-message [0] */
    if (response[offset] != 0xA0) return NULL;
    offset++;
    size_t len = asn1_decode_length(response, &offset);
    (void)len;


    if (response[offset] != ASN1_OCTETSTRING) return NULL;
    offset++;
    size_t octetLen = asn1_decode_length(response, &offset);

    /* Skip 4-byte length prefix */
    if (octetLen <= 4) return NULL;

    *krbMsgLen = octetLen - 4;
    BYTE* result = (BYTE*)malloc(*krbMsgLen);
    if (result) {
        memcpy(result, response + offset + 4, *krbMsgLen);
    }

    return result;
}

/* Convert string to wide string */
static WCHAR* str_to_wstr(const char* str) {
    int len = strlen(str) + 1;
    WCHAR* wstr = (WCHAR*)malloc(len * sizeof(WCHAR));
    for (int i = 0; i < len; i++) {
        wstr[i] = (WCHAR)str[i];
    }
    return wstr;
}

/* Parse URL into host, port, path */
static int parse_url(const char* url, char* host, int* port, char* path, int* useSSL) {
    *useSSL = 0;
    *port = 80;

    if (strncmp(url, "https://", 8) == 0) {
        *useSSL = 1;
        *port = 443;
        url += 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    }

    /* Find path */
    const char* pathStart = strchr(url, '/');
    if (pathStart) {
        strcpy(path, pathStart);
    } else {
        strcpy(path, "/");
        pathStart = url + strlen(url);
    }

    /* Extract host:port */
    size_t hostLen = pathStart - url;
    const char* colonPos = strchr(url, ':');
    if (colonPos && colonPos < pathStart) {
        hostLen = colonPos - url;
        *port = atoi(colonPos + 1);
    }

    strncpy(host, url, hostLen);
    host[hostLen] = '\0';

    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* proxyUrl = NULL;
    char* user = NULL;
    char* password = NULL;
    char* rc4Hash = NULL;
    char* domain = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: KDC Proxy (MS-KKDCP) Request\n\n");


    proxyUrl = arg_get(&parser, "proxyurl");
    user = arg_get(&parser, "user");
    password = arg_get(&parser, "password");
    rc4Hash = arg_get(&parser, "rc4");
    domain = arg_get(&parser, "domain");

    if (!proxyUrl || !user || (!password && !rc4Hash)) {
        BeaconFormatPrintf(&output, "[-] Error: /proxyurl:URL, /user:USER, and /password:PASS or /rc4:HASH required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_kdcproxy /proxyurl:URL /user:USER /password:PASS [/domain:DOMAIN]\n");
        BeaconFormatPrintf(&output, "       krb_kdcproxy /proxyurl:URL /user:USER /rc4:HASH [/domain:DOMAIN]\n\n");
        BeaconFormatPrintf(&output, "Sends Kerberos requests through an HTTPS KDC Proxy (MS-KKDCP).\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  krb_kdcproxy /proxyurl:https://kdc.domain.com/KdcProxy /user:admin /password:pass\n");
        BeaconFormatPrintf(&output, "  krb_kdcproxy /proxyurl:https://proxy.domain.com:443/KdcProxy /user:svc /rc4:HASH\n\n");
        BeaconFormatPrintf(&output, "Notes:\n");
        BeaconFormatPrintf(&output, "  - KDC Proxy allows Kerberos through HTTPS when direct access is blocked\n");
        BeaconFormatPrintf(&output, "  - Common proxy paths: /KdcProxy, /kerberos\n");
        BeaconFormatPrintf(&output, "  - Certificate validation errors are ignored\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Could not determine domain\n");
            goto cleanup;
        }
    }

    /* Get or compute NT hash */
    BYTE ntHash[16];
    if (rc4Hash) {
        size_t hashLen;
        BYTE* hash = hex_to_bytes(rc4Hash, &hashLen);
        if (!hash || hashLen != 16) {
            BeaconFormatPrintf(&output, "[-] Invalid RC4/NT hash\n");
            if (hash) free(hash);
            goto cleanup;
        }
        memcpy(ntHash, hash, 16);
        free(hash);
    } else {
        compute_ntlm_hash(password, ntHash);
    }

    /* Parse proxy URL */
    char host[256], path[256];
    int port, useSSL;
    if (!parse_url(proxyUrl, host, &port, path, &useSSL)) {
        BeaconFormatPrintf(&output, "[-] Failed to parse proxy URL\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Proxy Host: %s\n", host);
    BeaconFormatPrintf(&output, "[*] Proxy Port: %d\n", port);
    BeaconFormatPrintf(&output, "[*] Proxy Path: %s\n", path);
    BeaconFormatPrintf(&output, "[*] SSL: %s\n", useSSL ? "Yes" : "No");
    BeaconFormatPrintf(&output, "[*] User: %s\n", user);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);


    BeaconFormatPrintf(&output, "\n[*] Building AS-REQ...\n");

    KRB_BUFFER asreq;
    buf_init(&asreq, 4096);
    build_asreq(&asreq, user, domain, ntHash);

    BeaconFormatPrintf(&output, "[*] AS-REQ size: %d bytes\n", (int)asreq.length);


    size_t kkdcpLen;
    BYTE* kkdcpMsg = build_kkdcp_message(asreq.data, asreq.length, domain, &kkdcpLen);
    buf_free(&asreq);

    if (!kkdcpMsg) {
        BeaconFormatPrintf(&output, "[-] Failed to build KKDCP message\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] KKDCP message size: %d bytes\n", (int)kkdcpLen);

    /* Send via WinHTTP */
    BeaconFormatPrintf(&output, "[*] Sending request to KDC Proxy...\n");

    WCHAR* wHost = str_to_wstr(host);
    WCHAR* wPath = str_to_wstr(path);

    HINTERNET hSession = WINHTTP$WinHttpOpen(L"Kerbeus/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                              NULL, NULL, 0);
    if (!hSession) {
        BeaconFormatPrintf(&output, "[-] WinHttpOpen failed: %d\n", KERNEL32$GetLastError());
        free(wHost);
        free(wPath);
        free(kkdcpMsg);
        goto cleanup;
    }

    HINTERNET hConnect = WINHTTP$WinHttpConnect(hSession, wHost, (INTERNET_PORT)port, 0);
    if (!hConnect) {
        BeaconFormatPrintf(&output, "[-] WinHttpConnect failed: %d\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hSession);
        free(wHost);
        free(wPath);
        free(kkdcpMsg);
        goto cleanup;
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"POST", wPath, NULL, NULL, NULL, flags);
    if (!hRequest) {
        BeaconFormatPrintf(&output, "[-] WinHttpOpenRequest failed: %d\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        free(wHost);
        free(wPath);
        free(kkdcpMsg);
        goto cleanup;
    }

    /* Ignore certificate errors */
    if (useSSL) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WINHTTP$WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }


    WCHAR* contentType = L"Content-Type: application/kerberos";
    if (!WINHTTP$WinHttpSendRequest(hRequest, contentType, -1, kkdcpMsg, (DWORD)kkdcpLen,
                                     (DWORD)kkdcpLen, 0)) {
        BeaconFormatPrintf(&output, "[-] WinHttpSendRequest failed: %d\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        free(wHost);
        free(wPath);
        free(kkdcpMsg);
        goto cleanup;
    }

    free(kkdcpMsg);

    if (!WINHTTP$WinHttpReceiveResponse(hRequest, NULL)) {
        BeaconFormatPrintf(&output, "[-] WinHttpReceiveResponse failed: %d\n", KERNEL32$GetLastError());
        WINHTTP$WinHttpCloseHandle(hRequest);
        WINHTTP$WinHttpCloseHandle(hConnect);
        WINHTTP$WinHttpCloseHandle(hSession);
        free(wHost);
        free(wPath);
        goto cleanup;
    }

    /* Read response */
    BYTE respBuffer[16384];
    DWORD totalRead = 0;
    DWORD bytesAvailable, bytesRead;

    while (WINHTTP$WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        if (totalRead + bytesAvailable > sizeof(respBuffer)) break;
        if (WINHTTP$WinHttpReadData(hRequest, respBuffer + totalRead, bytesAvailable, &bytesRead)) {
            totalRead += bytesRead;
        } else break;
    }

    WINHTTP$WinHttpCloseHandle(hRequest);
    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hSession);
    free(wHost);
    free(wPath);

    if (totalRead == 0) {
        BeaconFormatPrintf(&output, "[-] No response received\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Received %d bytes\n", totalRead);

    /* Parse KKDCP response */
    size_t krbMsgLen;
    BYTE* krbMsg = parse_kkdcp_response(respBuffer, totalRead, &krbMsgLen);

    if (!krbMsg) {
        BeaconFormatPrintf(&output, "[-] Failed to parse KKDCP response\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Extracted Kerberos message: %d bytes\n", (int)krbMsgLen);

    if (krbMsg[0] == 0x6B) {
        BeaconFormatPrintf(&output, "[+] Received AS-REP!\n");
        BeaconFormatPrintf(&output, "[+] TGT obtained via KDC Proxy!\n");

        char* b64 = b64_encode_alloc(krbMsg, krbMsgLen);
        if (b64) {
            BeaconFormatPrintf(&output, "\n[*] TGT (AS-REP base64):\n");
            size_t b64len = strlen(b64);
            for (size_t i = 0; i < b64len; i += 76) {
                BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
            }
            free(b64);
        }
    } else if (krbMsg[0] == 0x7E) {
        BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");
    } else {
        BeaconFormatPrintf(&output, "[?] Unknown response type: 0x%02X\n", krbMsg[0]);
    }

    free(krbMsg);

cleanup:
    if (proxyUrl) free(proxyUrl);
    if (user) free(user);
    if (password) free(password);
    if (rc4Hash) free(rc4Hash);
    if (domain) free(domain);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
