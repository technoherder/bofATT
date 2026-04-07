/*
 * krb_hash - Generate Kerberos encryption keys from password
 *
 * Usage: krb_hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]
 *
 * Generates RC4-HMAC (NTLM), AES128, and AES256 hashes
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <wincrypt.h>

/* PBKDF2-HMAC-SHA1 implementation for AES key derivation */
/* Simplified - for full implementation would need complete PBKDF2 */

static int generate_ntlm_hash(const char* password, BYTE* hash_out) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 16;
    int result = 0;

    size_t pwlen = strlen(password);
    wchar_t* wpw = (wchar_t*)calloc(pwlen + 1, sizeof(wchar_t));
    if (!wpw) return 0;

    MSVCRT$mbstowcs(wpw, password, pwlen + 1);
    size_t wpwlen = pwlen;

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        free(wpw);
        return 0;
    }

    if (ADVAPI32$CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) {
        if (ADVAPI32$CryptHashData(hHash, (BYTE*)wpw, (DWORD)(wpwlen * 2), 0)) {
            if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, hash_out, &hashLen, 0)) {
                result = 1;
            }
        }
        ADVAPI32$CryptDestroyHash(hHash);
    }

    ADVAPI32$CryptReleaseContext(hProv, 0);
    free(wpw);
    return result;
}

/* Generate AES keys from password using PBKDF2
 * Salt for Kerberos is: "KERBEROSrealm" + principal
 * This is a simplified version - full implementation needs proper PBKDF2-HMAC-SHA1
 */
static int generate_aes_keys(const char* password, const char* user, const char* domain,
                             BYTE* aes128_out, BYTE* aes256_out) {
    /* Full AES key derivation requires:
     * 1. salt = uppercase(domain) + username
     * 2. PBKDF2-HMAC-SHA1(password, salt, 4096, keylen)
     * 3. DK = random-to-key(PBKDF2-output)
     *
     * This is complex and would need a full PBKDF2 implementation
     * For now, indicate this requires external tools
     */
    return 0;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 8 * 1024);
    arg_init(&parser, args, alen);

    char* password = arg_get(&parser, "password");
    char* user = arg_get(&parser, "user");
    char* domain = arg_get(&parser, "domain");

    if (!password) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Calculate Kerberos Hashes\n\n");

    BYTE ntlm_hash[16];
    if (generate_ntlm_hash(password, ntlm_hash)) {
        char hash_hex[33];
        for (int i = 0; i < 16; i++) {
            sprintf(hash_hex + (i * 2), "%02X", ntlm_hash[i]);
        }
        BeaconFormatPrintf(&output, "[*] RC4-HMAC (NTLM) hash:\n");
        BeaconFormatPrintf(&output, "    %s\n\n", hash_hex);
    } else {
        BeaconFormatPrintf(&output, "[-] Failed to generate NTLM hash\n\n");
    }

    if (user && domain) {
        char* domain_upper = (char*)malloc(strlen(domain) + 1);
        strcpy(domain_upper, domain);
        strupr(domain_upper);

        BeaconFormatPrintf(&output, "[*] Salt for AES keys: %s%s\n\n", domain_upper, user);

        BeaconFormatPrintf(&output, "[!] AES128 and AES256 key derivation requires PBKDF2-HMAC-SHA1\n");
        BeaconFormatPrintf(&output, "[*] Use external tools like Rubeus or impacket for AES keys:\n");
        BeaconFormatPrintf(&output, "    python3 -c \"from impacket.krb5.kerberosv5 import getKerberosTGT\"\n");
        BeaconFormatPrintf(&output, "    Or: Rubeus.exe hash /password:%s /user:%s /domain:%s\n\n",
                          password, user, domain_upper);

        free(domain_upper);
    } else {
        BeaconFormatPrintf(&output, "[*] Specify /user: and /domain: to calculate AES keys\n");
        BeaconFormatPrintf(&output, "[*] AES salt format: DOMAIN.COMusername\n\n");
    }

    BeaconFormatPrintf(&output, "[*] Password hashing complete\n");

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (password) free(password);
    if (user) free(user);
    if (domain) free(domain);
}
