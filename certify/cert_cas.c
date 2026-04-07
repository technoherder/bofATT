/*
 * cert_cas - Enumerate Certificate Authorities
 *
 * Enumerates all Certificate Authorities (CAs) in the Active Directory domain,
 * including their configuration, enabled templates, and potential vulnerabilities.
 *
 * Usage: cert_cas [/domain:DOMAIN] [/dc:DC] [/showallpermissions] [/vulnerable]
 */

#include "include/adcs_struct.h"
#include "include/adcs_utils.h"
#include "beacon.h"


typedef struct {
    char* buffer;
    int length;
    int position;
} ARG_PARSER;

static void arg_init(ARG_PARSER* parser, char* buffer, int length) {
    parser->buffer = buffer;
    parser->length = length;
    parser->position = 0;
}

static char* arg_get(ARG_PARSER* parser, const char* name) {
    char* buf = parser->buffer;
    int len = parser->length;
    char search[64];
    sprintf(search, "/%s:", name);
    int searchLen = strlen(search);

    for (int i = 0; i < len - searchLen; i++) {
        if (strncmp(buf + i, search, searchLen) == 0) {
            char* start = buf + i + searchLen;
            char* end = start;
            while (*end && *end != ' ' && *end != '\t' && *end != '\n') end++;
            int valueLen = end - start;
            char* value = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, valueLen + 1);
            if (value) {
                memcpy(value, start, valueLen);
                value[valueLen] = '\0';
            }
            return value;
        }
    }


    sprintf(search, "/%s", name);
    searchLen = strlen(search);
    for (int i = 0; i < len - searchLen; i++) {
        if (strncmp(buf + i, search, searchLen) == 0) {
            char next = buf[i + searchLen];
            if (next == '\0' || next == ' ' || next == '\t' || next == '\n') {
                char* value = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 2);
                if (value) value[0] = '1';
                return value;
            }
        }
    }

    return NULL;
}

/* Check for EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) */
static BOOL check_esc6(LDAP* ld, const WCHAR* caDN, formatp* output) {
    /* This would require querying the CA's registry or ICertAdmin interface */
    /* For now, we note it needs to be checked manually */
    return FALSE;
}

/* Parse certificate from binary blob */
static void parse_ca_cert(struct berval* certBlob, formatp* output) {
    if (!certBlob || certBlob->bv_len == 0) return;


    BYTE* cert = (BYTE*)certBlob->bv_val;
    DWORD certLen = certBlob->bv_len;


    if (cert[0] == 0x30) {
        BeaconFormatPrintf(output, "    [*] CA Certificate: %d bytes (DER encoded)\n", certLen);

        /* Calculate thumbprint (SHA-1 hash) */
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            if (ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
                ADVAPI32$CryptHashData(hHash, cert, certLen, 0);
                BYTE hash[20];
                DWORD hashLen = 20;
                if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    BeaconFormatPrintf(output, "    [*] Thumbprint: ");
                    for (int i = 0; i < 20; i++) {
                        BeaconFormatPrintf(output, "%02X", hash[i]);
                    }
                    BeaconFormatPrintf(output, "\n");
                }
                ADVAPI32$CryptDestroyHash(hHash);
            }
            ADVAPI32$CryptReleaseContext(hProv, 0);
        }
    }
}

/* Enumerate enrollment services */
static void enumerate_enrollment_services(LDAP* ld, const WCHAR* configDN, formatp* output, BOOL showAllPerms, BOOL vulnerableOnly) {
    WCHAR searchBase[512];
    swprintf(searchBase, 512, L"CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN);

    WCHAR* attrs[] = {
        L"cn",
        L"dNSHostName",
        L"cACertificate",
        L"certificateTemplates",
        L"displayName",
        L"nTSecurityDescriptor",
        NULL
    };

    LDAPMessage* results = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
        L"(objectClass=pKIEnrollmentService)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] LDAP search failed for Enrollment Services: %d\n", rc);
        return;
    }

    int caCount = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);

    while (entry) {
        caCount++;
        PWSTR dn = WLDAP32$ldap_get_dnW(ld, entry);
        char* dnStr = wstr_to_str(dn);

        BeaconFormatPrintf(output, "\n========================================\n");
        BeaconFormatPrintf(output, "[*] CA %d\n", caCount);
        BeaconFormatPrintf(output, "========================================\n");

        /* Get CN */
        PWSTR* cnValues = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        if (cnValues && cnValues[0]) {
            char* cn = wstr_to_str(cnValues[0]);
            BeaconFormatPrintf(output, "    CA Name           : %s\n", cn);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cn);
            WLDAP32$ldap_value_freeW(cnValues);
        }

        /* Get DNS hostname */
        PWSTR* dnsValues = WLDAP32$ldap_get_valuesW(ld, entry, L"dNSHostName");
        if (dnsValues && dnsValues[0]) {
            char* dns = wstr_to_str(dnsValues[0]);
            BeaconFormatPrintf(output, "    DNS Name          : %s\n", dns);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dns);
            WLDAP32$ldap_value_freeW(dnsValues);
        }

        BeaconFormatPrintf(output, "    Distinguished Name: %s\n", dnStr);

        /* Get CA certificate */
        struct berval** certValues = WLDAP32$ldap_get_values_lenW(ld, entry, L"cACertificate");
        if (certValues && certValues[0]) {
            parse_ca_cert(certValues[0], output);
            WLDAP32$ldap_value_free_len(certValues);
        }

        /* Get certificate templates */
        PWSTR* templateValues = WLDAP32$ldap_get_valuesW(ld, entry, L"certificateTemplates");
        if (templateValues) {
            int templateCount = 0;
            for (int i = 0; templateValues[i]; i++) templateCount++;

            BeaconFormatPrintf(output, "    Templates         : %d published\n", templateCount);

            if (templateCount <= 10 || showAllPerms) {
                for (int i = 0; templateValues[i]; i++) {
                    char* tmpl = wstr_to_str(templateValues[i]);
                    BeaconFormatPrintf(output, "        - %s\n", tmpl);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tmpl);
                }
            } else {
                for (int i = 0; i < 5; i++) {
                    char* tmpl = wstr_to_str(templateValues[i]);
                    BeaconFormatPrintf(output, "        - %s\n", tmpl);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tmpl);
                }
                BeaconFormatPrintf(output, "        ... and %d more (use /showallpermissions)\n",
                    templateCount - 5);
            }
            WLDAP32$ldap_value_freeW(templateValues);
        }

        /* Check for web enrollment (ESC8) */
        if (dnsValues && dnsValues[0]) {
            BeaconFormatPrintf(output, "\n    [*] Web Enrollment: Check https://<CA>/certsrv manually\n");
            BeaconFormatPrintf(output, "        If available, vulnerable to ESC8 (NTLM relay)\n");
        }

        /* Note about ESC6 */
        BeaconFormatPrintf(output, "\n    [*] EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6):\n");
        BeaconFormatPrintf(output, "        Check with: certutil -config \"<CA>\" -getreg policy\\EditFlags\n");
        BeaconFormatPrintf(output, "        If 0x00040000 flag is set, CA is vulnerable to ESC6\n");

        WLDAP32$ldap_memfreeW(dn);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dnStr);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(results);

    if (caCount == 0) {
        BeaconFormatPrintf(output, "[-] No Certificate Authorities found\n");
    } else {
        BeaconFormatPrintf(output, "\n[+] Found %d Certificate Authorit%s\n",
            caCount, caCount == 1 ? "y" : "ies");
    }
}

/* Enumerate AIA (Authority Information Access) */
static void enumerate_aia(LDAP* ld, const WCHAR* configDN, formatp* output) {
    WCHAR searchBase[512];
    swprintf(searchBase, 512, L"CN=AIA,CN=Public Key Services,CN=Services,%s", configDN);

    WCHAR* attrs[] = { L"cn", L"cACertificate", NULL };

    LDAPMessage* results = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
        L"(objectClass=certificationAuthority)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) return;

    BeaconFormatPrintf(output, "\n[*] Authority Information Access (AIA):\n");

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    while (entry) {
        PWSTR* cnValues = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        if (cnValues && cnValues[0]) {
            char* cn = wstr_to_str(cnValues[0]);
            BeaconFormatPrintf(output, "    - %s\n", cn);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cn);
            WLDAP32$ldap_value_freeW(cnValues);
        }
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(results);
}

/* Enumerate NTAuth certificates */
static void enumerate_ntauth(LDAP* ld, const WCHAR* configDN, formatp* output) {
    WCHAR searchBase[512];
    swprintf(searchBase, 512, L"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s", configDN);

    WCHAR* attrs[] = { L"cACertificate", NULL };

    LDAPMessage* results = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_BASE,
        L"(objectClass=*)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) return;

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    if (entry) {
        struct berval** certValues = WLDAP32$ldap_get_values_lenW(ld, entry, L"cACertificate");
        if (certValues) {
            int count = WLDAP32$ldap_count_values_len(certValues);
            BeaconFormatPrintf(output, "\n[*] NTAuthCertificates: %d certificate(s) for domain auth\n", count);
            WLDAP32$ldap_value_free_len(certValues);
        }
    }

    WLDAP32$ldap_msgfree(results);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    char* showAllPerms = NULL;
    char* vulnerableOnly = NULL;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Enumerate Certificate Authorities\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    showAllPerms = arg_get(&parser, "showallpermissions");
    vulnerableOnly = arg_get(&parser, "vulnerable");


    WCHAR* server = NULL;
    if (dc) {
        server = str_to_wstr(dc);
    } else {
        WCHAR dcBuf[256];
        if (KERNEL32$GetEnvironmentVariableW(L"LOGONSERVER", dcBuf, 256) > 0) {
            /* Remove leading \\ */
            server = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 256 * sizeof(WCHAR));
            if (dcBuf[0] == L'\\' && dcBuf[1] == L'\\') {
                wcscpy(server, dcBuf + 2);
            } else {
                wcscpy(server, dcBuf);
            }
        }
    }

    if (!server) {
        BeaconFormatPrintf(&output, "[-] Could not determine DC. Use /dc:DC\n");
        goto cleanup;
    }

    char* serverStr = wstr_to_str(server);
    BeaconFormatPrintf(&output, "[*] Connecting to: %s\n", serverStr);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, serverStr);


    LDAP* ld = ldap_connect(server);
    if (!ld) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LDAP\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] LDAP connection established\n");


    WCHAR* configDN = get_config_dn_for_domain(domain);
    if (!configDN) {
        BeaconFormatPrintf(&output, "[-] Could not determine Configuration DN\n");
        WLDAP32$ldap_unbind(ld);
        goto cleanup;
    }

    char* configStr = wstr_to_str(configDN);
    BeaconFormatPrintf(&output, "[*] Configuration DN: %s\n", configStr);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, configStr);


    enumerate_enrollment_services(ld, configDN, &output, showAllPerms != NULL, vulnerableOnly != NULL);


    enumerate_aia(ld, configDN, &output);


    enumerate_ntauth(ld, configDN, &output);


    WLDAP32$ldap_unbind(ld);

cleanup:
    if (domain) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain);
    if (dc) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dc);
    if (showAllPerms) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, showAllPerms);
    if (vulnerableOnly) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vulnerableOnly);
    if (server) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, server);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
