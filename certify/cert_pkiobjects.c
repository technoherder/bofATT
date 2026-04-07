/*
 * cert_pkiobjects - Enumerate PKI Objects in Active Directory
 *
 * Enumerates all PKI-related objects in AD including:
 * - Certificate Authorities (Enrollment Services)
 * - Certificate Templates
 * - NTAuth Certificates
 * - AIA (Authority Information Access)
 * - CDP (CRL Distribution Points)
 *
 * Usage: cert_pkiobjects [/domain:DOMAIN] [/type:TYPE]
 *
 * Types: all, cas, templates, ntauth, aia, cdp
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

/* Enumerate Enrollment Services (CAs) */
static void enumerate_cas(formatp* output, LDAP* ld, WCHAR* configDN) {
    WCHAR searchBase[512];
    WCHAR* attrs[] = { L"cn", L"dNSHostName", L"certificateTemplates", L"cACertificate", NULL };
    LDAPMessage* results = NULL;
    ULONG rc;

    wsprintfW(searchBase, L"CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN);

    BeaconFormatPrintf(output, "[*] Enrollment Services (Certificate Authorities):\n");
    BeaconFormatPrintf(output, "    Base: CN=Enrollment Services,CN=Public Key Services,CN=Services\n\n");

    rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_ONELEVEL,
        L"(objectClass=pKIEnrollmentService)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "    [-] LDAP search failed: %d\n\n", rc);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    int count = 0;

    while (entry) {
        count++;
        WCHAR* cn = NULL;
        WCHAR* dns = NULL;
        WCHAR** templates = NULL;
        WCHAR** cnVals = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        WCHAR** dnsVals = WLDAP32$ldap_get_valuesW(ld, entry, L"dNSHostName");

        if (cnVals && cnVals[0]) cn = cnVals[0];
        if (dnsVals && dnsVals[0]) dns = dnsVals[0];

        BeaconFormatPrintf(output, "    CA %d:\n", count);
        if (cn) BeaconFormatPrintf(output, "      Name: %S\n", cn);
        if (dns) BeaconFormatPrintf(output, "      DNS Host: %S\n", dns);

        templates = WLDAP32$ldap_get_valuesW(ld, entry, L"certificateTemplates");
        if (templates) {
            int tplCount = 0;
            while (templates[tplCount]) tplCount++;
            BeaconFormatPrintf(output, "      Templates Published: %d\n", tplCount);
            WLDAP32$ldap_value_freeW(templates);
        }

        BeaconFormatPrintf(output, "\n");

        if (cnVals) WLDAP32$ldap_value_freeW(cnVals);
        if (dnsVals) WLDAP32$ldap_value_freeW(dnsVals);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    if (count == 0) {
        BeaconFormatPrintf(output, "    (No enrollment services found)\n\n");
    }

    WLDAP32$ldap_msgfree(results);
}

/* Enumerate Certificate Templates */
static void enumerate_templates(formatp* output, LDAP* ld, WCHAR* configDN) {
    WCHAR searchBase[512];
    WCHAR* attrs[] = { L"cn", L"displayName", L"msPKI-Cert-Template-OID",
                       L"pKIExpirationPeriod", L"msPKI-Template-Schema-Version", NULL };
    LDAPMessage* results = NULL;
    ULONG rc;

    wsprintfW(searchBase, L"CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN);

    BeaconFormatPrintf(output, "[*] Certificate Templates:\n");
    BeaconFormatPrintf(output, "    Base: CN=Certificate Templates,CN=Public Key Services,CN=Services\n\n");

    rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_ONELEVEL,
        L"(objectClass=pKICertificateTemplate)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "    [-] LDAP search failed: %d\n\n", rc);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    int count = 0;

    while (entry) {
        count++;
        WCHAR** cnVals = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        WCHAR** dispVals = WLDAP32$ldap_get_valuesW(ld, entry, L"displayName");
        WCHAR** oidVals = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Cert-Template-OID");
        WCHAR** verVals = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Template-Schema-Version");

        BeaconFormatPrintf(output, "    Template %d:\n", count);
        if (cnVals && cnVals[0]) BeaconFormatPrintf(output, "      CN: %S\n", cnVals[0]);
        if (dispVals && dispVals[0]) BeaconFormatPrintf(output, "      Display Name: %S\n", dispVals[0]);
        if (oidVals && oidVals[0]) BeaconFormatPrintf(output, "      OID: %S\n", oidVals[0]);
        if (verVals && verVals[0]) BeaconFormatPrintf(output, "      Schema Version: %S\n", verVals[0]);
        BeaconFormatPrintf(output, "\n");

        if (cnVals) WLDAP32$ldap_value_freeW(cnVals);
        if (dispVals) WLDAP32$ldap_value_freeW(dispVals);
        if (oidVals) WLDAP32$ldap_value_freeW(oidVals);
        if (verVals) WLDAP32$ldap_value_freeW(verVals);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    BeaconFormatPrintf(output, "    Total Templates: %d\n\n", count);
    WLDAP32$ldap_msgfree(results);
}

/* Enumerate NTAuth Certificates */
static void enumerate_ntauth(formatp* output, LDAP* ld, WCHAR* configDN) {
    WCHAR searchBase[512];
    WCHAR* attrs[] = { L"cn", L"cACertificate", NULL };
    LDAPMessage* results = NULL;
    ULONG rc;

    wsprintfW(searchBase, L"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s", configDN);

    BeaconFormatPrintf(output, "[*] NTAuth Certificates:\n");
    BeaconFormatPrintf(output, "    Base: CN=NTAuthCertificates,CN=Public Key Services,CN=Services\n");
    BeaconFormatPrintf(output, "    (CAs trusted for NT authentication)\n\n");

    rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_BASE,
        L"(objectClass=*)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "    [-] LDAP search failed: %d (object may not exist)\n\n", rc);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    if (entry) {
        struct berval** certVals = WLDAP32$ldap_get_values_lenW(ld, entry, L"cACertificate");
        if (certVals) {
            int certCount = 0;
            while (certVals[certCount]) certCount++;
            BeaconFormatPrintf(output, "    Certificates stored: %d\n", certCount);
            BeaconFormatPrintf(output, "    (These CA certificates are trusted for AD authentication)\n\n");
            WLDAP32$ldap_value_free_len(certVals);
        } else {
            BeaconFormatPrintf(output, "    No certificates found in NTAuth store\n\n");
        }
    }

    WLDAP32$ldap_msgfree(results);
}

/* Enumerate AIA (Authority Information Access) */
static void enumerate_aia(formatp* output, LDAP* ld, WCHAR* configDN) {
    WCHAR searchBase[512];
    WCHAR* attrs[] = { L"cn", L"cACertificate", L"authorityRevocationList", NULL };
    LDAPMessage* results = NULL;
    ULONG rc;

    wsprintfW(searchBase, L"CN=AIA,CN=Public Key Services,CN=Services,%s", configDN);

    BeaconFormatPrintf(output, "[*] AIA (Authority Information Access):\n");
    BeaconFormatPrintf(output, "    Base: CN=AIA,CN=Public Key Services,CN=Services\n\n");

    rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_ONELEVEL,
        L"(objectClass=certificationAuthority)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "    [-] LDAP search failed: %d\n\n", rc);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    int count = 0;

    while (entry) {
        count++;
        WCHAR** cnVals = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");

        BeaconFormatPrintf(output, "    AIA Entry %d:\n", count);
        if (cnVals && cnVals[0]) BeaconFormatPrintf(output, "      CA: %S\n", cnVals[0]);

        struct berval** certVals = WLDAP32$ldap_get_values_lenW(ld, entry, L"cACertificate");
        if (certVals) {
            int certCount = 0;
            while (certVals[certCount]) certCount++;
            BeaconFormatPrintf(output, "      Certificates: %d\n", certCount);
            WLDAP32$ldap_value_free_len(certVals);
        }

        BeaconFormatPrintf(output, "\n");

        if (cnVals) WLDAP32$ldap_value_freeW(cnVals);
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    if (count == 0) {
        BeaconFormatPrintf(output, "    (No AIA entries found)\n\n");
    }

    WLDAP32$ldap_msgfree(results);
}

/* Enumerate CDP (CRL Distribution Points) */
static void enumerate_cdp(formatp* output, LDAP* ld, WCHAR* configDN) {
    WCHAR searchBase[512];
    WCHAR* attrs[] = { L"cn", L"certificateRevocationList", L"deltaRevocationList", NULL };
    LDAPMessage* results = NULL;
    ULONG rc;

    wsprintfW(searchBase, L"CN=CDP,CN=Public Key Services,CN=Services,%s", configDN);

    BeaconFormatPrintf(output, "[*] CDP (CRL Distribution Points):\n");
    BeaconFormatPrintf(output, "    Base: CN=CDP,CN=Public Key Services,CN=Services\n\n");

    rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
        L"(objectClass=cRLDistributionPoint)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "    [-] LDAP search failed: %d\n\n", rc);
        return;
    }

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    int count = 0;

    while (entry) {
        count++;
        WCHAR** cnVals = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        WCHAR* dn = WLDAP32$ldap_get_dnW(ld, entry);

        BeaconFormatPrintf(output, "    CDP Entry %d:\n", count);
        if (cnVals && cnVals[0]) BeaconFormatPrintf(output, "      CN: %S\n", cnVals[0]);
        if (dn) {
            BeaconFormatPrintf(output, "      DN: %S\n", dn);
            WLDAP32$ldap_memfreeW(dn);
        }

        struct berval** crlVals = WLDAP32$ldap_get_values_lenW(ld, entry, L"certificateRevocationList");
        if (crlVals) {
            BeaconFormatPrintf(output, "      Has Base CRL: Yes (%d bytes)\n", crlVals[0]->bv_len);
            WLDAP32$ldap_value_free_len(crlVals);
        } else {
            BeaconFormatPrintf(output, "      Has Base CRL: No\n");
        }

        struct berval** deltaVals = WLDAP32$ldap_get_values_lenW(ld, entry, L"deltaRevocationList");
        if (deltaVals) {
            BeaconFormatPrintf(output, "      Has Delta CRL: Yes (%d bytes)\n", deltaVals[0]->bv_len);
            WLDAP32$ldap_value_free_len(deltaVals);
        } else {
            BeaconFormatPrintf(output, "      Has Delta CRL: No\n");
        }

        BeaconFormatPrintf(output, "\n");

        if (cnVals) WLDAP32$ldap_value_freeW(cnVals);
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    if (count == 0) {
        BeaconFormatPrintf(output, "    (No CDP entries found)\n\n");
    }

    WLDAP32$ldap_msgfree(results);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* type = NULL;
    LDAP* ld = NULL;
    WCHAR* configDN = NULL;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Enumerate PKI Objects\n\n");


    domain = arg_get(&parser, "domain");
    type = arg_get(&parser, "type");

    if (!type) {
        type = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 4);
        if (type) strcpy(type, "all");
    }

    BeaconFormatPrintf(&output, "[*] Object Type: %s\n", type);
    if (domain) BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "\n");


    WCHAR* domainW = domain ? str_to_wstr(domain) : NULL;
    ld = ldap_connect(domainW);
    if (domainW) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domainW);
    if (!ld) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LDAP\n");
        goto cleanup;
    }


    configDN = get_config_dn();
    if (!configDN) {
        BeaconFormatPrintf(&output, "[-] Failed to get configuration naming context\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Configuration NC: %S\n\n", configDN);


    if (strcmp(type, "all") == 0 || strcmp(type, "cas") == 0) {
        enumerate_cas(&output, ld, configDN);
    }

    if (strcmp(type, "all") == 0 || strcmp(type, "templates") == 0) {
        enumerate_templates(&output, ld, configDN);
    }

    if (strcmp(type, "all") == 0 || strcmp(type, "ntauth") == 0) {
        enumerate_ntauth(&output, ld, configDN);
    }

    if (strcmp(type, "all") == 0 || strcmp(type, "aia") == 0) {
        enumerate_aia(&output, ld, configDN);
    }

    if (strcmp(type, "all") == 0 || strcmp(type, "cdp") == 0) {
        enumerate_cdp(&output, ld, configDN);
    }

    BeaconFormatPrintf(&output, "[*] PKI Object enumeration complete\n");

cleanup:
    if (ld) WLDAP32$ldap_unbind(ld);
    if (configDN) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, configDN);
    if (domain) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain);
    if (type) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, type);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
