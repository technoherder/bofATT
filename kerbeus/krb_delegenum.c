/*
 * krb_delegenum - Delegation Enumeration
 *
 * Enumerates accounts with Kerberos delegation privileges:
 * - Unconstrained delegation
 * - Constrained delegation
 * - Resource-based constrained delegation
 *
 * Usage: krb_delegenum [/domain:DOMAIN] [/dc:DC]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* LDAP declarations */
DECLSPEC_IMPORT PVOID WINAPI WLDAP32$ldap_initA(PCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sA(PVOID, PCHAR, PCHAR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(PVOID);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sA(PVOID, PCHAR, ULONG, PCHAR, PCHAR*, ULONG, PVOID*);
DECLSPEC_IMPORT PVOID WINAPI WLDAP32$ldap_first_entry(PVOID, PVOID);
DECLSPEC_IMPORT PVOID WINAPI WLDAP32$ldap_next_entry(PVOID, PVOID);
DECLSPEC_IMPORT PCHAR* WINAPI WLDAP32$ldap_get_valuesA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_value_freeA(PCHAR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(PVOID);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_count_entries(PVOID, PVOID);

/* berval structure */
typedef struct berval {
    ULONG bv_len;
    PCHAR bv_val;
} BERVAL;

DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);

/* LDAP constants */
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_PORT 389
#define LDAP_SUCCESS 0

/* UAC flags for delegation */
#define UAC_TRUSTED_FOR_DELEGATION      0x00080000
#define UAC_TRUSTED_TO_AUTH_FOR_DELEG   0x01000000
#define UAC_NOT_DELEGATED               0x00100000

/* Statistics */
static int g_unconstrained = 0;
static int g_constrained = 0;
static int g_rbcd = 0;

/* Search for unconstrained delegation */
static void enum_unconstrained(PVOID ldap, const char* searchBase, formatp* output) {
    char* filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
    char* attrs[] = { "sAMAccountName", "userAccountControl", "servicePrincipalName",
                      "operatingSystem", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(output, "\n=== UNCONSTRAINED DELEGATION ===\n");
    BeaconFormatPrintf(output, "(TRUSTED_FOR_DELEGATION flag set)\n\n");

    ULONG ldapResult = WLDAP32$ldap_search_sA(ldap, (PCHAR)searchBase, LDAP_SCOPE_SUBTREE,
                                               filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] Search failed: %d\n", ldapResult);
        return;
    }

    int count = WLDAP32$ldap_count_entries(ldap, searchResult);
    BeaconFormatPrintf(output, "[*] Found %d accounts with unconstrained delegation\n\n", count);

    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        PCHAR* osVals = WLDAP32$ldap_get_valuesA(ldap, entry, "operatingSystem");
        PCHAR* spnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "servicePrincipalName");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";
        char* os = osVals && osVals[0] ? osVals[0] : "";

        /* Skip domain controllers (they have unconstrained by default) */
        int isDC = 0;
        if (spnVals) {
            for (int i = 0; spnVals[i]; i++) {
                if (strstr(spnVals[i], "GC/") || strstr(spnVals[i], "ldap/")) {
                    isDC = 1;
                    break;
                }
            }
        }

        BeaconFormatPrintf(output, "  %s", name);
        if (os[0]) BeaconFormatPrintf(output, " (%s)", os);
        if (isDC) BeaconFormatPrintf(output, " [DC]");
        BeaconFormatPrintf(output, "\n");

        if (!isDC) g_unconstrained++;

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (osVals) WLDAP32$ldap_value_freeA(osVals);
        if (spnVals) WLDAP32$ldap_value_freeA(spnVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
}

/* Search for constrained delegation */
static void enum_constrained(PVOID ldap, const char* searchBase, formatp* output) {
    char* filter = "(msDS-AllowedToDelegateTo=*)";
    char* attrs[] = { "sAMAccountName", "msDS-AllowedToDelegateTo",
                      "userAccountControl", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(output, "\n=== CONSTRAINED DELEGATION ===\n");
    BeaconFormatPrintf(output, "(msDS-AllowedToDelegateTo attribute set)\n\n");

    ULONG ldapResult = WLDAP32$ldap_search_sA(ldap, (PCHAR)searchBase, LDAP_SCOPE_SUBTREE,
                                               filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] Search failed: %d\n", ldapResult);
        return;
    }

    int count = WLDAP32$ldap_count_entries(ldap, searchResult);
    BeaconFormatPrintf(output, "[*] Found %d accounts with constrained delegation\n\n", count);

    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        PCHAR* delegVals = WLDAP32$ldap_get_valuesA(ldap, entry, "msDS-AllowedToDelegateTo");
        PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";
        DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;

        BeaconFormatPrintf(output, "  Account: %s\n", name);

        /* Check for protocol transition */
        if (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEG) {
            BeaconFormatPrintf(output, "    [!] Protocol Transition ENABLED (T2A4D)\n");
        }

        BeaconFormatPrintf(output, "    Allowed to delegate to:\n");
        if (delegVals) {
            for (int i = 0; delegVals[i] && i < 10; i++) {
                BeaconFormatPrintf(output, "      - %s\n", delegVals[i]);
            }
            int delegCount = 0;
            while (delegVals[delegCount]) delegCount++;
            if (delegCount > 10) {
                BeaconFormatPrintf(output, "      ... and %d more\n", delegCount - 10);
            }
        }
        BeaconFormatPrintf(output, "\n");

        g_constrained++;

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (delegVals) WLDAP32$ldap_value_freeA(delegVals);
        if (uacVals) WLDAP32$ldap_value_freeA(uacVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
}

/* Search for resource-based constrained delegation */
static void enum_rbcd(PVOID ldap, const char* searchBase, formatp* output) {
    char* filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
    char* attrs[] = { "sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(output, "\n=== RESOURCE-BASED CONSTRAINED DELEGATION ===\n");
    BeaconFormatPrintf(output, "(msDS-AllowedToActOnBehalfOfOtherIdentity attribute set)\n\n");

    ULONG ldapResult = WLDAP32$ldap_search_sA(ldap, (PCHAR)searchBase, LDAP_SCOPE_SUBTREE,
                                               filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] Search failed: %d\n", ldapResult);
        return;
    }

    int count = WLDAP32$ldap_count_entries(ldap, searchResult);
    BeaconFormatPrintf(output, "[*] Found %d accounts with RBCD configured\n\n", count);

    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        struct berval** rbcdVals = WLDAP32$ldap_get_values_lenA(ldap, entry,
            "msDS-AllowedToActOnBehalfOfOtherIdentity");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";

        BeaconFormatPrintf(output, "  Account: %s\n", name);
        BeaconFormatPrintf(output, "    [!] Has RBCD configured (check security descriptor)\n");

        if (rbcdVals && rbcdVals[0]) {
            BeaconFormatPrintf(output, "    Security Descriptor size: %d bytes\n",
                rbcdVals[0]->bv_len);
        }

        BeaconFormatPrintf(output, "\n");
        g_rbcd++;

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (rbcdVals) WLDAP32$ldap_value_free_len(rbcdVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Delegation Enumeration\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Error: Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
    }

    int dc_is_domain = 0;
    if (!dc) {
        dc = domain;
        dc_is_domain = 1;
    }

    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);

    /* Connect via LDAP */
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

    /* Build search base */
    char searchBase[512];
    char* domainCopy = (char*)malloc(strlen(domain) + 1);
    strcpy(domainCopy, domain);

    strcpy(searchBase, "DC=");
    char* part = strtok(domainCopy, ".");
    int first = 1;
    while (part) {
        if (!first) strcat(searchBase, ",DC=");
        strcat(searchBase, part);
        first = 0;
        part = strtok(NULL, ".");
    }
    free(domainCopy);

    /* Reset counters */
    g_unconstrained = 0;
    g_constrained = 0;
    g_rbcd = 0;

    /* Enumerate each type */
    enum_unconstrained(ldap, searchBase, &output);
    enum_constrained(ldap, searchBase, &output);
    enum_rbcd(ldap, searchBase, &output);

    WLDAP32$ldap_unbind(ldap);

    /* Summary */
    BeaconFormatPrintf(&output, "\n========================================\n");
    BeaconFormatPrintf(&output, "         DELEGATION SUMMARY\n");
    BeaconFormatPrintf(&output, "========================================\n\n");

    BeaconFormatPrintf(&output, "Unconstrained Delegation: %d (excluding DCs)\n", g_unconstrained);
    BeaconFormatPrintf(&output, "Constrained Delegation:   %d\n", g_constrained);
    BeaconFormatPrintf(&output, "Resource-Based (RBCD):    %d\n", g_rbcd);

    if (g_unconstrained > 0) {
        BeaconFormatPrintf(&output, "\n[!] Unconstrained delegation hosts can capture TGTs!\n");
        BeaconFormatPrintf(&output, "    Use krb_unconstrained to monitor for incoming tickets\n");
    }

    if (g_constrained > 0) {
        BeaconFormatPrintf(&output, "\n[!] Constrained delegation can be abused with S4U attacks\n");
        BeaconFormatPrintf(&output, "    Protocol transition (T2A4D) enables impersonation\n");
    }

    if (g_rbcd > 0) {
        BeaconFormatPrintf(&output, "\n[!] RBCD can be abused if you control an allowed account\n");
        BeaconFormatPrintf(&output, "    Use krb_rbcd for S4U2Self attacks\n");
    }

cleanup:
    if (domain) free(domain);
    if (dc && !dc_is_domain) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
