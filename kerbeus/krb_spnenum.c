/*
 * krb_spnenum - SPN Enumeration via LDAP
 *
 * Enumerates Service Principal Names (SPNs) in Active Directory
 * for Kerberoasting target discovery.
 *
 * Usage: krb_spnenum [/domain:DOMAIN] [/dc:DC] [/filter:PATTERN]
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

/* Missing MSVCRT imports */
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char*, const char*);
DECLSPEC_IMPORT long __cdecl MSVCRT$atol(const char*);
#define strncmp MSVCRT$strncmp
#define strtok MSVCRT$strtok
#define atol MSVCRT$atol

/* LDAP constants */
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_PORT 389
#define LDAP_SUCCESS 0

/* SPN categories */
typedef struct _SPN_CATEGORY {
    const char* prefix;
    const char* name;
    int count;
} SPN_CATEGORY;

static SPN_CATEGORY g_categories[] = {
    {"MSSQLSvc", "SQL Server", 0},
    {"HTTP", "Web Services", 0},
    {"TERMSRV", "Terminal Services", 0},
    {"exchangeMDB", "Exchange", 0},
    {"exchangeRFR", "Exchange", 0},
    {"IMAP", "IMAP", 0},
    {"SMTP", "SMTP", 0},
    {"POP", "POP3", 0},
    {"FTP", "FTP", 0},
    {"WSMAN", "WinRM/PS Remoting", 0},
    {"ldap", "LDAP", 0},
    {"DNS", "DNS", 0},
    {"cifs", "CIFS/SMB", 0},
    {"HOST", "Host", 0},
    {"kafka", "Kafka", 0},
    {"mongodb", "MongoDB", 0},
    {"mysql", "MySQL", 0},
    {"oracle", "Oracle", 0},
    {"postgres", "PostgreSQL", 0},
    {NULL, NULL, 0}
};

/* Categorize SPN */
static const char* categorize_spn(const char* spn) {
    for (int i = 0; g_categories[i].prefix != NULL; i++) {
        size_t plen = strlen(g_categories[i].prefix);
        if (strncmp(spn, g_categories[i].prefix, plen) == 0 &&
            (spn[plen] == '/' || spn[plen] == ':')) {
            g_categories[i].count++;
            return g_categories[i].name;
        }
    }
    return "Other";
}

/* Reset category counts */
static void reset_categories(void) {
    for (int i = 0; g_categories[i].prefix != NULL; i++) {
        g_categories[i].count = 0;
    }
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    char* filter = NULL;
    char* useronly = NULL;
    int total_accounts = 0;
    int total_spns = 0;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: SPN Enumeration\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    filter = arg_get(&parser, "filter");
    useronly = arg_get(&parser, "useronly");

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
    if (filter) {
        BeaconFormatPrintf(&output, "[*] SPN Filter: %s\n", filter);
    }

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

    /* Build LDAP filter */
    char ldapFilter[512];
    if (useronly) {
        /* Only user accounts with SPNs (not computers) */
        strcpy(ldapFilter, "(&(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))");
    } else {
        /* All SPNs */
        strcpy(ldapFilter, "(servicePrincipalName=*)");
    }

    char* attrs[] = { "sAMAccountName", "servicePrincipalName", "userAccountControl",
                      "pwdLastSet", "description", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(&output, "\n[*] Searching for SPNs...\n\n");

    ldapResult = WLDAP32$ldap_search_sA(ldap, searchBase, LDAP_SCOPE_SUBTREE,
                                         ldapFilter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP search failed: %d\n", ldapResult);
        WLDAP32$ldap_unbind(ldap);
        goto cleanup;
    }

    int entryCount = WLDAP32$ldap_count_entries(ldap, searchResult);
    BeaconFormatPrintf(&output, "[*] Found %d accounts with SPNs\n\n", entryCount);

    reset_categories();

    /* Process entries */
    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        PCHAR* spnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "servicePrincipalName");
        PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");
        PCHAR* descVals = WLDAP32$ldap_get_valuesA(ldap, entry, "description");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";
        DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;
        char* desc = descVals && descVals[0] ? descVals[0] : "";

        /* Count SPNs */
        int spnCount = 0;
        if (spnVals) {
            while (spnVals[spnCount]) spnCount++;
        }

        /* Apply filter if specified */
        int matchesFilter = 1;
        if (filter && spnVals) {
            matchesFilter = 0;
            for (int i = 0; spnVals[i]; i++) {
                if (strstr(spnVals[i], filter)) {
                    matchesFilter = 1;
                    break;
                }
            }
        }

        if (matchesFilter) {
            BeaconFormatPrintf(&output, "Account: %s\n", name);

            if (desc[0]) {
                BeaconFormatPrintf(&output, "  Description: %.60s%s\n",
                    desc, strlen(desc) > 60 ? "..." : "");
            }

            BeaconFormatPrintf(&output, "  UAC: 0x%08X", uac);
            if (uac & 0x00000002) BeaconFormatPrintf(&output, " [DISABLED]");
            if (uac & 0x00400000) BeaconFormatPrintf(&output, " [NO_PREAUTH]");
            if (uac & 0x00080000) BeaconFormatPrintf(&output, " [TRUSTED_DELEG]");
            if (uac & 0x01000000) BeaconFormatPrintf(&output, " [CONSTRAINED_DELEG]");
            BeaconFormatPrintf(&output, "\n");

            BeaconFormatPrintf(&output, "  SPNs (%d):\n", spnCount);
            if (spnVals) {
                for (int i = 0; spnVals[i] && i < 10; i++) {
                    const char* category = categorize_spn(spnVals[i]);
                    BeaconFormatPrintf(&output, "    - %s [%s]\n", spnVals[i], category);
                    total_spns++;
                }
                if (spnCount > 10) {
                    BeaconFormatPrintf(&output, "    ... and %d more\n", spnCount - 10);
                    total_spns += (spnCount - 10);
                }
            }

            BeaconFormatPrintf(&output, "\n");
            total_accounts++;
        }

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (spnVals) WLDAP32$ldap_value_freeA(spnVals);
        if (uacVals) WLDAP32$ldap_value_freeA(uacVals);
        if (descVals) WLDAP32$ldap_value_freeA(descVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    WLDAP32$ldap_unbind(ldap);

    /* Print summary */
    BeaconFormatPrintf(&output, "========================================\n");
    BeaconFormatPrintf(&output, "         SPN ENUMERATION SUMMARY\n");
    BeaconFormatPrintf(&output, "========================================\n\n");

    BeaconFormatPrintf(&output, "Total accounts: %d\n", total_accounts);
    BeaconFormatPrintf(&output, "Total SPNs: %d\n\n", total_spns);

    BeaconFormatPrintf(&output, "By Service Type:\n");
    for (int i = 0; g_categories[i].prefix != NULL; i++) {
        if (g_categories[i].count > 0) {
            BeaconFormatPrintf(&output, "  %-20s: %d\n",
                g_categories[i].name, g_categories[i].count);
        }
    }

    BeaconFormatPrintf(&output, "\n[*] Use krb_kerberoasting to request service tickets\n");

cleanup:
    if (domain) free(domain);
    if (dc && !dc_is_domain) free(dc);
    if (filter) free(filter);
    if (useronly) free(useronly);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
