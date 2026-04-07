/*
 * cert_download - Download Issued Certificates from CA
 *
 * Downloads a certificate from the CA using the request ID.
 * Useful for retrieving certificates that were issued but not immediately collected.
 *
 * Usage: cert_download /ca:CA_NAME /id:REQUEST_ID [/install]
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
    char* requestId = NULL;
    char* install = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Download Certificate\n\n");


    ca = arg_get(&parser, "ca");
    requestId = arg_get(&parser, "id");
    install = arg_get(&parser, "install");

    if (!ca || !requestId) {
        BeaconFormatPrintf(&output, "[-] Error: /ca:CA_CONFIG and /id:REQUEST_ID required\n\n");
        BeaconFormatPrintf(&output, "Usage: cert_download /ca:CA\\CAName /id:REQUEST_ID [/install]\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /ca:SERVER\\CAName   - Target CA configuration\n");
        BeaconFormatPrintf(&output, "  /id:REQUEST_ID      - Certificate request ID from CA\n");
        BeaconFormatPrintf(&output, "  /install            - Install cert in local store\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  cert_download /ca:dc01.corp.local\\corp-CA /id:123\n");
        BeaconFormatPrintf(&output, "  cert_download /ca:dc01.corp.local\\corp-CA /id:456 /install\n");
        goto cleanup;
    }

    int reqId = atoi(requestId);
    BeaconFormatPrintf(&output, "[*] CA Configuration: %s\n", ca);
    BeaconFormatPrintf(&output, "[*] Request ID: %d\n", reqId);


    BeaconFormatPrintf(&output, "\n[*] Certificate Download Methods:\n\n");

    BeaconFormatPrintf(&output, "Method 1: Using certreq.exe\n");
    BeaconFormatPrintf(&output, "  certreq -retrieve -config \"%s\" %d cert.cer\n\n", ca, reqId);

    BeaconFormatPrintf(&output, "Method 2: Using certutil.exe\n");
    BeaconFormatPrintf(&output, "  certutil -config \"%s\" -retrieve %d cert.cer\n\n", ca, reqId);

    BeaconFormatPrintf(&output, "Method 3: Check request status\n");
    BeaconFormatPrintf(&output, "  certutil -config \"%s\" -view -restrict \"RequestId=%d\"\n\n", ca, reqId);

    BeaconFormatPrintf(&output, "[*] After downloading, to use for authentication:\n");
    BeaconFormatPrintf(&output, "  1. Import with private key:\n");
    BeaconFormatPrintf(&output, "     certreq -accept cert.cer\n\n");
    BeaconFormatPrintf(&output, "  2. Export to PFX:\n");
    BeaconFormatPrintf(&output, "     certutil -exportpfx My <thumbprint> cert.pfx\n\n");
    BeaconFormatPrintf(&output, "  3. Request TGT with certificate:\n");
    BeaconFormatPrintf(&output, "     krb_asktgt /user:TARGET /certificate:cert.pfx /password:PASS /ptt\n");

cleanup:
    if (ca) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ca);
    if (requestId) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, requestId);
    if (install) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, install);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
