/*
 * krb_u2u - User-to-User (U2U) Ticket Requests
 *
 * Performs User-to-User Kerberos authentication where the service ticket
 * is encrypted with the target user's TGT session key instead of the
 * service's long-term key. Useful for services running as user accounts.
 *
 * Usage: krb_u2u /tgt:BASE64_TGT /targetuser:USER [/domain:DOMAIN] [/dc:DC]
 *
 * U2U is indicated by:
 *   - KDC option ENC-TKT-IN-SKEY set
 *   - Target user's TGT included in additional-tickets
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* KDC option for U2U */
#define KDCOPTION_ENC_TKT_IN_SKEY 0x00000008

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

/* Extract ticket from TGT (AS-REP or KRB-CRED) */
static int extract_ticket_from_tgt(BYTE* tgt, size_t tgtLen,
                                    BYTE** ticketOut, size_t* ticketLenOut,
                                    char* realm, size_t realmMax,
                                    char* cname, size_t cnameMax) {
    size_t offset = 0;

    realm[0] = '\0';
    cname[0] = '\0';

    /* Check format */
    if (tgt[0] == 0x76) {
        /* KRB-CRED format - extract ticket from tickets sequence */
        offset = 1;
        size_t totalLen = asn1_decode_length(tgt, &offset);
        (void)totalLen;

        if (tgt[offset] != ASN1_SEQUENCE) return 0;
        offset++;
        asn1_decode_length(tgt, &offset);

        /* Find tickets [2] */
        while (offset < tgtLen - 4) {
            if (tgt[offset] == 0xA2) {
                offset++;
                size_t len = asn1_decode_length(tgt, &offset);
                (void)len;

                /* SEQUENCE OF Ticket */
                if (tgt[offset] == ASN1_SEQUENCE) {
                    offset++;
                    size_t seqLen = asn1_decode_length(tgt, &offset);
                    (void)seqLen;

                    /* First Ticket */
                    if (tgt[offset] == 0x61) {
                        size_t ticketStart = offset;
                        offset++;
                        size_t ticketLen = asn1_decode_length(tgt, &offset);
                        size_t fullTicketLen = (offset - ticketStart) + ticketLen;

                        *ticketOut = (BYTE*)malloc(fullTicketLen);
                        if (*ticketOut) {
                            memcpy(*ticketOut, tgt + ticketStart, fullTicketLen);
                            *ticketLenOut = fullTicketLen;

                            /* Extract realm from ticket */
                            for (size_t i = 0; i < fullTicketLen - 4; i++) {
                                if ((*ticketOut)[i] == 0xA1) {
                                    size_t off = i + 1;
                                    asn1_decode_length(*ticketOut, &off);
                                    if ((*ticketOut)[off] == ASN1_GENERALSTRING) {
                                        off++;
                                        size_t strLen = asn1_decode_length(*ticketOut, &off);
                                        if (strLen < realmMax) {
                                            memcpy(realm, *ticketOut + off, strLen);
                                            realm[strLen] = '\0';
                                        }
                                        break;
                                    }
                                }
                            }

                            return 1;
                        }
                    }
                }
                break;
            }
            offset++;
        }
    } else if (tgt[0] == 0x6B) {
        /* AS-REP format */
        offset = 1;
        asn1_decode_length(tgt, &offset);

        if (tgt[offset] != ASN1_SEQUENCE) return 0;
        offset++;
        asn1_decode_length(tgt, &offset);

        while (offset < tgtLen - 4) {
            BYTE tag = tgt[offset];

            if (tag == 0xA3) {
                /* crealm */
                offset++;
                size_t len = asn1_decode_length(tgt, &offset);
                if (tgt[offset] == ASN1_GENERALSTRING) {
                    offset++;
                    size_t strLen = asn1_decode_length(tgt, &offset);
                    if (strLen < realmMax) {
                        memcpy(realm, tgt + offset, strLen);
                        realm[strLen] = '\0';
                    }
                    offset += strLen;
                } else {
                    offset += len;
                }
            } else if (tag == 0xA4) {
                /* cname */
                offset++;
                size_t len = asn1_decode_length(tgt, &offset);
                size_t endOff = offset + len;

                /* Parse PrincipalName to get name */
                while (offset < endOff) {
                    if (tgt[offset] == 0xA1) {
                        offset++;
                        asn1_decode_length(tgt, &offset);
                        if (tgt[offset] == ASN1_SEQUENCE) {
                            offset++;
                            asn1_decode_length(tgt, &offset);
                            if (tgt[offset] == ASN1_GENERALSTRING) {
                                offset++;
                                size_t strLen = asn1_decode_length(tgt, &offset);
                                if (strLen < cnameMax) {
                                    memcpy(cname, tgt + offset, strLen);
                                    cname[strLen] = '\0';
                                }
                            }
                        }
                        break;
                    }
                    offset++;
                }
                offset = endOff;
            } else if (tag == 0xA5) {
                /* ticket */
                offset++;
                size_t len = asn1_decode_length(tgt, &offset);

                if (tgt[offset] == 0x61) {
                    *ticketOut = (BYTE*)malloc(len);
                    if (*ticketOut) {
                        memcpy(*ticketOut, tgt + offset, len);
                        *ticketLenOut = len;
                        return 1;
                    }
                }
                offset += len;
            } else if ((tag & 0xE0) == 0xA0) {
                offset++;
                size_t len = asn1_decode_length(tgt, &offset);
                offset += len;
            } else {
                offset++;
            }
        }
    } else if (tgt[0] == 0x61) {
        /* Raw Ticket */
        *ticketOut = (BYTE*)malloc(tgtLen);
        if (*ticketOut) {
            memcpy(*ticketOut, tgt, tgtLen);
            *ticketLenOut = tgtLen;

            /* Extract realm */
            for (size_t i = 0; i < tgtLen - 4; i++) {
                if (tgt[i] == 0xA1) {
                    size_t off = i + 1;
                    asn1_decode_length(tgt, &off);
                    if (tgt[off] == ASN1_GENERALSTRING) {
                        off++;
                        size_t strLen = asn1_decode_length(tgt, &off);
                        if (strLen < realmMax) {
                            memcpy(realm, tgt + off, strLen);
                            realm[strLen] = '\0';
                        }
                        break;
                    }
                }
            }
            return 1;
        }
    }

    return 0;
}

/* Build TGS-REQ for U2U */
static void build_u2u_tgsreq(KRB_BUFFER* out, const char* targetUser,
                              const char* realm, BYTE* clientTgt, size_t clientTgtLen,
                              BYTE* targetTgt, size_t targetTgtLen) {
    KRB_BUFFER tgsreq, pvno, msg_type, padata, req_body;
    KRB_BUFFER body, tmp, etype_seq, etype_list, addl_tickets;
    BYTE kdc_opts[4];
    DWORD kdc_options = KDCOPTION_FORWARDABLE | KDCOPTION_RENEWABLE |
                        KDCOPTION_CANONICALIZE | KDCOPTION_ENC_TKT_IN_SKEY;

    buf_init(&tgsreq, 8192);
    buf_init(&pvno, 16);
    buf_init(&msg_type, 16);
    buf_init(&padata, 2048);
    buf_init(&req_body, 4096);
    buf_init(&body, 4096);
    buf_init(&tmp, 2048);
    buf_init(&etype_seq, 64);
    buf_init(&etype_list, 64);
    buf_init(&addl_tickets, targetTgtLen + 64);

    /* pvno [1] */
    asn1_encode_integer(&pvno, KRB5_PVNO);
    asn1_context_wrap(&tgsreq, 1, &pvno);

    /* msg-type [2] = TGS-REQ (12) */
    asn1_encode_integer(&msg_type, KRB5_TGS_REQ);
    asn1_context_wrap(&tgsreq, 2, &msg_type);

    /* padata [3] - AP-REQ with client's TGT */
    {
        KRB_BUFFER pa_list, pa_tgsreq, pa_type, pa_value;
        buf_init(&pa_list, 2048);
        buf_init(&pa_tgsreq, 2048);
        buf_init(&pa_type, 16);
        buf_init(&pa_value, 2048);

        /* PA-TGS-REQ */
        asn1_encode_integer(&pa_type, PADATA_TGS_REQ);
        asn1_context_wrap(&pa_tgsreq, 1, &pa_type);

        /* Build simple AP-REQ (without authenticator encryption for now) */
        /* This is a simplified version - real implementation needs proper authenticator */
        KRB_BUFFER apreq, ap_pvno, ap_msgtype, ap_opts, ap_ticket, ap_auth;
        buf_init(&apreq, 2048);
        buf_init(&ap_pvno, 16);
        buf_init(&ap_msgtype, 16);
        buf_init(&ap_opts, 16);
        buf_init(&ap_ticket, clientTgtLen + 32);
        buf_init(&ap_auth, 256);

        asn1_encode_integer(&ap_pvno, KRB5_PVNO);
        asn1_context_wrap(&apreq, 0, &ap_pvno);

        asn1_encode_integer(&ap_msgtype, 14);  /* AP-REQ */
        asn1_context_wrap(&apreq, 1, &ap_msgtype);

        BYTE ap_options[4] = {0, 0, 0, 0};
        asn1_encode_bit_string(&ap_opts, ap_options, 4, 0);
        asn1_context_wrap(&apreq, 2, &ap_opts);

        /* Include client's ticket */
        buf_append(&ap_ticket, clientTgt, clientTgtLen);
        asn1_context_wrap(&apreq, 3, &ap_ticket);

        /* Authenticator - minimal placeholder */
        /* Real implementation needs encrypted authenticator */
        {
            KRB_BUFFER auth, auth_vno, auth_realm, auth_cname;
            buf_init(&auth, 256);
            buf_init(&auth_vno, 16);
            buf_init(&auth_realm, 64);
            buf_init(&auth_cname, 128);

            asn1_encode_integer(&auth_vno, 5);
            asn1_context_wrap(&auth, 0, &auth_vno);

            asn1_encode_general_string(&auth_realm, realm);
            asn1_context_wrap(&auth, 1, &auth_realm);

            /* cname */
            KRB_BUFFER name_type, name_str, name_seq;
            buf_init(&name_type, 16);
            buf_init(&name_str, 64);
            buf_init(&name_seq, 128);

            asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
            asn1_context_wrap(&name_seq, 0, &name_type);

            asn1_encode_general_string(&tmp, "user");
            asn1_wrap(&name_str, ASN1_SEQUENCE, &tmp);
            asn1_context_wrap(&name_seq, 1, &name_str);
            buf_reset(&tmp);

            asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
            asn1_context_wrap(&auth, 2, &tmp);
            buf_reset(&tmp);

            buf_free(&name_type);
            buf_free(&name_str);
            buf_free(&name_seq);

            /* cusec + ctime */
            SYSTEMTIME st;
            KERNEL32$GetSystemTime(&st);
            char timeStr[32];
            sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            asn1_encode_integer(&tmp, st.wMilliseconds * 1000);
            asn1_context_wrap(&auth, 4, &tmp);
            buf_reset(&tmp);

            asn1_encode_generalized_time(&tmp, timeStr);
            asn1_context_wrap(&auth, 5, &tmp);
            buf_reset(&tmp);

            asn1_wrap(&tmp, ASN1_APP(2), &auth);

            buf_free(&auth);
            buf_free(&auth_vno);
            buf_free(&auth_realm);
            buf_free(&auth_cname);
        }

        /* EncryptedData wrapper for authenticator */
        {
            KRB_BUFFER enc_auth, enc_etype, enc_cipher;
            buf_init(&enc_auth, 512);
            buf_init(&enc_etype, 16);
            buf_init(&enc_cipher, 256);

            asn1_encode_integer(&enc_etype, ETYPE_RC4_HMAC);
            asn1_context_wrap(&enc_auth, 0, &enc_etype);

            asn1_encode_octet_string(&enc_cipher, tmp.data, tmp.length);
            asn1_context_wrap(&enc_auth, 2, &enc_cipher);

            buf_reset(&tmp);
            asn1_wrap(&tmp, ASN1_SEQUENCE, &enc_auth);
            asn1_context_wrap(&apreq, 4, &tmp);

            buf_free(&enc_auth);
            buf_free(&enc_etype);
            buf_free(&enc_cipher);
        }
        buf_reset(&tmp);

        asn1_wrap(&tmp, ASN1_APP(14), &apreq);

        asn1_encode_octet_string(&pa_value, tmp.data, tmp.length);
        asn1_context_wrap(&pa_tgsreq, 2, &pa_value);

        buf_reset(&tmp);
        asn1_wrap(&tmp, ASN1_SEQUENCE, &pa_tgsreq);
        buf_append(&pa_list, tmp.data, tmp.length);

        asn1_wrap(&padata, ASN1_SEQUENCE, &pa_list);
        asn1_context_wrap(&tgsreq, 3, &padata);

        buf_free(&apreq);
        buf_free(&ap_pvno);
        buf_free(&ap_msgtype);
        buf_free(&ap_opts);
        buf_free(&ap_ticket);
        buf_free(&ap_auth);
        buf_free(&pa_list);
        buf_free(&pa_tgsreq);
        buf_free(&pa_type);
        buf_free(&pa_value);
    }
    buf_reset(&tmp);

    /* req-body [4] */
    /* KDC options with ENC-TKT-IN-SKEY */
    kdc_opts[0] = (kdc_options >> 24) & 0xFF;
    kdc_opts[1] = (kdc_options >> 16) & 0xFF;
    kdc_opts[2] = (kdc_options >> 8) & 0xFF;
    kdc_opts[3] = kdc_options & 0xFF;
    asn1_encode_bit_string(&tmp, kdc_opts, 4, 0);
    asn1_context_wrap(&body, 0, &tmp);
    buf_reset(&tmp);

    /* realm [2] */
    asn1_encode_general_string(&tmp, realm);
    asn1_context_wrap(&body, 2, &tmp);
    buf_reset(&tmp);

    /* sname [3] - target user as principal */
    {
        KRB_BUFFER name_type, name_string, name_seq;
        buf_init(&name_type, 16);
        buf_init(&name_string, 128);
        buf_init(&name_seq, 256);

        asn1_encode_integer(&name_type, KRB5_NT_PRINCIPAL);
        asn1_context_wrap(&name_seq, 0, &name_type);

        asn1_encode_general_string(&tmp, targetUser);
        asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
        asn1_context_wrap(&name_seq, 1, &name_string);

        buf_reset(&tmp);
        asn1_wrap(&tmp, ASN1_SEQUENCE, &name_seq);
        asn1_context_wrap(&body, 3, &tmp);

        buf_free(&name_type);
        buf_free(&name_string);
        buf_free(&name_seq);
    }
    buf_reset(&tmp);

    /* till [5] */
    asn1_encode_generalized_time(&tmp, "20370913024805Z");
    asn1_context_wrap(&body, 5, &tmp);
    buf_reset(&tmp);

    /* nonce [7] */
    DWORD nonce = KERNEL32$GetTickCount();
    asn1_encode_integer(&tmp, nonce);
    asn1_context_wrap(&body, 7, &tmp);
    buf_reset(&tmp);

    /* etype [8] */
    asn1_encode_integer(&tmp, ETYPE_AES256_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_AES128_CTS_HMAC_SHA1);
    buf_append(&etype_list, tmp.data, tmp.length);
    buf_reset(&tmp);
    asn1_encode_integer(&tmp, ETYPE_RC4_HMAC);
    buf_append(&etype_list, tmp.data, tmp.length);

    asn1_wrap(&etype_seq, ASN1_SEQUENCE, &etype_list);
    asn1_context_wrap(&body, 8, &etype_seq);
    buf_reset(&tmp);

    /* additional-tickets [11] - target user's TGT */
    buf_append(&addl_tickets, targetTgt, targetTgtLen);
    asn1_wrap(&tmp, ASN1_SEQUENCE, &addl_tickets);
    asn1_context_wrap(&body, 11, &tmp);


    buf_reset(&tmp);
    asn1_wrap(&req_body, ASN1_SEQUENCE, &body);
    asn1_context_wrap(&tgsreq, 4, &req_body);


    asn1_wrap(out, ASN1_APP(KRB5_TGS_REQ), &tgsreq);

    buf_free(&tgsreq);
    buf_free(&pvno);
    buf_free(&msg_type);
    buf_free(&padata);
    buf_free(&req_body);
    buf_free(&body);
    buf_free(&tmp);
    buf_free(&etype_seq);
    buf_free(&etype_list);
    buf_free(&addl_tickets);
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* tgt_b64 = NULL;
    char* targetTgt_b64 = NULL;
    char* targetUser = NULL;
    char* domain = NULL;
    char* dc = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: User-to-User (U2U) Ticket Request\n\n");


    tgt_b64 = arg_get(&parser, "tgt");
    targetTgt_b64 = arg_get(&parser, "targettgt");
    targetUser = arg_get(&parser, "targetuser");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!tgt_b64 || !targetUser) {
        BeaconFormatPrintf(&output, "[-] Error: /tgt:BASE64 and /targetuser:USER required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_u2u /tgt:YOUR_TGT /targetuser:USER [/targettgt:TARGET_TGT]\n");
        BeaconFormatPrintf(&output, "               [/domain:DOMAIN] [/dc:DC]\n\n");
        BeaconFormatPrintf(&output, "Performs User-to-User Kerberos authentication.\n\n");
        BeaconFormatPrintf(&output, "In U2U authentication:\n");
        BeaconFormatPrintf(&output, "  - The service ticket is encrypted with the target user's\n");
        BeaconFormatPrintf(&output, "    TGT session key instead of a long-term service key\n");
        BeaconFormatPrintf(&output, "  - KDC option ENC-TKT-IN-SKEY is set\n");
        BeaconFormatPrintf(&output, "  - Target's TGT is included in additional-tickets\n\n");
        BeaconFormatPrintf(&output, "Options:\n");
        BeaconFormatPrintf(&output, "  /tgt        - Your TGT (base64 kirbi or AS-REP)\n");
        BeaconFormatPrintf(&output, "  /targetuser - Target user to get U2U ticket for\n");
        BeaconFormatPrintf(&output, "  /targettgt  - Target user's TGT (if you have it)\n");
        BeaconFormatPrintf(&output, "  /domain     - Domain name\n");
        BeaconFormatPrintf(&output, "  /dc         - Domain controller\n");
        goto cleanup;
    }

    /* Decode TGTs */
    size_t tgtLen;
    BYTE* tgt = b64_decode_alloc(tgt_b64, &tgtLen);
    if (!tgt) {
        BeaconFormatPrintf(&output, "[-] Failed to decode TGT\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Your TGT: %d bytes\n", (int)tgtLen);

    /* Extract ticket from TGT */
    BYTE* clientTicket = NULL;
    size_t clientTicketLen = 0;
    char realm[256] = {0};
    char cname[256] = {0};

    if (!extract_ticket_from_tgt(tgt, tgtLen, &clientTicket, &clientTicketLen, realm, sizeof(realm), cname, sizeof(cname))) {
        BeaconFormatPrintf(&output, "[-] Failed to extract ticket from TGT\n");
        free(tgt);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Extracted client ticket: %d bytes\n", (int)clientTicketLen);
    if (realm[0]) BeaconFormatPrintf(&output, "[*] Realm: %s\n", realm);
    if (cname[0]) BeaconFormatPrintf(&output, "[*] Client: %s\n", cname);

    /* Use domain from TGT if not specified */
    if (!domain && realm[0]) {
        domain = _strdup(realm);
    } else if (!domain) {
        domain = get_domain_from_env();
    }

    if (!domain) {
        BeaconFormatPrintf(&output, "[-] Could not determine domain\n");
        free(clientTicket);
        free(tgt);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Target user: %s\n", targetUser);
    BeaconFormatPrintf(&output, "[*] Domain: %s\n", domain);

    /* Handle target TGT */
    BYTE* targetTicket = NULL;
    size_t targetTicketLen = 0;

    if (targetTgt_b64) {
        size_t targetTgtLen;
        BYTE* targetTgt = b64_decode_alloc(targetTgt_b64, &targetTgtLen);
        if (targetTgt) {
            char dummy1[64], dummy2[64];
            if (extract_ticket_from_tgt(targetTgt, targetTgtLen, &targetTicket, &targetTicketLen, dummy1, sizeof(dummy1), dummy2, sizeof(dummy2))) {
                BeaconFormatPrintf(&output, "[*] Target TGT provided: %d bytes\n", (int)targetTicketLen);
            }
            free(targetTgt);
        }
    }

    if (!targetTicket) {
        /* For U2U without target TGT, we'd need to obtain it first */
        /* This is a simplified demonstration - real U2U needs the target's TGT */
        BeaconFormatPrintf(&output, "[!] No target TGT provided\n");
        BeaconFormatPrintf(&output, "[!] Using client ticket as placeholder (for demonstration)\n");
        BeaconFormatPrintf(&output, "[!] Real U2U requires the target user's TGT\n");
        targetTicket = (BYTE*)malloc(clientTicketLen);
        memcpy(targetTicket, clientTicket, clientTicketLen);
        targetTicketLen = clientTicketLen;
    }

    int dc_is_domain = 0;
    if (!dc) {
        dc = domain;
        dc_is_domain = 1;
    }
    BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);


    WSADATA wsaData;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconFormatPrintf(&output, "[-] WSAStartup failed\n");
        free(targetTicket);
        free(clientTicket);
        free(tgt);
        goto cleanup;
    }

    /* Connect to KDC */
    SOCKET sock = connect_to_kdc(dc, KRB5_PORT);
    if (sock == INVALID_SOCKET) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to KDC\n");
        WS2_32$WSACleanup();
        free(targetTicket);
        free(clientTicket);
        free(tgt);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "\n[*] Building TGS-REQ with ENC-TKT-IN-SKEY (U2U)...\n");

    /* Build TGS-REQ */
    KRB_BUFFER request;
    buf_init(&request, 8192);
    build_u2u_tgsreq(&request, targetUser, domain, clientTicket, clientTicketLen,
                     targetTicket, targetTicketLen);

    BeaconFormatPrintf(&output, "[*] Sending TGS-REQ (%d bytes)...\n", (int)request.length);

    if (send_krb_msg(sock, request.data, request.length) <= 0) {
        BeaconFormatPrintf(&output, "[-] Failed to send TGS-REQ\n");
        buf_free(&request);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        free(targetTicket);
        free(clientTicket);
        free(tgt);
        goto cleanup;
    }


    BYTE response[16384];
    int recvLen = recv_krb_msg(sock, response, sizeof(response));

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    buf_free(&request);
    free(targetTicket);
    free(clientTicket);
    free(tgt);

    if (recvLen <= 4) {
        BeaconFormatPrintf(&output, "[-] No response from KDC\n");
        goto cleanup;
    }

    BYTE* respData = response + 4;
    int respLen = recvLen - 4;

    if (respData[0] == 0x6D) {
        /* TGS-REP */
        BeaconFormatPrintf(&output, "[+] Received TGS-REP!\n");
        BeaconFormatPrintf(&output, "[+] U2U service ticket obtained!\n");

        char* b64 = b64_encode_alloc(respData, respLen);
        if (b64) {
            BeaconFormatPrintf(&output, "\n[*] U2U Ticket (TGS-REP base64):\n");
            size_t b64len = strlen(b64);
            for (size_t i = 0; i < b64len; i += 76) {
                BeaconFormatPrintf(&output, "  %.76s\n", b64 + i);
            }
            free(b64);
        }

    } else if (respData[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconFormatPrintf(&output, "[-] Received KRB-ERROR\n");

        for (size_t i = 0; i < (size_t)respLen - 4; i++) {
            if (respData[i] == 0xA6) {
                size_t off = i + 1;
                asn1_decode_length(respData, &off);
                if (respData[off] == 0x02) {
                    off++;
                    size_t intLen = asn1_decode_length(respData, &off);
                    DWORD errCode = 0;
                    for (size_t j = 0; j < intLen; j++) {
                        errCode = (errCode << 8) | respData[off + j];
                    }
                    BeaconFormatPrintf(&output, "[*] Error code: %d ", errCode);
                    switch (errCode) {
                        case 7:  BeaconFormatPrintf(&output, "(KDC_ERR_S_PRINCIPAL_UNKNOWN)\n"); break;
                        case 31: BeaconFormatPrintf(&output, "(KRB_AP_ERR_MODIFIED)\n"); break;
                        case 41: BeaconFormatPrintf(&output, "(KRB_AP_ERR_TKT_EXPIRED)\n"); break;
                        default: BeaconFormatPrintf(&output, "(Unknown)\n"); break;
                    }
                    break;
                }
            }
        }
    } else {
        BeaconFormatPrintf(&output, "[?] Unknown response: 0x%02X\n", respData[0]);
    }

cleanup:
    if (tgt_b64) free(tgt_b64);
    if (targetTgt_b64) free(targetTgt_b64);
    if (targetUser) free(targetUser);
    if (domain) free(domain);
    if (dc && !dc_is_domain) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
