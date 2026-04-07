/*
 * krb_describe - Parse and describe a Kerberos ticket
 *
 * Usage: krb_describe /ticket:BASE64
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

static void describe_ticket(const BYTE* data, size_t len, formatp* output) {
    size_t offset = 0;

    BeaconFormatPrintf(output, "\n[*] Ticket Information:\n");
    BeaconFormatPrintf(output, "    Size: %zu bytes\n\n", len);

    BYTE tag = data[0];

    if (tag == ASN1_APP(KRB5_AS_REP)) {
        BeaconFormatPrintf(output, "[*] Type: AS-REP (TGT response)\n");
    } else if (tag == ASN1_APP(KRB5_TGS_REP)) {
        BeaconFormatPrintf(output, "[*] Type: TGS-REP (Service ticket response)\n");
    } else if (tag == ASN1_APP(KRB5_AP_REQ)) {
        BeaconFormatPrintf(output, "[*] Type: AP-REQ (Application request)\n");
    } else if (tag == 0x76) {
        /* KRB-CRED (APPLICATION 22) */
        BeaconFormatPrintf(output, "[*] Type: KRB-CRED (Credential message)\n");
    } else if (tag == ASN1_APP(14)) {
        BeaconFormatPrintf(output, "[*] Type: AP-REQ (Application request)\n");
    } else {
        BeaconFormatPrintf(output, "[*] Type: Unknown (tag 0x%02X)\n", tag);
    }

    offset = 1;
    size_t total_len = asn1_decode_length(data, &offset);
    BeaconFormatPrintf(output, "[*] Content length: %zu bytes\n\n", total_len);

    if (data[offset] == ASN1_SEQUENCE) {
        offset++;
        size_t seq_len = asn1_decode_length(data, &offset);

        BeaconFormatPrintf(output, "[*] Parsing ticket structure...\n\n");

        while (offset < len - 4) {
            BYTE ctx_tag = data[offset];
            if ((ctx_tag & 0xE0) != 0xA0) break;

            int ctx_num = ctx_tag & 0x1F;
            offset++;
            size_t field_len = asn1_decode_length(data, &offset);
            size_t field_start = offset;

            switch (ctx_num) {
                case 0:
                    /* pvno or tkt-vno */
                    if (data[offset] == ASN1_INTEGER) {
                        offset++;
                        size_t int_len = asn1_decode_length(data, &offset);
                        int val = 0;
                        for (size_t i = 0; i < int_len && i < 4; i++) {
                            val = (val << 8) | data[offset + i];
                        }
                        BeaconFormatPrintf(output, "    Version: %d\n", val);
                    }
                    break;

                case 1:
                    /* msg-type or realm */
                    if (data[offset] == ASN1_INTEGER) {
                        offset++;
                        size_t int_len = asn1_decode_length(data, &offset);
                        int val = 0;
                        for (size_t i = 0; i < int_len && i < 4; i++) {
                            val = (val << 8) | data[offset + i];
                        }
                        BeaconFormatPrintf(output, "    Message Type: %d\n", val);
                    } else if (data[offset] == ASN1_GENERALSTRING) {
                        offset++;
                        size_t str_len = asn1_decode_length(data, &offset);
                        char* realm = (char*)malloc(str_len + 1);
                        if (realm) {
                            memcpy(realm, data + offset, str_len);
                            realm[str_len] = '\0';
                            BeaconFormatPrintf(output, "    Realm: %s\n", realm);
                            free(realm);
                        }
                    }
                    break;

                case 2:
                    /* crealm or sname */
                    if (data[offset] == ASN1_GENERALSTRING) {
                        offset++;
                        size_t str_len = asn1_decode_length(data, &offset);
                        char* str = (char*)malloc(str_len + 1);
                        if (str) {
                            memcpy(str, data + offset, str_len);
                            str[str_len] = '\0';
                            BeaconFormatPrintf(output, "    Client Realm: %s\n", str);
                            free(str);
                        }
                    }
                    break;

                case 3:
                    /* cname or enc-part */
                    BeaconFormatPrintf(output, "    Client Name: [present]\n");
                    break;

                case 4:
                    /* ticket */
                    BeaconFormatPrintf(output, "    Ticket: [present, %zu bytes]\n", field_len);
                    break;

                case 5:
                    /* enc-part times */
                    BeaconFormatPrintf(output, "    Encrypted Part: [present, %zu bytes]\n", field_len);
                    break;

                case 6:
                    /* enc-part for AS-REP/TGS-REP */
                    if (data[offset] == ASN1_SEQUENCE) {
                        offset++;
                        asn1_decode_length(data, &offset);

                        /* Look for etype */
                        while (offset < field_start + field_len) {
                            if (data[offset] == ASN1_CONTEXT(0)) {
                                offset++;
                                asn1_decode_length(data, &offset);
                                if (data[offset] == ASN1_INTEGER) {
                                    offset++;
                                    size_t int_len = asn1_decode_length(data, &offset);
                                    int etype = 0;
                                    for (size_t i = 0; i < int_len && i < 4; i++) {
                                        etype = (etype << 8) | data[offset + i];
                                    }
                                    BeaconFormatPrintf(output, "    Encryption Type: %s (%d)\n",
                                                      etype_string(etype), etype);
                                }
                                break;
                            }
                            offset++;
                        }
                    }
                    break;
            }

            offset = field_start + field_len;
        }
    }

    BeaconFormatPrintf(output, "\n[*] Describe complete\n");
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 16 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");

    if (!ticket_b64) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_describe /ticket:BASE64");
        BeaconFormatFree(&output);
        return;
    }

    BeaconFormatPrintf(&output, "[*] Action: Describe Ticket\n");

    size_t b64_len = strlen(ticket_b64);
    size_t max_decoded = (b64_len / 4) * 3 + 3;
    BYTE* ticket_data = (BYTE*)malloc(max_decoded);

    if (!ticket_data) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        BeaconFormatFree(&output);
        free(ticket_b64);
        return;
    }

    size_t ticket_len = base64_decode(ticket_b64, b64_len, ticket_data);
    if (ticket_len == 0) {
        BeaconFormatPrintf(&output, "[-] Failed to decode base64 ticket\n");
        free(ticket_data);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        BeaconFormatFree(&output);
        free(ticket_b64);
        return;
    }

    describe_ticket(ticket_data, ticket_len, &output);

    free(ticket_data);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

    BeaconFormatFree(&output);
    free(ticket_b64);
}
