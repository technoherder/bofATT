/*
 * krb_s4u - S4U2Self/S4U2Proxy constrained delegation abuse
 *
 * Usage: krb_s4u /ticket:BASE64 /service:SPN /impersonateuser:USER [/domain:DOMAIN] [/dc:DC] [/altservice:SVC] [/ptt] [/self]
 *        krb_s4u /ticket:BASE64 /service:SPN /tgs:BASE64 [/altservice:SVC] [/ptt]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

/* S4U2Self - Get a service ticket to yourself on behalf of another user */
static int s4u2self(const char* impersonate_user, const char* domain, formatp* output) {
    BeaconFormatPrintf(output, "[*] Performing S4U2Self for user: %s\n", impersonate_user);
    BeaconFormatPrintf(output, "[*] Domain: %s\n\n", domain);

    /* S4U2Self requires:
     * 1. TGT for the service account (from /ticket parameter)
     * 2. Build PA-FOR-USER with target user's name
     * 3. Send TGS-REQ with S4U2Self extension
     *
     * This is complex and requires full Kerberos protocol implementation
     */

    BeaconFormatPrintf(output, "[!] S4U2Self requires full Kerberos protocol implementation\n");
    BeaconFormatPrintf(output, "[*] The attack flow is:\n");
    BeaconFormatPrintf(output, "    1. Use service account TGT to request TGS for ourselves\n");
    BeaconFormatPrintf(output, "    2. Include PA-FOR-USER with target user identity\n");
    BeaconFormatPrintf(output, "    3. KDC returns service ticket for target user to our service\n\n");

    return 0;
}

/* S4U2Proxy - Use an S4U2Self ticket to access another service */
static int s4u2proxy(const BYTE* s4u2self_ticket, size_t ticket_len,
                     const char* target_spn, formatp* output) {
    BeaconFormatPrintf(output, "[*] Performing S4U2Proxy to: %s\n\n", target_spn);

    /* S4U2Proxy requires:
     * 1. Forwardable service ticket from S4U2Self
     * 2. Build TGS-REQ with additional-tickets containing the S4U2Self ticket
     * 3. Send to KDC for target SPN
     *
     * This allows impersonating the user to the target service
     */

    BeaconFormatPrintf(output, "[!] S4U2Proxy requires full Kerberos protocol implementation\n");
    BeaconFormatPrintf(output, "[*] The attack flow is:\n");
    BeaconFormatPrintf(output, "    1. Use S4U2Self ticket as additional-ticket in TGS-REQ\n");
    BeaconFormatPrintf(output, "    2. Request ticket for target service as the impersonated user\n");
    BeaconFormatPrintf(output, "    3. KDC returns ticket allowing access to target service\n\n");

    return 0;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 32 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");
    char* service = arg_get(&parser, "service");
    char* impersonate = arg_get(&parser, "impersonateuser");
    char* tgs_b64 = arg_get(&parser, "tgs");
    char* domain = arg_get(&parser, "domain");
    char* dc = arg_get(&parser, "dc");
    char* altservice = arg_get(&parser, "altservice");
    bool ptt = arg_exists(&parser, "ptt");
    bool self_only = arg_exists(&parser, "self");
    bool nopac = arg_exists(&parser, "nopac");
    bool opsec = arg_exists(&parser, "opsec");

    if (!ticket_b64 || !service) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_s4u /ticket:BASE64 /service:SPN /impersonateuser:USER [options]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_s4u /ticket:BASE64 /service:SPN /tgs:BASE64 [/altservice:SVC]");
        BeaconPrintf(CALLBACK_ERROR, "Options: [/domain:DOMAIN] [/dc:DC] [/ptt] [/self] [/nopac] [/opsec]");
        goto cleanup;
    }

    if (!impersonate && !tgs_b64) {
        BeaconPrintf(CALLBACK_ERROR, "Must specify either /impersonateuser: or /tgs:");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: S4U Delegation Abuse\n");
    BeaconFormatPrintf(&output, "[*] Target Service: %s\n", service);
    if (impersonate) BeaconFormatPrintf(&output, "[*] Impersonate User: %s\n", impersonate);
    if (altservice) BeaconFormatPrintf(&output, "[*] Alt Service: %s\n", altservice);
    if (self_only) BeaconFormatPrintf(&output, "[*] S4U2Self only mode\n");
    BeaconFormatPrintf(&output, "\n");

    /* Get domain if not specified */
    if (!domain) {
        domain = get_domain_from_env();
    }

    /* Decode the TGT ticket */
    size_t b64_len = strlen(ticket_b64);
    size_t max_decoded = (b64_len / 4) * 3 + 3;
    BYTE* ticket_data = (BYTE*)malloc(max_decoded);

    if (!ticket_data) {
        BeaconFormatPrintf(&output, "[-] Memory allocation failed\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    size_t ticket_len = base64_decode(ticket_b64, b64_len, ticket_data);
    if (ticket_len == 0) {
        BeaconFormatPrintf(&output, "[-] Failed to decode base64 ticket\n");
        free(ticket_data);
        BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Decoded TGT: %zu bytes\n\n", ticket_len);

    if (impersonate) {
        /* Perform S4U2Self first */
        s4u2self(impersonate, domain ? domain : "DOMAIN", &output);

        if (!self_only) {
            /* Then S4U2Proxy if not self-only mode */
            BeaconFormatPrintf(&output, "[*] Would proceed with S4U2Proxy to %s\n\n", service);
            s4u2proxy(NULL, 0, service, &output);
        }
    } else if (tgs_b64) {
        /* S4U2Proxy with provided TGS */
        BeaconFormatPrintf(&output, "[*] Using provided TGS for S4U2Proxy\n");
        s4u2proxy(NULL, 0, service, &output);
    }

    BeaconFormatPrintf(&output, "[*] Note: Full S4U implementation requires raw Kerberos protocol\n");
    BeaconFormatPrintf(&output, "[*] Consider using Rubeus or impacket for full S4U support\n");

    free(ticket_data);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (ticket_b64) free(ticket_b64);
    if (service) free(service);
    if (impersonate) free(impersonate);
    if (tgs_b64) free(tgs_b64);
    if (domain) free(domain);
    if (dc) free(dc);
    if (altservice) free(altservice);
}
