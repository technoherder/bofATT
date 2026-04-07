/*
 * krb_changepw - Change user password via Kerberos
 *
 * Usage: krb_changepw /ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#define SECURITY_WIN32
#include <sspi.h>

/* Kerberos password change port */
#define KPASSWD_PORT 464

/* KRB-PRIV message types for password change */
#define KPASSWD_CHANGEPW 1
#define KPASSWD_SETPW    255

/* Result codes */
#define KRB5_KPASSWD_SUCCESS      0
#define KRB5_KPASSWD_MALFORMED    1
#define KRB5_KPASSWD_HARDERROR    2
#define KRB5_KPASSWD_AUTHERROR    3
#define KRB5_KPASSWD_SOFTERROR    4
#define KRB5_KPASSWD_ACCESSDENIED 5
#define KRB5_KPASSWD_BAD_VERSION  6
#define KRB5_KPASSWD_INITIAL_FLAG 7

void go(char* args, int alen) {
    WSADATA wsaData;
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 16 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");
    char* new_password = arg_get(&parser, "new");
    char* dc = arg_get(&parser, "dc");
    char* target_user = arg_get(&parser, "targetuser");
    char* target_domain = arg_get(&parser, "targetdomain");

    if (!ticket_b64 || !new_password) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_changepw /ticket:BASE64 /new:PASSWORD [/dc:DC]");
        BeaconPrintf(CALLBACK_ERROR, "       krb_changepw /ticket:BASE64 /new:PASSWORD /targetuser:USER /targetdomain:DOMAIN");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Change Password via Kerberos\n");
    if (dc) BeaconFormatPrintf(&output, "[*] DC: %s\n", dc);
    if (target_user) BeaconFormatPrintf(&output, "[*] Target User: %s\n", target_user);
    if (target_domain) BeaconFormatPrintf(&output, "[*] Target Domain: %s\n", target_domain);
    BeaconFormatPrintf(&output, "[*] New Password: %s\n\n", new_password);

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

    BeaconFormatPrintf(&output, "[*] Decoded ticket: %zu bytes\n\n", ticket_len);

    /* Password change protocol (RFC 3244):
     *
     * 1. Get a service ticket for kadmin/changepw@REALM
     * 2. Build AP-REQ using that ticket
     * 3. Build KRB-PRIV message containing new password
     * 4. Send to kpasswd service (port 464)
     * 5. Parse response
     */

    BeaconFormatPrintf(&output, "[!] Kerberos password change requires full protocol implementation\n\n");
    BeaconFormatPrintf(&output, "[*] The password change process:\n");
    BeaconFormatPrintf(&output, "    1. Request TGS for kadmin/changepw@REALM\n");
    BeaconFormatPrintf(&output, "    2. Build AP-REQ with the service ticket\n");
    BeaconFormatPrintf(&output, "    3. Build KRB-PRIV containing new password\n");
    BeaconFormatPrintf(&output, "    4. Send to kpasswd service (port 464)\n");
    BeaconFormatPrintf(&output, "    5. Parse KRB-PRIV response for result\n\n");

    if (target_user) {
        BeaconFormatPrintf(&output, "[*] Setting password for another user requires:\n");
        BeaconFormatPrintf(&output, "    - Ticket for a privileged account (admin/password reset rights)\n");
        BeaconFormatPrintf(&output, "    - Using setpw operation (op code 255) instead of changepw\n\n");
    }

    BeaconFormatPrintf(&output, "[*] Result codes:\n");
    BeaconFormatPrintf(&output, "    0 = Success\n");
    BeaconFormatPrintf(&output, "    1 = Malformed request\n");
    BeaconFormatPrintf(&output, "    2 = Hard error\n");
    BeaconFormatPrintf(&output, "    3 = Authentication error\n");
    BeaconFormatPrintf(&output, "    4 = Soft error (password policy violation)\n");
    BeaconFormatPrintf(&output, "    5 = Access denied\n\n");

    BeaconFormatPrintf(&output, "[*] Consider using Rubeus or impacket for full changepw support\n");

    free(ticket_data);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (ticket_b64) free(ticket_b64);
    if (new_password) free(new_password);
    if (dc) free(dc);
    if (target_user) free(target_user);
    if (target_domain) free(target_domain);
}
