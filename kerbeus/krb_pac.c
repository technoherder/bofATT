/*
 * krb_pac - Decode and display PAC (Privilege Attribute Certificate) data
 *
 * Extracts and parses the PAC from a Kerberos ticket, displaying
 * user SID, group memberships, and other authorization data.
 *
 * Usage: krb_pac [/service:SPN] [/luid:0xLUID]
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* PAC structures */
#define PAC_LOGON_INFO          1
#define PAC_CREDENTIALS_INFO    2
#define PAC_SERVER_CHECKSUM     6
#define PAC_PRIVSVR_CHECKSUM    7
#define PAC_CLIENT_INFO         10
#define PAC_DELEGATION_INFO     11
#define PAC_UPN_DNS_INFO        12
#define PAC_CLIENT_CLAIMS       13
#define PAC_DEVICE_INFO         14
#define PAC_DEVICE_CLAIMS       15
#define PAC_TICKET_CHECKSUM     16

typedef struct _PAC_INFO_BUFFER {
    ULONG ulType;
    ULONG cbBufferSize;
    ULONG64 Offset;
} PAC_INFO_BUFFER;

typedef struct _PACTYPE {
    ULONG cBuffers;
    ULONG Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE;

/* SID structure for parsing */
typedef struct _MY_SID {
    BYTE Revision;
    BYTE SubAuthorityCount;
    BYTE IdentifierAuthority[6];
    DWORD SubAuthority[15];
} MY_SID;

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

/* Format SID to string */
static void format_sid(BYTE* sidData, char* buf, size_t bufsize) {
    MY_SID* sid = (MY_SID*)sidData;
    if (!sid || sid->Revision != 1) {
        strcpy(buf, "(invalid SID)");
        return;
    }

    /* Build authority value */
    ULONG64 authority = 0;
    for (int i = 0; i < 6; i++) {
        authority = (authority << 8) | sid->IdentifierAuthority[i];
    }

    int offset = sprintf(buf, "S-%d-%llu", sid->Revision, authority);

    for (BYTE i = 0; i < sid->SubAuthorityCount && i < 15; i++) {
        offset += sprintf(buf + offset, "-%lu", sid->SubAuthority[i]);
    }
}

/* Get PAC type name */
static const char* pac_type_name(ULONG type) {
    switch (type) {
        case PAC_LOGON_INFO: return "LOGON_INFO";
        case PAC_CREDENTIALS_INFO: return "CREDENTIALS_INFO";
        case PAC_SERVER_CHECKSUM: return "SERVER_CHECKSUM";
        case PAC_PRIVSVR_CHECKSUM: return "PRIVSVR_CHECKSUM";
        case PAC_CLIENT_INFO: return "CLIENT_INFO";
        case PAC_DELEGATION_INFO: return "DELEGATION_INFO";
        case PAC_UPN_DNS_INFO: return "UPN_DNS_INFO";
        case PAC_CLIENT_CLAIMS: return "CLIENT_CLAIMS";
        case PAC_DEVICE_INFO: return "DEVICE_INFO";
        case PAC_DEVICE_CLAIMS: return "DEVICE_CLAIMS";
        case PAC_TICKET_CHECKSUM: return "TICKET_CHECKSUM";
        default: return "UNKNOWN";
    }
}

/* Parse PAC_CLIENT_INFO */
static void parse_client_info(BYTE* data, ULONG size, formatp* output) {
    if (size < 10) return;

    /* Client ID (FILETIME) */
    FILETIME* ft = (FILETIME*)data;
    SYSTEMTIME st;
    if (KERNEL32$FileTimeToSystemTime(ft, &st)) {
        BeaconFormatPrintf(output, "    Client Time: %04d-%02d-%02d %02d:%02d:%02d\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }

    /* Name length and name */
    USHORT nameLen = *(USHORT*)(data + 8);
    if (size >= 10 + nameLen) {
        WCHAR* name = (WCHAR*)(data + 10);
        char nameBuf[256];
        MSVCRT$wcstombs(nameBuf, name, nameLen / 2);
        nameBuf[nameLen / 2] = '\0';
        BeaconFormatPrintf(output, "    Client Name: %s\n", nameBuf);
    }
}

/* Parse UPN_DNS_INFO */
static void parse_upn_dns(BYTE* data, ULONG size, formatp* output) {
    if (size < 16) return;

    USHORT upnLen = *(USHORT*)(data);
    USHORT upnOffset = *(USHORT*)(data + 2);
    USHORT dnsLen = *(USHORT*)(data + 4);
    USHORT dnsOffset = *(USHORT*)(data + 6);
    ULONG flags = *(ULONG*)(data + 8);

    if (upnOffset + upnLen <= size) {
        char upnBuf[512];
        MSVCRT$wcstombs(upnBuf, (WCHAR*)(data + upnOffset), upnLen / 2);
        upnBuf[upnLen / 2] = '\0';
        BeaconFormatPrintf(output, "    UPN: %s\n", upnBuf);
    }

    if (dnsOffset + dnsLen <= size) {
        char dnsBuf[512];
        MSVCRT$wcstombs(dnsBuf, (WCHAR*)(data + dnsOffset), dnsLen / 2);
        dnsBuf[dnsLen / 2] = '\0';
        BeaconFormatPrintf(output, "    DNS Domain: %s\n", dnsBuf);
    }

    BeaconFormatPrintf(output, "    Flags: 0x%08X\n", flags);
}

/* Parse checksum info */
static void parse_checksum(BYTE* data, ULONG size, formatp* output) {
    if (size < 4) return;

    ULONG checksumType = *(ULONG*)data;
    const char* typeName;

    switch (checksumType) {
        case 0xFFFFFF76: typeName = "HMAC-MD5 (-138)"; break;
        case 16: typeName = "HMAC-SHA1-96-AES128"; break;
        case 17: typeName = "HMAC-SHA1-96-AES256"; break;
        default: typeName = "Unknown"; break;
    }

    BeaconFormatPrintf(output, "    Checksum Type: %s (%d)\n", typeName, checksumType);

    if (size > 4) {
        BeaconFormatPrintf(output, "    Checksum: ");
        for (ULONG i = 4; i < size && i < 24; i++) {
            BeaconFormatPrintf(output, "%02X", data[i]);
        }
        if (size > 24) BeaconFormatPrintf(output, "...");
        BeaconFormatPrintf(output, "\n");
    }
}

/* Parse PAC from ticket */
static void parse_pac(BYTE* pacData, ULONG pacSize, formatp* output) {
    if (pacSize < sizeof(PACTYPE) - sizeof(PAC_INFO_BUFFER)) {
        BeaconFormatPrintf(output, "[-] PAC too small\n");
        return;
    }

    PACTYPE* pac = (PACTYPE*)pacData;

    BeaconFormatPrintf(output, "[*] PAC Version: %d\n", pac->Version);
    BeaconFormatPrintf(output, "[*] PAC Buffers: %d\n\n", pac->cBuffers);

    for (ULONG i = 0; i < pac->cBuffers; i++) {
        PAC_INFO_BUFFER* buf = &pac->Buffers[i];

        BeaconFormatPrintf(output, "  [%d] Type: %s (%d)\n", i,
            pac_type_name(buf->ulType), buf->ulType);
        BeaconFormatPrintf(output, "      Size: %d bytes\n", buf->cbBufferSize);
        BeaconFormatPrintf(output, "      Offset: 0x%llX\n", buf->Offset);

        /* Validate offset */
        if (buf->Offset + buf->cbBufferSize > pacSize) {
            BeaconFormatPrintf(output, "      [!] Invalid offset/size\n\n");
            continue;
        }

        BYTE* bufData = pacData + buf->Offset;

        switch (buf->ulType) {
            case PAC_CLIENT_INFO:
                parse_client_info(bufData, buf->cbBufferSize, output);
                break;
            case PAC_UPN_DNS_INFO:
                parse_upn_dns(bufData, buf->cbBufferSize, output);
                break;
            case PAC_SERVER_CHECKSUM:
            case PAC_PRIVSVR_CHECKSUM:
            case PAC_TICKET_CHECKSUM:
                parse_checksum(bufData, buf->cbBufferSize, output);
                break;
            case PAC_LOGON_INFO:
                BeaconFormatPrintf(output, "    (KERB_VALIDATION_INFO - complex NDR structure)\n");
                break;
            default:
                BeaconFormatPrintf(output, "    (Raw data - %d bytes)\n", buf->cbBufferSize);
                break;
        }
        BeaconFormatPrintf(output, "\n");
    }
}

/* Retrieve and parse PAC from a ticket */
static int analyze_ticket_pac(HANDLE hLsa, ULONG authPackage, PLUID luid,
                               UNICODE_STRING* serverName, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE response = NULL;
    ULONG requestSize, responseSize = 0;
    char* sname = unicode_to_char(serverName);
    int result = 0;

    if (!sname) return 0;

    BeaconFormatPrintf(output, "\n========================================\n");
    BeaconFormatPrintf(output, "Service: %s\n", sname);
    BeaconFormatPrintf(output, "========================================\n");

    /* Allocate request */
    requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + serverName->MaximumLength;
    request = (KERB_RETRIEVE_TKT_REQUEST*)malloc(requestSize);
    if (!request) {
        free(sname);
        return 0;
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
        /* The encoded ticket is in KRB-CRED format */
        /* PAC is embedded in the encrypted ticket portion */
        /* For full PAC analysis, we'd need to decrypt - showing structure info instead */

        BeaconFormatPrintf(output, "[*] Ticket Size: %d bytes\n", response->Ticket.EncodedTicketSize);

        /* Look for PAC signature in the raw data (if accessible) */
        /* In practice, PAC is encrypted; this shows the ticket structure */
        BYTE* ticketData = response->Ticket.EncodedTicket;
        ULONG ticketSize = response->Ticket.EncodedTicketSize;

        BeaconFormatPrintf(output, "[*] Ticket format: ");
        if (ticketData[0] == 0x76) {
            BeaconFormatPrintf(output, "KRB-CRED (Application 22)\n");
        } else if (ticketData[0] == 0x61) {
            BeaconFormatPrintf(output, "AP-REP (Application 15)\n");
        } else {
            BeaconFormatPrintf(output, "Unknown (0x%02X)\n", ticketData[0]);
        }

        BeaconFormatPrintf(output, "[!] Note: PAC is encrypted within the ticket.\n");
        BeaconFormatPrintf(output, "[!] Full PAC decoding requires the service key.\n");

        result = 1;
    } else {
        BeaconFormatPrintf(output, "[-] Failed to retrieve ticket: 0x%08X\n", status);
    }

    if (response) SECUR32$LsaFreeReturnBuffer(response);
    free(request);
    free(sname);
    return result;
}

/* Query and analyze tickets */
static int analyze_tickets(HANDLE hLsa, ULONG authPackage, PLUID luid,
                            const char* service_filter, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_QUERY_TKT_CACHE_REQUEST request;
    PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
    ULONG responseSize = 0;
    int analyzed = 0;

    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    request.LogonId = *luid;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, &request, sizeof(request),
        (PVOID*)&response, &responseSize, &subStatus);

    if (status != 0 || !response) {
        BeaconFormatPrintf(output, "[-] Failed to query ticket cache\n");
        return 0;
    }

    BeaconFormatPrintf(output, "[*] Found %d cached ticket(s)\n", response->CountOfTickets);

    for (ULONG i = 0; i < response->CountOfTickets; i++) {
        char* sname = unicode_to_char(&response->Tickets[i].ServerName);
        if (!sname) continue;

        /* Apply filter if specified */
        if (service_filter && !strstr(sname, service_filter)) {
            free(sname);
            continue;
        }

        free(sname);
        analyze_ticket_pac(hLsa, authPackage, luid, &response->Tickets[i].ServerName, output);
        analyzed++;
    }

    SECUR32$LsaFreeReturnBuffer(response);
    return analyzed;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* service_filter = NULL;
    char* luid_str = NULL;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LUID targetLuid = {0};
    LSA_STRING kerbName;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: PAC Analysis\n\n");


    service_filter = arg_get(&parser, "service");
    luid_str = arg_get(&parser, "luid");

    if (service_filter) {
        BeaconFormatPrintf(&output, "[*] Filter: %s\n", service_filter);
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

    int count = analyze_tickets(hLsa, authPackage, &targetLuid, service_filter, &output);
    BeaconFormatPrintf(&output, "\n[*] Analyzed %d ticket(s)\n", count);

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    if (service_filter) free(service_filter);
    if (luid_str) free(luid_str);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
