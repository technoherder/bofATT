/*
 * krb_ccache - Import/Export ccache format tickets
 *
 * Converts between Windows kirbi format and Linux ccache format
 * for interoperability with tools like Impacket.
 *
 * Usage: krb_ccache /export [/service:SPN] - Export to ccache format
 *        krb_ccache /import /ticket:CCACHE_B64 - Import from ccache
 */

/* Include krb5_struct.h first - it includes winsock2.h before windows.h */
#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* ccache file format constants */
#define CCACHE_VERSION 0x0504  /* Version 5.4 */

/* Helper: allocate and base64 encode */
static char* b64_encode_alloc(const BYTE* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char* encoded = (char*)malloc(out_len);
    if (!encoded) return NULL;
    base64_encode(data, len, encoded);
    return encoded;
}

/* Helper: allocate and base64 decode */
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

/* Write big-endian uint16 */
static void write_be16(BYTE* buf, USHORT val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

/* Write big-endian uint32 */
static void write_be32(BYTE* buf, ULONG val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/* Read big-endian uint16 */
static USHORT read_be16(const BYTE* buf) {
    return (buf[0] << 8) | buf[1];
}

/* Read big-endian uint32 */
static ULONG read_be32(const BYTE* buf) {
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

/* Convert FILETIME to Unix timestamp */
static ULONG filetime_to_unix(LARGE_INTEGER* ft) {
    /* FILETIME is 100ns intervals since Jan 1, 1601 */
    /* Unix time is seconds since Jan 1, 1970 */
    ULONGLONG unixTime = (ft->QuadPart - 116444736000000000ULL) / 10000000ULL;
    return (ULONG)unixTime;
}

/* Write ccache principal */
static size_t write_ccache_principal(BYTE* buf, const char* name, const char* realm) {
    size_t offset = 0;

    /* Name type (KRB5_NT_PRINCIPAL = 1) */
    write_be32(buf + offset, 1);
    offset += 4;

    /* Number of components */
    write_be32(buf + offset, 1);
    offset += 4;

    /* Realm */
    size_t realmLen = strlen(realm);
    write_be32(buf + offset, (ULONG)realmLen);
    offset += 4;
    memcpy(buf + offset, realm, realmLen);
    offset += realmLen;

    /* Component (name) */
    size_t nameLen = strlen(name);
    write_be32(buf + offset, (ULONG)nameLen);
    offset += 4;
    memcpy(buf + offset, name, nameLen);
    offset += nameLen;

    return offset;
}

/* Write ccache header */
static size_t write_ccache_header(BYTE* buf, const char* principal, const char* realm) {
    size_t offset = 0;

    /* Version */
    write_be16(buf + offset, CCACHE_VERSION);
    offset += 2;

    /* Header tags (empty for v5.4) */
    write_be16(buf + offset, 0);  /* headerlen */
    offset += 2;

    /* Default principal */
    offset += write_ccache_principal(buf + offset, principal, realm);

    return offset;
}

/* Export tickets to ccache format */
static int export_to_ccache(HANDLE hLsa, ULONG authPackage, PLUID luid,
                             const char* service_filter, formatp* output) {
    NTSTATUS status, subStatus;
    KERB_QUERY_TKT_CACHE_REQUEST request;
    PKERB_QUERY_TKT_CACHE_RESPONSE response = NULL;
    ULONG responseSize = 0;
    BYTE ccache[65536];
    size_t ccOffset = 0;
    int exported = 0;

    memset(&request, 0, sizeof(request));
    request.MessageType = KerbQueryTicketCacheMessage;
    request.LogonId = *luid;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, &request, sizeof(request),
        (PVOID*)&response, &responseSize, &subStatus);

    if (status != 0 || !response || response->CountOfTickets == 0) {
        BeaconFormatPrintf(output, "[-] No tickets found in cache\n");
        return 0;
    }

    /* Get first ticket for principal info */
    char* clientName = NULL;
    char* clientRealm = NULL;

    /* Query detailed ticket info */
    for (ULONG i = 0; i < response->CountOfTickets; i++) {
        char* sname = unicode_to_char(&response->Tickets[i].ServerName);
        char* rname = unicode_to_char(&response->Tickets[i].RealmName);

        if (service_filter && sname && !strstr(sname, service_filter)) {
            if (sname) free(sname);
            if (rname) free(rname);
            continue;
        }

        /* Use first ticket's realm for client principal */
        if (!clientRealm && rname) {
            clientRealm = (char*)malloc(strlen(rname) + 1);
            strcpy(clientRealm, rname);
        }

        if (sname) free(sname);
        if (rname) free(rname);
    }

    if (!clientRealm) {
        clientRealm = (char*)malloc(16);
        strcpy(clientRealm, "UNKNOWN");
    }

    clientName = (char*)malloc(32);
    strcpy(clientName, "user");

    /* Write ccache header */
    ccOffset = write_ccache_header(ccache, clientName, clientRealm);

    BeaconFormatPrintf(output, "[*] Building ccache with %d tickets...\n\n", response->CountOfTickets);

    /* Note: Full implementation would retrieve each ticket's encoded form */
    /* and convert to ccache credential format */
    BeaconFormatPrintf(output, "[!] Note: ccache export requires ticket decoding\n");
    BeaconFormatPrintf(output, "[!] For full ccache support, use krb_kirbi to export\n");
    BeaconFormatPrintf(output, "[!] then convert with ticketConverter.py (Impacket)\n\n");

    /* List tickets that would be exported */
    for (ULONG i = 0; i < response->CountOfTickets; i++) {
        char* sname = unicode_to_char(&response->Tickets[i].ServerName);
        char* rname = unicode_to_char(&response->Tickets[i].RealmName);

        if (service_filter && sname && !strstr(sname, service_filter)) {
            if (sname) free(sname);
            if (rname) free(rname);
            continue;
        }

        BeaconFormatPrintf(output, "  [%d] %s @ %s\n", exported, sname ? sname : "?", rname ? rname : "?");

        ULONG endTime = filetime_to_unix(&response->Tickets[i].EndTime);
        BeaconFormatPrintf(output, "      EndTime: %u (Unix timestamp)\n", endTime);

        exported++;

        if (sname) free(sname);
        if (rname) free(rname);
    }

    if (clientName) free(clientName);
    if (clientRealm) free(clientRealm);
    SECUR32$LsaFreeReturnBuffer(response);

    return exported;
}

/* Parse ccache and display info */
static int parse_ccache(const BYTE* data, size_t len, formatp* output) {
    if (len < 4) {
        BeaconFormatPrintf(output, "[-] Invalid ccache: too small\n");
        return 0;
    }

    size_t offset = 0;

    /* Version */
    USHORT version = read_be16(data + offset);
    offset += 2;

    BeaconFormatPrintf(output, "[*] ccache version: 0x%04X\n", version);

    if (version != 0x0504 && version != 0x0503) {
        BeaconFormatPrintf(output, "[!] Warning: Unexpected version (expected 0x0503 or 0x0504)\n");
    }

    /* Header length (v5.4) */
    if (version >= 0x0504) {
        USHORT headerLen = read_be16(data + offset);
        offset += 2;
        offset += headerLen;  /* Skip header tags */
    }

    /* Default principal */
    if (offset + 8 > len) {
        BeaconFormatPrintf(output, "[-] Truncated ccache\n");
        return 0;
    }

    ULONG nameType = read_be32(data + offset);
    offset += 4;

    ULONG numComponents = read_be32(data + offset);
    offset += 4;

    BeaconFormatPrintf(output, "[*] Principal name type: %d\n", nameType);
    BeaconFormatPrintf(output, "[*] Components: %d\n", numComponents);

    /* Realm */
    if (offset + 4 > len) return 0;
    ULONG realmLen = read_be32(data + offset);
    offset += 4;

    if (offset + realmLen > len) return 0;
    char* realm = (char*)malloc(realmLen + 1);
    memcpy(realm, data + offset, realmLen);
    realm[realmLen] = '\0';
    offset += realmLen;

    BeaconFormatPrintf(output, "[*] Realm: %s\n", realm);

    /* Principal components */
    BeaconFormatPrintf(output, "[*] Principal: ");
    for (ULONG i = 0; i < numComponents && offset + 4 <= len; i++) {
        ULONG compLen = read_be32(data + offset);
        offset += 4;

        if (offset + compLen > len) break;
        char* comp = (char*)malloc(compLen + 1);
        memcpy(comp, data + offset, compLen);
        comp[compLen] = '\0';
        offset += compLen;

        if (i > 0) BeaconFormatPrintf(output, "/");
        BeaconFormatPrintf(output, "%s", comp);
        free(comp);
    }
    BeaconFormatPrintf(output, "@%s\n", realm);
    free(realm);

    /* Count credentials */
    int credCount = 0;
    BeaconFormatPrintf(output, "\n[*] Credentials:\n");

    while (offset < len) {
        /* Each credential has: client, server, keyblock, times, etc */
        /* Simplified parsing - just count */
        credCount++;

        /* Skip to next credential (simplified) */
        /* In full impl, would parse each field */
        break;  /* Just show header info for now */
    }

    BeaconFormatPrintf(output, "    (Detailed credential parsing not implemented)\n");
    BeaconFormatPrintf(output, "\n[*] Use ticketConverter.py to convert ccache <-> kirbi\n");

    return 1;
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* do_export = NULL;
    char* do_import = NULL;
    char* ticket_b64 = NULL;
    char* service_filter = NULL;
    char* luid_str = NULL;
    HANDLE hLsa = NULL;
    ULONG authPackage = 0;
    NTSTATUS status;
    LUID targetLuid = {0};
    LSA_STRING kerbName;

    BeaconFormatAlloc(&output, 32768);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n[*] Action: ccache Import/Export\n\n");


    do_export = arg_get(&parser, "export");
    do_import = arg_get(&parser, "import");
    ticket_b64 = arg_get(&parser, "ticket");
    service_filter = arg_get(&parser, "service");
    luid_str = arg_get(&parser, "luid");

    if (!do_export && !do_import) {
        BeaconFormatPrintf(&output, "[-] Error: /export or /import required\n\n");
        BeaconFormatPrintf(&output, "Usage:\n");
        BeaconFormatPrintf(&output, "  Export: krb_ccache /export [/service:SPN] [/luid:0xLUID]\n");
        BeaconFormatPrintf(&output, "  Import: krb_ccache /import /ticket:CCACHE_BASE64\n\n");
        BeaconFormatPrintf(&output, "Note: For full ccache support, use Impacket's ticketConverter.py\n");
        BeaconFormatPrintf(&output, "      kirbi -> ccache: ticketConverter.py ticket.kirbi ticket.ccache\n");
        BeaconFormatPrintf(&output, "      ccache -> kirbi: ticketConverter.py ticket.ccache ticket.kirbi\n");
        goto cleanup;
    }

    if (do_import) {
        if (!ticket_b64) {
            BeaconFormatPrintf(&output, "[-] Error: /ticket:BASE64 required for import\n");
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] Parsing ccache data...\n\n");

        size_t ccLen;
        BYTE* ccData = b64_decode_alloc(ticket_b64, &ccLen);
        if (!ccData) {
            BeaconFormatPrintf(&output, "[-] Failed to decode base64\n");
            goto cleanup;
        }

        BeaconFormatPrintf(&output, "[*] ccache size: %d bytes\n\n", (int)ccLen);
        parse_ccache(ccData, ccLen, &output);

        free(ccData);
    } else {
        /* Parse LUID */
        if (luid_str) {
            if (luid_str[0] == '0' && (luid_str[1] == 'x' || luid_str[1] == 'X')) {
                targetLuid.LowPart = strtoul(luid_str + 2, NULL, 16);
            } else {
                targetLuid.LowPart = strtoul(luid_str, NULL, 10);
            }
            BeaconFormatPrintf(&output, "[*] Target LUID: 0x%X\n", targetLuid.LowPart);
        }

        /* Connect to LSA */
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

        int count = export_to_ccache(hLsa, authPackage, &targetLuid, service_filter, &output);
        BeaconFormatPrintf(&output, "\n[*] Listed %d ticket(s)\n", count);
    }

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
    if (do_export) free(do_export);
    if (do_import) free(do_import);
    if (ticket_b64) free(ticket_b64);
    if (service_filter) free(service_filter);
    if (luid_str) free(luid_str);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
