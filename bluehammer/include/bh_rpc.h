/*
 * bh_rpc.h - Minimal Windows Defender RPC stub for BOF
 *
 * This provides a minimal implementation of the Proc42_ServerMpUpdateEngineSignature
 * RPC call without requiring the full 73K-line MIDL-generated stubs.
 *
 * Only the NDR format string bytes needed for procedure 42 are included.
 * NDR64 is not provided; NdrClientCall3 negotiates down to NDR automatically.
 */

#ifndef BH_RPC_H
#define BH_RPC_H

#include <windows.h>
#include <rpc.h>
#include <rpcndr.h>

/*
 * Minimal NDR format strings for Proc42_ServerMpUpdateEngineSignature
 *
 * Proc42 signature:
 *   long Proc42(handle_t h, long arg_1, wchar_t* arg_2, error_status_t* arg_3)
 *
 * The proc format string encodes parameter types, stack offsets, and marshaling info.
 * The type format string encodes complex types (conformant wide string at offset 1414).
 */

/* Proc format: 54 bytes starting at offset 2386 */
static const unsigned char g_BH_Proc42_Bytes[54] = {
    0x00, 0x48,                         /* procedure flags */
    0x00, 0x00, 0x00, 0x00,             /* NdrFcLong(0) */
    0x2a, 0x00,                         /* proc num 42 */
    0x28, 0x00,                         /* stack size 40 */
    0x32, 0x00,                         /* FC_BIND_PRIMITIVE, pad */
    0x00, 0x00,                         /* bind stack offset 0 */
    0x08, 0x00,                         /* constant client buffer size */
    0x24, 0x00,                         /* constant server buffer size */
    0x46, 0x04,                         /* Oi2 flags, 4 params */
    0x0a, 0x01,                         /* extension size, ext flags */
    0x00, 0x00,                         /* corr desc reserved */
    0x00, 0x00,                         /* corr desc reserved */
    0x00, 0x00,                         /* corr desc reserved */
    0x00, 0x00,                         /* corr desc reserved */
    /* arg_1: [in] long */
    0x48, 0x00,                         /* flags: in, base type */
    0x08, 0x00,                         /* stack offset 8 */
    0x08, 0x00,                         /* FC_LONG, pad */
    /* arg_2: [in][string] wchar_t* */
    0x0b, 0x01,                         /* flags: must size, must free, in, simple ref */
    0x10, 0x00,                         /* stack offset 16 */
    0x86, 0x05,                         /* type offset 1414 */
    /* arg_3: [out] error_status_t* */
    0x50, 0x21,                         /* flags: out, base type, simple ref, srv alloc */
    0x18, 0x00,                         /* stack offset 24 */
    0x10, 0x00,                         /* FC_ERROR_STATUS_T, pad */
    /* return value: long */
    0x70, 0x00,                         /* flags: out, return, base type */
    0x20, 0x00,                         /* stack offset 32 */
    0x08, 0x00                          /* FC_LONG, pad */
};

/* Total sizes for format string buffers */
#define BH_PROC_FMT_SIZE  2440
#define BH_TYPE_FMT_SIZE  1416
#define BH_PROC42_OFFSET  2386

/* Runtime state for the RPC module */
typedef struct _BH_RPC_STATE {
    BOOL initialized;

    /* Format strings (zero-filled, patched at init) */
    unsigned char procFmt[BH_PROC_FMT_SIZE];
    unsigned char typeFmt[BH_TYPE_FMT_SIZE];
    unsigned short offsetTable[43];

    /* MIDL structures */
    RPC_CLIENT_INTERFACE clientIface;
    MIDL_STUB_DESC stubDesc;
    MIDL_SYNTAX_INFO syntaxInfo[1];
    MIDL_STUBLESS_PROXY_INFO proxyInfo;

    /* NdrClientCall3 function pointer (loaded from rpcrt4.dll) */
    fn_NdrClientCall3 pfnNdrClientCall3;
    RPC_BINDING_HANDLE autoBindHandle;
} BH_RPC_STATE;

/*
 * MIDL memory allocation functions (required by NDR runtime)
 */
static void __RPC_FAR* __RPC_USER BH_MIDL_user_allocate(size_t cBytes)
{
    return malloc(cBytes);
}

static void __RPC_USER BH_MIDL_user_free(void __RPC_FAR* p)
{
    free(p);
}

/*
 * Initialize the minimal RPC state for calling Defender's Proc42.
 * Must be called before BH_CallWDUpdate().
 * Returns TRUE on success.
 */
static BOOL BH_InitRpc(BH_RPC_STATE* rpc)
{
    HMODULE hRpcRt4;

    if (rpc->initialized)
        return TRUE;

    ZeroMemory(rpc, sizeof(BH_RPC_STATE));

    /* Load NdrClientCall3 from rpcrt4.dll */
    hRpcRt4 = KERNEL32$GetModuleHandleW(L"rpcrt4.dll");
    if (!hRpcRt4)
        hRpcRt4 = LoadLibraryA("rpcrt4.dll");
    if (!hRpcRt4)
        return FALSE;

    rpc->pfnNdrClientCall3 = (fn_NdrClientCall3)GetProcAddress(hRpcRt4, "NdrClientCall3");
    if (!rpc->pfnNdrClientCall3)
        return FALSE;

    /* Initialize type format string - sparse, only set used offsets */
    /* Offset 2-3: FC_RP [alloced_on_stack] [simple_pointer] */
    rpc->typeFmt[2] = 0x11;
    rpc->typeFmt[3] = 0x0c;
    /* Offset 4-5: FC_ERROR_STATUS_T, FC_PAD */
    rpc->typeFmt[4] = 0x10;
    rpc->typeFmt[5] = 0x5c;
    /* Offset 1414-1415: FC_C_WSTRING, FC_PAD */
    rpc->typeFmt[1414] = 0x25;
    rpc->typeFmt[1415] = 0x5c;

    /* Initialize proc format string - copy Proc42 bytes at correct offset */
    memmove(&rpc->procFmt[BH_PROC42_OFFSET], g_BH_Proc42_Bytes, sizeof(g_BH_Proc42_Bytes));

    /* Initialize offset table - only entry 42 matters */
    rpc->offsetTable[42] = BH_PROC42_OFFSET;

    /* Initialize RPC client interface */
    rpc->clientIface.Length = sizeof(RPC_CLIENT_INTERFACE);
    /* Interface UUID: c503f532-443a-4c69-8300-ccd1fbdb3839, version 2.0 */
    rpc->clientIface.InterfaceId.SyntaxGUID.Data1 = 0xc503f532;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data2 = 0x443a;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data3 = 0x4c69;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[0] = 0x83;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[1] = 0x00;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[2] = 0xcc;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[3] = 0xd1;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[4] = 0xfb;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[5] = 0xdb;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[6] = 0x38;
    rpc->clientIface.InterfaceId.SyntaxGUID.Data4[7] = 0x39;
    rpc->clientIface.InterfaceId.SyntaxVersion.MajorVersion = 2;
    rpc->clientIface.InterfaceId.SyntaxVersion.MinorVersion = 0;
    /* NDR transfer syntax */
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data1 = 0x8A885D04;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data2 = 0x1CEB;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data3 = 0x11C9;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[0] = 0x9F;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[1] = 0xE8;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[2] = 0x08;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[3] = 0x00;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[4] = 0x2B;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[5] = 0x10;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[6] = 0x48;
    rpc->clientIface.TransferSyntax.SyntaxGUID.Data4[7] = 0x60;
    rpc->clientIface.TransferSyntax.SyntaxVersion.MajorVersion = 2;
    rpc->clientIface.TransferSyntax.SyntaxVersion.MinorVersion = 0;
    rpc->clientIface.InterpreterInfo = &rpc->proxyInfo;
    rpc->clientIface.Flags = 0x02000000;

    /* Initialize syntax info (NDR only, no NDR64) */
    rpc->syntaxInfo[0].TransferSyntax = rpc->clientIface.TransferSyntax;
    rpc->syntaxInfo[0].DispatchTable = NULL;
    rpc->syntaxInfo[0].ProcString = rpc->procFmt;
    rpc->syntaxInfo[0].FmtStringOffset = rpc->offsetTable;
    rpc->syntaxInfo[0].TypeString = rpc->typeFmt;
    rpc->syntaxInfo[0].aUserMarshalQuadruple = NULL;
    rpc->syntaxInfo[0].pMethodProperties = NULL;
    rpc->syntaxInfo[0].pReserved2 = NULL;

    /* Initialize stub descriptor */
    rpc->stubDesc.RpcInterfaceInformation = &rpc->clientIface;
    rpc->stubDesc.pfnAllocate = BH_MIDL_user_allocate;
    rpc->stubDesc.pfnFree = BH_MIDL_user_free;
    rpc->stubDesc.IMPLICIT_HANDLE_INFO.pAutoHandle = &rpc->autoBindHandle;
    rpc->stubDesc.apfnNdrRundownRoutines = NULL;
    rpc->stubDesc.aGenericBindingRoutinePairs = NULL;
    rpc->stubDesc.apfnExprEval = NULL;
    rpc->stubDesc.aXmitQuintuple = NULL;
    rpc->stubDesc.pFormatTypes = rpc->typeFmt;
    rpc->stubDesc.fCheckBounds = 1;
    rpc->stubDesc.Version = 0x60001;  /* NDR library version */
    rpc->stubDesc.pMallocFreeStruct = NULL;
    rpc->stubDesc.MIDLVersion = 0x8010274;
    rpc->stubDesc.CommFaultOffsets = NULL;
    rpc->stubDesc.CsRoutines = NULL;
    rpc->stubDesc.pProxyInfo = &rpc->proxyInfo;
    rpc->stubDesc.pExprInfo = NULL;

    /* Initialize proxy info */
    rpc->proxyInfo.pStubDesc = &rpc->stubDesc;
    rpc->proxyInfo.ProcFormatString = rpc->procFmt;
    rpc->proxyInfo.FmtStringOffset = rpc->offsetTable;
    rpc->proxyInfo.pTransferSyntax = &rpc->clientIface.TransferSyntax;
    rpc->proxyInfo.nCount = 1;  /* NDR only */
    rpc->proxyInfo.pSyntaxInfo = rpc->syntaxInfo;

    rpc->initialized = TRUE;
    return TRUE;
}

/*
 * Call Windows Defender's ServerMpUpdateEngineSignature RPC method.
 *
 * Parameters:
 *   rpc       - initialized RPC state
 *   dirpath   - path to directory containing update .vdm files
 *   errstat   - receives error status from Defender
 *
 * Returns: RPC_STATUS (0 = success)
 */
static long BH_CallWDUpdate(BH_RPC_STATE* rpc, wchar_t* dirpath, error_status_t* errstat)
{
    RPC_WSTR StringBinding = NULL;
    RPC_BINDING_HANDLE bindhandle = NULL;
    CLIENT_CALL_RETURN_BOF retval;
    RPC_STATUS stat;

    if (!rpc->initialized || !rpc->pfnNdrClientCall3)
        return RPC_S_CALL_FAILED;

    /* Build binding to Defender's ALPC RPC endpoint */
    stat = RPCRT4$RpcStringBindingComposeW(
        (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839",
        (RPC_WSTR)L"ncalrpc",
        NULL,
        (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24",
        NULL,
        &StringBinding);

    if (stat != RPC_S_OK)
        return stat;

    stat = RPCRT4$RpcBindingFromStringBindingW(StringBinding, &bindhandle);
    RPCRT4$RpcStringFreeW(&StringBinding);

    if (stat != RPC_S_OK)
        return stat;

    /* Call Proc42_ServerMpUpdateEngineSignature via NdrClientCall3 */
    retval = rpc->pfnNdrClientCall3(
        (void*)&rpc->proxyInfo,
        42,
        0,
        bindhandle,
        (long)0,       /* arg_1: NULL */
        dirpath,        /* arg_2: update directory path */
        errstat);       /* arg_3: error status output */

    RPCRT4$RpcBindingFree(&bindhandle);

    return (long)retval.Simple;
}

#endif /* BH_RPC_H */
