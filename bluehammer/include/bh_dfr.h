/*
 * bh_dfr.h - Dynamic Function Resolution declarations for BlueHammer BOFs
 *
 * All Windows API calls used by BlueHammer BOFs are declared here with
 * the DFR naming convention (LIBRARY$Function) required for BOF compilation.
 */

#ifndef BH_DFR_H
#define BH_DFR_H

#include <windows.h>
#include <winternl.h>

/* ============================================================================
 * KERNEL32.DLL
 * ============================================================================ */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$RemoveDirectoryW(LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$MoveFileW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void   WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeThread(HANDLE, LPDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentThreadId(void);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetFileInformationByHandle(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadDirectoryChangesW(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$LockFileEx(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$UnlockFile(HANDLE, DWORD, DWORD, DWORD, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTempPathW(DWORD, LPWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ProcessIdToSessionId(DWORD, DWORD*);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SuspendThread(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ResumeThread(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetThreadContext(HANDLE, LPCONTEXT);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetThreadContext(HANDLE, const CONTEXT*);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetUserNameW(LPWSTR, LPDWORD);
DECLSPEC_IMPORT void   WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SystemTimeToFileTime(const SYSTEMTIME*, LPFILETIME);

/* ============================================================================
 * NTDLL.DLL
 * ============================================================================ */

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT void     NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT ULONG    NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS);

/* These are resolved via GetProcAddress since they may not be in all import libs */
typedef NTSTATUS(NTAPI* fn_NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* fn_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* fn_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
typedef NTSTATUS(NTAPI* fn_NtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

/* ============================================================================
 * WININET.DLL
 * ============================================================================ */

DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenW(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenUrlW(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL      WINAPI WININET$HttpQueryInfoW(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI WININET$InternetReadFile(HINTERNET, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI WININET$InternetCloseHandle(HINTERNET);

/* ============================================================================
 * CABINET.DLL (FDI - Cabinet Decompression)
 * ============================================================================ */

DECLSPEC_IMPORT HFDI CABINET$FDICreate(PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK, int, PERF);
DECLSPEC_IMPORT BOOL CABINET$FDICopy(HFDI, char*, char*, int, PFNFDINOTIFY, PFNFDIDECRYPT, void*);
DECLSPEC_IMPORT BOOL CABINET$FDIDestroy(HFDI);

/* ============================================================================
 * SHLWAPI.DLL
 * ============================================================================ */

DECLSPEC_IMPORT LPWSTR WINAPI SHLWAPI$PathFindFileNameW(LPCWSTR);

/* ============================================================================
 * RPCRT4.DLL
 * ============================================================================ */

DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringBindingComposeW(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFromStringBindingW(RPC_WSTR, RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeW(RPC_WSTR*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$UuidCreate(UUID*);
DECLSPEC_IMPORT RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringW(const UUID*, RPC_WSTR*);

/* NdrClientCall3 - variadic, used for MIDL-generated RPC calls */
typedef union _CLIENT_CALL_RETURN_BOF {
    void *Pointer;
    LONG_PTR Simple;
} CLIENT_CALL_RETURN_BOF;

/* We load NdrClientCall3 via GetProcAddress because it's variadic */
typedef CLIENT_CALL_RETURN_BOF (RPC_VAR_ENTRY *fn_NdrClientCall3)(
    void* /* PMIDL_STUBLESS_PROXY_INFO */ pProxyInfo,
    unsigned long nProcNum,
    void *pReturnValue,
    ...
);

/* ============================================================================
 * ADVAPI32.DLL
 * ============================================================================ */

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

/* Crypto API */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSetKeyParam(HCRYPTKEY, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);

/* Registry */
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);

/* LSA */
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaQueryInformationPolicy(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID*);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaLookupNames(LSA_HANDLE, ULONG, PLSA_UNICODE_STRING, PLSA_REFERENCED_DOMAIN_LIST*, PLSA_TRANSLATED_SID*);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaClose(LSA_HANDLE);

/* Token/Privilege */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSidToSidW(LPCWSTR, PSID*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateWellKnownSid(WELL_KNOWN_SID_TYPE, PSID, PSID, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CheckTokenMembership(HANDLE, PSID, PBOOL);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsWellKnownSid(PSID, WELL_KNOWN_SID_TYPE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LogonUserExW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE, PSID*, PVOID, LPDWORD, PQUOTA_LIMITS);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT DWORD     WINAPI ADVAPI32$GetLengthSid(PSID);

/* ============================================================================
 * CLDAPI.DLL (Cloud Files API)
 * ============================================================================ */

/* Loaded via GetProcAddress since cfapi.h types are complex */
typedef HRESULT (WINAPI *fn_CfRegisterSyncRoot)(LPCWSTR, const void*, const void*, ULONG);
typedef HRESULT (WINAPI *fn_CfConnectSyncRoot)(LPCWSTR, const void*, const void*, ULONG, void*);
typedef HRESULT (WINAPI *fn_CfDisconnectSyncRoot)(LONGLONG);
typedef HRESULT (WINAPI *fn_CfUnregisterSyncRoot)(LPCWSTR);
typedef HRESULT (WINAPI *fn_CfExecute)(const void*, void*);

/* ============================================================================
 * MSVCRT.DLL (C Runtime)
 * ============================================================================ */

DECLSPEC_IMPORT void*    __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void     __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memmove(void*, const void*, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsnicmp(const wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wtoi(const wchar_t*);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$wcstoul(const wchar_t*, wchar_t**, int);
DECLSPEC_IMPORT int      __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);

/* ============================================================================
 * C Runtime Macros (for cleaner code)
 * ============================================================================ */

#define malloc       MSVCRT$malloc
#define free         MSVCRT$free
#define memset       MSVCRT$memset
#define memmove      MSVCRT$memmove
#define memcmp       MSVCRT$memcmp
#define strlen       MSVCRT$strlen
#define strcpy       MSVCRT$strcpy
#define strcat       MSVCRT$strcat
#define strcmp       MSVCRT$strcmp
#define _stricmp     MSVCRT$_stricmp
#define sprintf      MSVCRT$sprintf
#define sscanf       MSVCRT$sscanf
#define wcslen       MSVCRT$wcslen
#define wcscpy       MSVCRT$wcscpy
#define wcscat       MSVCRT$wcscat
#define wcsstr       MSVCRT$wcsstr
#define _wcsicmp     MSVCRT$_wcsicmp
#define _wcsnicmp    MSVCRT$_wcsnicmp
#define _wtoi        MSVCRT$_wtoi
#define wcstoul      MSVCRT$wcstoul
#define swprintf     MSVCRT$swprintf
#define ZeroMemory(p,s) memset((p),0,(s))

/* ============================================================================
 * Windows API Macros (shortcuts for frequently used APIs)
 * ============================================================================ */

#define CreateFileW          KERNEL32$CreateFileW
#define WriteFile            KERNEL32$WriteFile
#define ReadFile             KERNEL32$ReadFile
#define CloseHandle          KERNEL32$CloseHandle
#define DeleteFileW          KERNEL32$DeleteFileW
#define CreateDirectoryW     KERNEL32$CreateDirectoryW
#define RemoveDirectoryW     KERNEL32$RemoveDirectoryW
#define MoveFileW            KERNEL32$MoveFileW
#define ExpandEnvironmentStringsW KERNEL32$ExpandEnvironmentStringsW
#define GetLastError         KERNEL32$GetLastError
#define SetLastError         KERNEL32$SetLastError
#define CreateEventW         KERNEL32$CreateEventW
#define SetEvent             KERNEL32$SetEvent
#define WaitForSingleObject  KERNEL32$WaitForSingleObject
#define WaitForMultipleObjects KERNEL32$WaitForMultipleObjects
#define CreateThread         KERNEL32$CreateThread
#define GetExitCodeThread    KERNEL32$GetExitCodeThread
#define Sleep                KERNEL32$Sleep
#define DeviceIoControl      KERNEL32$DeviceIoControl
#define GetOverlappedResult  KERNEL32$GetOverlappedResult
#define GetFileSizeEx        KERNEL32$GetFileSizeEx
#define GetTempPathW         KERNEL32$GetTempPathW
#define HeapAlloc            KERNEL32$HeapAlloc
#define HeapFree             KERNEL32$HeapFree
#define GetProcessHeap       KERNEL32$GetProcessHeap
#define LoadLibraryW         KERNEL32$LoadLibraryW
#define LoadLibraryA         KERNEL32$LoadLibraryA
#define FreeLibrary          KERNEL32$FreeLibrary
#define GetProcAddress       KERNEL32$GetProcAddress
#define MultiByteToWideChar  KERNEL32$MultiByteToWideChar

/* ============================================================================
 * Shared Structure Definitions
 * ============================================================================ */

/* OBJECT_DIRECTORY_INFORMATION - not in standard headers */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

/* REPARSE_DATA_BUFFER - for junction creation */
typedef struct _BH_REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} BH_REPARSE_DATA_BUFFER, *PBH_REPARSE_DATA_BUFFER;

#define BH_REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(BH_REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

/* Arg parser (matches memdumper pattern) */
typedef struct _ARG_PARSER {
    char* buffer;
    size_t buflen;
} ARG_PARSER;

static void arg_init(ARG_PARSER* p, char* args, int len) {
    p->buffer = args;
    p->buflen = len;
}

static char* arg_get(ARG_PARSER* p, const char* key) {
    char pattern[64];
    sprintf(pattern, "/%s:", key);
    char* found = (char*)MSVCRT$strstr(p->buffer, pattern);
    if (!found) return NULL;
    char* value = found + strlen(pattern);
    char* end = (char*)MSVCRT$strchr(value, ' ');
    if (!end) end = value + strlen(value);
    size_t len = end - value;
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    memmove(result, value, len);
    result[len] = '\0';
    return result;
}

static int arg_has(ARG_PARSER* p, const char* flag) {
    char pattern[64];
    sprintf(pattern, "/%s", flag);
    return MSVCRT$strstr(p->buffer, pattern) != NULL;
}

DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);

#endif /* BH_DFR_H */
