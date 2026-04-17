/*
 * toast_dfr.h - Dynamic Function Resolution declarations for the toast suite.
 *
 * advapi32 Reg* exports are needed for toast_getaumid (registry walk of
 * Software\Classes\AppUserModelId under HKCU/HKLM).
 *
 * combase Ro* / Windows*String exports are needed for toast_send /
 * toast_custom to reach the Windows.UI.Notifications WinRT factories.
 *
 * kernel32 heap/string helpers are shared across all three BOFs.
 */

#ifndef TOAST_DFR_H
#define TOAST_DFR_H

#include <windows.h>

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

/* ---- kernel32 ---------------------------------------------------------- */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

/* ---- advapi32 registry -------------------------------------------------- */
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryInfoKeyW(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);

/* ---- combase WinRT ------------------------------------------------------
 * HSTRING is an opaque handle to a reference-counted immutable string.
 * RoGetActivationFactory returns the IActivationFactory (or a requested
 * "statics" interface) for a named runtime class.
 */
typedef HANDLE HSTRING;
typedef struct HSTRING_HEADER__ { void* Reserved[25/sizeof(void*) + 1]; } HSTRING_HEADER;

DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoInitialize(DWORD initType);          /* 0 = single-threaded, 1 = multi-threaded */
DECLSPEC_IMPORT void    WINAPI COMBASE$RoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoGetActivationFactory(HSTRING activatableClassId, REFIID iid, void** factory);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsCreateString(LPCWSTR sourceString, UINT32 length, HSTRING* string);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsCreateStringReference(LPCWSTR sourceString, UINT32 length, HSTRING_HEADER* hstringHeader, HSTRING* string);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsDeleteString(HSTRING string);
DECLSPEC_IMPORT LPCWSTR WINAPI COMBASE$WindowsGetStringRawBuffer(HSTRING string, UINT32* length);

#endif /* TOAST_DFR_H */
