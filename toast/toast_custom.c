/*
 * toast_custom - Display a toast from an XML template file.
 *
 * Usage: toast_custom /aumid:AUMID /file:C:\path\template.xml
 *
 * Reads the XML via CreateFileA/ReadFile (no shell redirection), then
 * drives the same WinRT activation chain as toast_send.
 *
 * STATUS: SKELETON. Shares the TODO(winrt) marker with toast_send —
 * finish that one first, then copy the working chain here.
 */

#include <windows.h>
#include "beacon.h"
#include "include/toast_dfr.h"
#include "include/toast_winrt.h"

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
        char* s = buf + i + nl;
        char* e = s;
        while (*e && *e != '\r' && *e != '\n') e++;
        int vl = (int)(e - s);
        char* v = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, vl + 1);
        if (!v) return NULL;
        for (int k = 0; k < vl; k++) v[k] = s[k];
        return v;
    }
    return NULL;
}

static void hfree(void* p) { if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p); }

/* Slurp a file into a freshly allocated UTF-8 buffer (null-terminated).
 * Returns NULL on failure. Caller frees. */
static char* read_file_utf8(const char* path, DWORD* out_size) {
    HANDLE h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = KERNEL32$GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > (16 * 1024 * 1024)) { KERNEL32$CloseHandle(h); return NULL; }
    char* buf = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sz + 1);
    if (!buf) { KERNEL32$CloseHandle(h); return NULL; }
    DWORD got = 0;
    if (!KERNEL32$ReadFile(h, buf, sz, &got, NULL) || got != sz) {
        hfree(buf); KERNEL32$CloseHandle(h); return NULL;
    }
    KERNEL32$CloseHandle(h);
    if (out_size) *out_size = sz;
    return buf;
}

void go(char* args, int alen) {
    char* aumid = find_arg(args, alen, "aumid");
    char* file  = find_arg(args, alen, "file");
    if (!aumid || !file) {
        BeaconPrintf(CALLBACK_ERROR, "usage: toast_custom /aumid:AUMID /file:PATH");
        hfree(aumid); hfree(file);
        return;
    }

    DWORD sz = 0;
    char* xml = read_file_utf8(file, &sz);
    if (!xml) {
        BeaconPrintf(CALLBACK_ERROR, "could not read %s", file);
        hfree(aumid); hfree(file);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[!] toast_custom: read %lu bytes from %s (WinRT chain not yet wired — see toast_send.c TODO(winrt))",
        sz, file);

    hfree(xml);
    hfree(aumid);
    hfree(file);
}
