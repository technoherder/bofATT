/*
 * toast_send - Display a Windows toast notification via WinRT.
 *
 * Usage: toast_send /aumid:AUMID /title:TITLE /body:BODY
 *
 * Builds a minimal ToastGeneric XML in-memory:
 *
 *   <toast><visual><binding template="ToastGeneric">
 *     <text>TITLE</text>
 *     <text>BODY</text>
 *   </binding></visual></toast>
 *
 * then drives the WinRT activation chain documented in toast_winrt.h.
 *
 * STATUS: SKELETON. The registry/AUMID validation, XML assembly, HSTRING
 * lifetimes, and COM plumbing are scaffolded but the factory calls marked
 * with TODO(winrt) below need to be wired up and smoke-tested on a live
 * desktop session. Toasts only display when the BOF runs in an interactive
 * user session — SYSTEM/service contexts will get the toast objects but
 * the shell won't render them.
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

/* Escape &, <, > for safe insertion into XML text nodes. Returns a new heap buffer. */
static char* xml_escape(const char* s) {
    if (!s) return NULL;
    size_t need = 1;
    for (const char* p = s; *p; p++) {
        switch (*p) {
            case '&': need += 5; break;   /* &amp; */
            case '<': need += 4; break;   /* &lt;  */
            case '>': need += 4; break;   /* &gt;  */
            default:  need += 1; break;
        }
    }
    char* out = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    if (!out) return NULL;
    char* w = out;
    for (const char* p = s; *p; p++) {
        switch (*p) {
            case '&': *w++='&';*w++='a';*w++='m';*w++='p';*w++=';'; break;
            case '<': *w++='&';*w++='l';*w++='t';*w++=';'; break;
            case '>': *w++='&';*w++='g';*w++='t';*w++=';'; break;
            default:  *w++ = *p; break;
        }
    }
    return out;
}

static WCHAR* utf8_to_wide(const char* s) {
    if (!s) return NULL;
    int need = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (need <= 0) return NULL;
    WCHAR* w = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, need * sizeof(WCHAR));
    if (!w) return NULL;
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, s, -1, w, need);
    return w;
}

static void hfree(void* p) { if (p) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, p); }

/* Thin wrapper: new HSTRING from a UTF-16 literal. Caller must WindowsDeleteString. */
static HRESULT hstr_new(const WCHAR* w, HSTRING* out) {
    UINT32 len = 0;
    if (w) while (w[len]) len++;
    return COMBASE$WindowsCreateString(w, len, out);
}

void go(char* args, int alen) {
    char* aumid = find_arg(args, alen, "aumid");
    char* title = find_arg(args, alen, "title");
    char* body  = find_arg(args, alen, "body");

    if (!aumid || !title || !body) {
        BeaconPrintf(CALLBACK_ERROR, "usage: toast_send /aumid:AUMID /title:TITLE /body:BODY");
        goto cleanup_args;
    }

    /* Build the XML body (UTF-8), then widen once for HSTRING. */
    char* t_esc = xml_escape(title);
    char* b_esc = xml_escape(body);
    if (!t_esc || !b_esc) {
        BeaconPrintf(CALLBACK_ERROR, "xml_escape oom");
        goto cleanup_xml;
    }

    size_t xlen = 128 + (t_esc ? 0 : 0);
    /* Reserve generously; toast XML is tiny. */
    char* xml = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 + 4 * (int)(xlen));
    if (!xml) goto cleanup_xml;
    /* sprintf is tolerated by the certify/kerbeus build profile; follow that
     * convention instead of pulling in user32!wsprintfA via DFR. */
    sprintf(xml,
        "<toast><visual><binding template=\"ToastGeneric\">"
        "<text>%s</text><text>%s</text>"
        "</binding></visual></toast>",
        t_esc, b_esc);

    WCHAR* xml_w   = utf8_to_wide(xml);
    WCHAR* aumid_w = utf8_to_wide(aumid);
    if (!xml_w || !aumid_w) {
        BeaconPrintf(CALLBACK_ERROR, "utf-16 conversion failed");
        goto cleanup_wide;
    }

    /* ---- WinRT activation ------------------------------------------- */
    HRESULT hr = COMBASE$RoInitialize(1 /* RO_INIT_MULTITHREADED */);
    /* RPC_E_CHANGED_MODE (0x80010106) is fine — a caller already initialized. */
    BOOL inited = SUCCEEDED(hr);

    HSTRING h_aumid = NULL, h_xml = NULL;
    HSTRING h_rc_mgr = NULL, h_rc_xml = NULL, h_rc_toast = NULL;

    IToastNotificationManagerStatics* mgrStatics = NULL;
    IActivationFactory*               xmlFactory = NULL;
    IToastNotificationFactory*        toastFactory = NULL;
    IXmlDocumentIO*                   xmlDoc = NULL;
    void*                             xmlDocInst = NULL;  /* IInspectable* from ActivateInstance */
    void*                             toast = NULL;
    IToastNotifier*                   notifier = NULL;

    if (FAILED(hstr_new(aumid_w, &h_aumid))) goto winrt_done;
    if (FAILED(hstr_new(xml_w,   &h_xml  ))) goto winrt_done;
    if (FAILED(hstr_new(RCN_TOAST_NOTIFICATION_MANAGER, &h_rc_mgr))) goto winrt_done;
    if (FAILED(hstr_new(RCN_XML_DOCUMENT,               &h_rc_xml))) goto winrt_done;
    if (FAILED(hstr_new(RCN_TOAST_NOTIFICATION,         &h_rc_toast))) goto winrt_done;

    /* TODO(winrt): needs live-session validation. The calls below are the
     * canonical WinRT sequence but IIDs/vtable offsets haven't been smoke
     * tested from a BOF context yet. Start here:
     *
     *   1. RoGetActivationFactory(h_rc_mgr, &IID_IToastNotificationManagerStatics, &mgrStatics)
     *   2. mgrStatics->CreateToastNotifierWithId(h_aumid, &notifier)
     *   3. RoGetActivationFactory(h_rc_xml, &IID_IActivationFactory, &xmlFactory)
     *   4. xmlFactory->ActivateInstance(&xmlDocInst)
     *      ((IUnknown*)xmlDocInst)->QueryInterface(&IID_IXmlDocumentIO, &xmlDoc)
     *      xmlDoc->LoadXml(h_xml)
     *   5. RoGetActivationFactory(h_rc_toast, &IID_IToastNotificationFactory, &toastFactory)
     *      toastFactory->CreateToastNotification(xmlDocInst, &toast)   (xmlDocInst cast as IXmlDocument*)
     *   6. notifier->Show(toast)
     *
     * Release every out-param in reverse order on both success and failure.
     */
    BeaconPrintf(CALLBACK_OUTPUT, "[!] toast_send: WinRT plumbing scaffolded — Show() call not yet wired");
    BeaconPrintf(CALLBACK_OUTPUT, "    aumid=%s title=%s body=%s", aumid, title, body);

winrt_done:
    if (notifier)     notifier->lpVtbl->Release(notifier);
    if (toastFactory) toastFactory->lpVtbl->Release(toastFactory);
    if (xmlDoc)       xmlDoc->lpVtbl->Release(xmlDoc);
    if (xmlFactory)   xmlFactory->lpVtbl->Release(xmlFactory);
    if (mgrStatics)   mgrStatics->lpVtbl->Release(mgrStatics);
    if (h_rc_toast) COMBASE$WindowsDeleteString(h_rc_toast);
    if (h_rc_xml)   COMBASE$WindowsDeleteString(h_rc_xml);
    if (h_rc_mgr)   COMBASE$WindowsDeleteString(h_rc_mgr);
    if (h_xml)      COMBASE$WindowsDeleteString(h_xml);
    if (h_aumid)    COMBASE$WindowsDeleteString(h_aumid);
    if (inited) COMBASE$RoUninitialize();

cleanup_wide:
    hfree(xml_w); hfree(aumid_w); hfree(xml);
cleanup_xml:
    hfree(t_esc); hfree(b_esc);
cleanup_args:
    hfree(aumid); hfree(title); hfree(body);
}
