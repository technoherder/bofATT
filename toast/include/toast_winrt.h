/*
 * toast_winrt.h - WinRT COM interface declarations for the toast suite.
 *
 * C# projects these via language projections. From C we work the raw ABI:
 * vtables-of-function-pointers and hand-declared IIDs.
 *
 * Activation chain for a toast:
 *   1. RoGetActivationFactory("Windows.UI.Notifications.ToastNotificationManager",
 *                             IID_IToastNotificationManagerStatics, ...)
 *   2. IToastNotificationManagerStatics::CreateToastNotifierWithId(aumid, ...)
 *   3. RoGetActivationFactory("Windows.Data.Xml.Dom.XmlDocument",
 *                             IID_IXmlDocumentIO, ...)   [activation factory also implements IActivationFactory]
 *   4. IActivationFactory::ActivateInstance -> IXmlDocument
 *      QueryInterface IXmlDocument -> IXmlDocumentIO, LoadXml(HSTRING)
 *   5. RoGetActivationFactory("Windows.UI.Notifications.ToastNotification",
 *                             IID_IToastNotificationFactory, ...)
 *   6. IToastNotificationFactory::CreateToastNotification(xmlDoc, ...)
 *   7. IToastNotifier::Show(toast)
 *
 * IIDs below are the canonical WinRT IIDs — do not change them. They come
 * from the Windows SDK metadata (windows.ui.notifications.idl /
 * windows.data.xml.dom.idl).
 */

#ifndef TOAST_WINRT_H
#define TOAST_WINRT_H

#include <windows.h>
#include "toast_dfr.h"

/* Runtime class names (UTF-16, used with WindowsCreateString) */
#define RCN_TOAST_NOTIFICATION_MANAGER L"Windows.UI.Notifications.ToastNotificationManager"
#define RCN_TOAST_NOTIFICATION         L"Windows.UI.Notifications.ToastNotification"
#define RCN_XML_DOCUMENT               L"Windows.Data.Xml.Dom.XmlDocument"

/* ---- IIDs --------------------------------------------------------------- */

/* IInspectable (base of every WinRT interface) - {AF86E2E0-B12D-4c6a-9C5A-D7AA65101E90} */
static const IID IID_IInspectable =
    { 0xAF86E2E0, 0xB12D, 0x4c6a, { 0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90 } };

/* IActivationFactory - {00000035-0000-0000-C000-000000000046} */
static const IID IID_IActivationFactory =
    { 0x00000035, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* IToastNotificationManagerStatics - {50AC103F-D235-4598-BBEF-98FE4D1A3AD4} */
static const IID IID_IToastNotificationManagerStatics =
    { 0x50AC103F, 0xD235, 0x4598, { 0xBB, 0xEF, 0x98, 0xFE, 0x4D, 0x1A, 0x3A, 0xD4 } };

/* IToastNotifier - {75927B93-03F3-41EC-91D3-6E5BAC1B38E7} */
static const IID IID_IToastNotifier =
    { 0x75927B93, 0x03F3, 0x41EC, { 0x91, 0xD3, 0x6E, 0x5B, 0xAC, 0x1B, 0x38, 0xE7 } };

/* IToastNotificationFactory - {04124B20-82C6-4229-B109-FD9ED4662B53} */
static const IID IID_IToastNotificationFactory =
    { 0x04124B20, 0x82C6, 0x4229, { 0xB1, 0x09, 0xFD, 0x9E, 0xD4, 0x66, 0x2B, 0x53 } };

/* IToastNotification - {997E2675-059E-4E60-8B06-1760917C8B80} */
static const IID IID_IToastNotification =
    { 0x997E2675, 0x059E, 0x4E60, { 0x8B, 0x06, 0x17, 0x60, 0x91, 0x7C, 0x8B, 0x80 } };

/* IXmlDocument - {F7F3A506-1E87-42D6-BCFB-B8C809FA5494} */
static const IID IID_IXmlDocument =
    { 0xF7F3A506, 0x1E87, 0x42D6, { 0xBC, 0xFB, 0xB8, 0xC8, 0x09, 0xFA, 0x54, 0x94 } };

/* IXmlDocumentIO - {6CD0E74E-EE65-4489-9EBF-CA43E87BA637} */
static const IID IID_IXmlDocumentIO =
    { 0x6CD0E74E, 0xEE65, 0x4489, { 0x9E, 0xBF, 0xCA, 0x43, 0xE8, 0x7B, 0xA6, 0x37 } };


/* ---- Vtable skeletons ---------------------------------------------------
 * Each WinRT interface inherits IInspectable, which inherits IUnknown. Lay
 * the vtable out in that order: IUnknown (3) + IInspectable (3) + methods.
 *
 * We only declare the methods we actually call. Unused slots are opaque
 * function pointers so the layout is still correct.
 */

typedef struct IActivationFactory IActivationFactory;
typedef struct IActivationFactoryVtbl {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IActivationFactory*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IActivationFactory*);
    ULONG   (STDMETHODCALLTYPE *Release)(IActivationFactory*);
    /* IInspectable */
    void* GetIids;
    void* GetRuntimeClassName;
    void* GetTrustLevel;
    /* IActivationFactory */
    HRESULT (STDMETHODCALLTYPE *ActivateInstance)(IActivationFactory*, void** instance);
} IActivationFactoryVtbl;
struct IActivationFactory { const IActivationFactoryVtbl* lpVtbl; };

typedef struct IToastNotificationManagerStatics IToastNotificationManagerStatics;
typedef struct IToastNotificationManagerStaticsVtbl {
    /* IUnknown / IInspectable */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IToastNotificationManagerStatics*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IToastNotificationManagerStatics*);
    ULONG   (STDMETHODCALLTYPE *Release)(IToastNotificationManagerStatics*);
    void* GetIids;
    void* GetRuntimeClassName;
    void* GetTrustLevel;
    /* IToastNotificationManagerStatics */
    HRESULT (STDMETHODCALLTYPE *CreateToastNotifier)(IToastNotificationManagerStatics*, void** notifier);
    HRESULT (STDMETHODCALLTYPE *CreateToastNotifierWithId)(IToastNotificationManagerStatics*, HSTRING applicationId, void** notifier);
    HRESULT (STDMETHODCALLTYPE *GetTemplateContent)(IToastNotificationManagerStatics*, INT32 type, void** xmlDoc);
} IToastNotificationManagerStaticsVtbl;
struct IToastNotificationManagerStatics { const IToastNotificationManagerStaticsVtbl* lpVtbl; };

typedef struct IToastNotifier IToastNotifier;
typedef struct IToastNotifierVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IToastNotifier*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IToastNotifier*);
    ULONG   (STDMETHODCALLTYPE *Release)(IToastNotifier*);
    void* GetIids;
    void* GetRuntimeClassName;
    void* GetTrustLevel;
    /* IToastNotifier */
    HRESULT (STDMETHODCALLTYPE *Show)(IToastNotifier*, void* notification);
    HRESULT (STDMETHODCALLTYPE *Hide)(IToastNotifier*, void* notification);
    void* get_Setting;
    void* AddToSchedule;
    void* RemoveFromSchedule;
    void* GetScheduledToastNotifications;
} IToastNotifierVtbl;
struct IToastNotifier { const IToastNotifierVtbl* lpVtbl; };

typedef struct IToastNotificationFactory IToastNotificationFactory;
typedef struct IToastNotificationFactoryVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IToastNotificationFactory*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IToastNotificationFactory*);
    ULONG   (STDMETHODCALLTYPE *Release)(IToastNotificationFactory*);
    void* GetIids;
    void* GetRuntimeClassName;
    void* GetTrustLevel;
    /* IToastNotificationFactory */
    HRESULT (STDMETHODCALLTYPE *CreateToastNotification)(IToastNotificationFactory*, void* xmlDoc, void** toast);
} IToastNotificationFactoryVtbl;
struct IToastNotificationFactory { const IToastNotificationFactoryVtbl* lpVtbl; };

typedef struct IXmlDocumentIO IXmlDocumentIO;
typedef struct IXmlDocumentIOVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IXmlDocumentIO*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IXmlDocumentIO*);
    ULONG   (STDMETHODCALLTYPE *Release)(IXmlDocumentIO*);
    void* GetIids;
    void* GetRuntimeClassName;
    void* GetTrustLevel;
    /* IXmlDocumentIO */
    HRESULT (STDMETHODCALLTYPE *LoadXml)(IXmlDocumentIO*, HSTRING xml);
    void* LoadXmlWithSettings;
    void* SaveToFileAsync;
} IXmlDocumentIOVtbl;
struct IXmlDocumentIO { const IXmlDocumentIOVtbl* lpVtbl; };

#endif /* TOAST_WINRT_H */
