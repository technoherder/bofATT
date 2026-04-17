@echo off
REM Build script for Toast BOF suite (Windows toast-notification abuse)
REM Adapted from certify/build.bat — same MSVC flags, same output layout.

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cd /d "%~dp0"

echo ========================================
echo Building Toast BOF Suite
echo Windows Toast Notification Abuse
echo ========================================
echo.

if not exist bin mkdir bin

REM BOF-specific compiler flags (see certify/build.bat for rationale)
set CFLAGS=/c /GS- /Gs999999999 /GF- /Gy- /O1 /I. /I../

set BOFS=toast_getaumid toast_send toast_custom

echo [Building] Toast BOFs...
echo.

for %%b in (%BOFS%) do (
    echo Building %%b...

    cl.exe %CFLAGS% /D WIN64 %%b.c /Fobin\%%b.x64.o >nul 2>&1
    if errorlevel 1 (
        echo   [FAILED] %%b.x64.o
    ) else (
        echo   [OK] %%b.x64.o
    )

    cl.exe %CFLAGS% /D WIN32 %%b.c /Fobin\%%b.x86.o >nul 2>&1
    if errorlevel 1 (
        echo   [FAILED] %%b.x86.o
    ) else (
        echo   [OK] %%b.x86.o
    )
)

echo.
echo ========================================
echo Build complete!
echo Output files in: bin\
echo.
echo Total BOFs: 3
echo ========================================
echo.
echo AUMID enumeration:   toast_getaumid
echo Send lure toast:     toast_send    (WinRT chain — skeleton)
echo Custom XML template: toast_custom  (WinRT chain — skeleton)
echo.
