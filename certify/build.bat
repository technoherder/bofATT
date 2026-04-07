@echo off
REM Build script for Certify BOF suite using Visual Studio compiler
REM Auto-initializes VS environment if needed

REM Initialize Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Change to script directory
cd /d "%~dp0"

echo ========================================
echo Building Certify BOF Suite
echo AD CS Enumeration and Abuse Tools
echo ========================================
echo.

if not exist bin mkdir bin

REM BOF-specific compiler flags:
REM   /c           - Compile only (no linking)
REM   /GS-         - Disable buffer security checks
REM   /Gs999999999 - Disable stack probes (prevents __chkstk)
REM   /GF-         - Disable string pooling (prevents ??_C@ symbols)
REM   /Gy-         - Disable function-level linking
REM   /O1          - Optimize for size
set CFLAGS=/c /GS- /Gs999999999 /GF- /Gy- /O1 /I. /I../

REM Certify BOFs - AD Certificate Services tools
set BOFS=cert_cas cert_find cert_request cert_download cert_forge cert_manageca cert_pkiobjects cert_request_agent

echo [Building] Certify BOFs...
echo.

for %%b in (%BOFS%) do (
    echo Building %%b...

    REM Build 64-bit
    cl.exe %CFLAGS% /D WIN64 %%b.c /Fobin\%%b.x64.o >nul 2>&1
    if errorlevel 1 (
        echo   [FAILED] %%b.x64.o
    ) else (
        echo   [OK] %%b.x64.o
    )

    REM Build 32-bit
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
echo Total BOFs: 8
echo ========================================
echo.
echo CA Enumeration:      cert_cas, cert_pkiobjects
echo Template Finding:    cert_find
echo Certificate Request: cert_request, cert_request_agent, cert_download
echo Exploitation:        cert_forge, cert_manageca
echo.
echo ESC Vulnerability Coverage:
echo   ESC1: cert_find, cert_request (enrollee supplies subject)
echo   ESC2: cert_find (Any Purpose/no EKU)
echo   ESC3: cert_find, cert_request_agent (enrollment agent)
echo   ESC4: cert_find (template ACL abuse)
echo   ESC5: cert_find (PKI object ACL abuse)
echo   ESC6: cert_manageca (EDITF_ATTRIBUTESUBJECTALTNAME2)
echo   ESC7: cert_manageca (ManageCA rights)
echo   ESC8: cert_cas (HTTP enrollment endpoints)
echo   ESC9-15: cert_find (various mapping issues)
echo.
echo Golden Cert: cert_forge (with stolen CA key)
echo.
