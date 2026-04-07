@echo off
REM Build script for Kerbeus BOF suite using Visual Studio compiler
REM Auto-initializes VS environment if needed

REM Initialize Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Change to script directory
cd /d "%~dp0"

echo ========================================
echo Building Kerbeus BOF Suite
echo Full Rubeus Feature Set
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

REM Original BOFs from Kerbeus-BOF
set BOFS_ORIGINAL=krb_asktgt krb_asktgs krb_kerberoasting krb_asreproasting krb_klist krb_ptt krb_purge krb_describe krb_tgtdeleg krb_hash krb_dump krb_triage krb_s4u krb_renew krb_changepw

REM New BOFs matching Rubeus features
set BOFS_NEW=krb_currentluid krb_logonsession krb_createnetonly krb_monitor krb_harvest krb_brute krb_golden krb_silver krb_diamond krb_preauthscan krb_showall krb_crossdomain krb_resetpw krb_anonldap krb_kirbi krb_pac krb_unconstrained krb_rbcd krb_bronzebit krb_shadowcred krb_stats krb_spnroast krb_spray krb_spnenum krb_delegenum krb_ccache krb_asktgtrc4 krb_overpass krb_tgssub krb_asrep2kirbi krb_nopac krb_u2u krb_kdcproxy krb_opsec krb_unconstrained_enum 

echo [Phase 1] Building original Kerbeus BOFs...
echo.

for %%b in (%BOFS_ORIGINAL%) do (
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
echo [Phase 2] Building new Rubeus-equivalent BOFs...
echo.

for %%b in (%BOFS_NEW%) do (
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
echo Total BOFs: 49
echo ========================================
echo.
echo Ticket Requests:    krb_asktgt, krb_asktgs, krb_renew, krb_asktgtrc4, krb_overpass
echo                     krb_nopac, krb_opsec
echo Roasting:           krb_kerberoasting, krb_asreproasting, krb_preauthscan, krb_spnroast
echo Ticket Management:  krb_klist, krb_ptt, krb_purge, krb_describe, krb_showall, krb_kirbi
echo                     krb_ccache, krb_tgssub, krb_asrep2kirbi
echo Ticket Extraction:  krb_dump, krb_triage, krb_tgtdeleg, krb_harvest, krb_monitor
echo                     krb_unconstrained
echo Delegation:         krb_s4u, krb_crossdomain, krb_rbcd, krb_delegenum, krb_u2u
echo Ticket Forging:     krb_golden, krb_silver, krb_diamond, krb_bronzebit
echo Analysis:           krb_pac, krb_stats
echo Utilities:          krb_hash, krb_changepw, krb_currentluid, krb_logonsession
echo                     krb_createnetonly, krb_brute, krb_resetpw, krb_spray
echo Enumeration:        krb_anonldap, krb_shadowcred, krb_spnenum
echo Advanced:           krb_kdcproxy
echo.
