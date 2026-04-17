@echo off
REM Build script for RedSun BOF suite
REM x64 only - exploit targets x64 TieringEngineService

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "%~dp0"

echo ========================================
echo Building RedSun BOF Suite
echo Defender cloud-tag priv-esc (x64 only)
echo ========================================
echo.

if not exist bin mkdir bin

REM BOF flags + Windows 10 target defines
set CFLAGS=/c /GS- /Gs999999999 /GF- /Gy- /O1 /I. /I../ /D WIN64 /D _WIN32_WINNT=0x0A00 /D NTDDI_VERSION=0x0A000000

set BOFS=redsun

for %%b in (%BOFS%) do (
    echo Building %%b...
    cl.exe %CFLAGS% %%b.c /Fobin\%%b.x64.o >nul 2>&1
    if errorlevel 1 (
        echo   [FAILED] %%b.x64.o
    ) else (
        echo   [OK] %%b.x64.o
    )
)

echo.
echo ========================================
echo Build complete!  Output: bin\
echo ========================================
echo.
echo Load redsun.cna in Cobalt Strike and run:
echo   redsun /payload:C:\path\to\payload.exe
echo.
