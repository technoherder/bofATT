@echo off
REM Build script for memdumper BOF
REM
REM Prerequisites:
REM   - Visual Studio Developer Command Prompt (for cl.exe)
REM   OR
REM   - MinGW-w64 (for x86_64-w64-mingw32-gcc)
REM
REM Usage:
REM   build.bat          - Build with MSVC (auto-detect platform)
REM   build.bat mingw    - Build with MinGW

if "%1"=="mingw" goto mingw

REM ============================================================================
REM MSVC Build
REM ============================================================================

set PLAT="x86"
IF "%Platform%"=="x64" set PLAT="x64"
set VERSION="WIN32"
IF "%Platform%"=="x64" set VERSION="WIN64"

echo [*] Building memdumper BOF with MSVC (%PLAT%)

cl.exe /D %VERSION% /c /GS- memdumper.c /Fomemdumper.%PLAT%.o

if %ERRORLEVEL% EQU 0 (
    echo [+] Successfully built memdumper.%PLAT%.o
) else (
    echo [-] Build failed
)

goto end

REM ============================================================================
REM MinGW Build
REM ============================================================================

:mingw
echo [*] Building memdumper BOF with MinGW

REM x64 build
x86_64-w64-mingw32-gcc -c memdumper.c -o memdumper.x64.o -DWIN64 -masm=intel

if %ERRORLEVEL% EQU 0 (
    echo [+] Successfully built memdumper.x64.o
) else (
    echo [-] x64 build failed
)

REM x86 build
i686-w64-mingw32-gcc -c memdumper.c -o memdumper.x86.o -DWIN32 -masm=intel

if %ERRORLEVEL% EQU 0 (
    echo [+] Successfully built memdumper.x86.o
) else (
    echo [-] x86 build failed
)

:end
