@echo off
REM Debug build using MinGW if available

echo Checking for MinGW...

where x86_64-w64-mingw32-gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo MinGW not found in PATH.
    echo.
    echo Please either:
    echo   1. Run from "Developer Command Prompt for VS" for MSVC build
    echo   2. Install MinGW-w64 and add to PATH
    echo.
    echo To find Developer Command Prompt:
    echo   - Open Start Menu
    echo   - Search for "Developer Command Prompt" or "x64 Native Tools"
    exit /b 1
)

echo Found MinGW! Building with verbose output...
echo.

x86_64-w64-mingw32-gcc -c -I. -I../ krb_currentluid.c -o bin/krb_currentluid.x64.o

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] krb_currentluid.x64.o built!
) else (
    echo.
    echo [FAILED] See errors above
)
