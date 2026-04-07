@echo off
REM BlueHammer BOF Build Script
REM Requires Visual Studio Developer Command Prompt (cl.exe in PATH)
REM
REM Usage: build.bat
REM Output: bin\bh_leak.x64.o, bin\bh_hashdump.x64.o

set CFLAGS=/c /GS- /Gs999999999 /GF- /Gy- /O1 /I. /I../ /I./include /D WIN64

if not exist bin mkdir bin

echo [*] Building BlueHammer BOFs (x64)...

echo [*] Compiling bh_leak.x64.o...
cl.exe %CFLAGS% bh_leak.c /Fobin\bh_leak.x64.o
if %errorlevel% neq 0 (
    echo [-] bh_leak.x64.o FAILED
    goto :done
)
echo [+] bh_leak.x64.o OK

echo [*] Compiling bh_hashdump.x64.o...
cl.exe %CFLAGS% bh_hashdump.c /Fobin\bh_hashdump.x64.o
if %errorlevel% neq 0 (
    echo [-] bh_hashdump.x64.o FAILED
    goto :done
)
echo [+] bh_hashdump.x64.o OK

echo.
echo [+] Build complete! Output in bin\
echo     bin\bh_leak.x64.o      - File leak exploit BOF
echo     bin\bh_hashdump.x64.o  - SAM hash extraction BOF

:done
