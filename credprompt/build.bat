@echo off
REM Build credprompt BOF for x64 and x86
REM Requires Visual Studio 2022 Build Tools

if not exist bin mkdir bin

REM --- x64 Build ---
echo [*] Building credprompt (x64)...
cl.exe /c /GS- /Gs999999999 /GF- /Gy- /O1 /Fo"bin\credprompt.x64.o" credprompt.c
if %errorlevel% neq 0 (
    echo [!] x64 build failed.
    exit /b 1
)
echo [+] bin\credprompt.x64.o

REM --- x86 Build ---
echo [*] Building credprompt (x86)...
cl.exe /c /GS- /Gs999999999 /GF- /Gy- /O1 /Fo"bin\credprompt.x86.o" credprompt.c
if %errorlevel% neq 0 (
    echo [!] x86 build failed.
    exit /b 1
)
echo [+] bin\credprompt.x86.o

echo [+] Build complete.
