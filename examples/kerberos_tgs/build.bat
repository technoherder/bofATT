@echo off
REM Build script for Kerberos TGS BOF using Visual Studio compiler
REM Requires Visual Studio Developer Command Prompt

echo Building Kerberos TGS BOF...

REM Build 64-bit version
cl.exe /c /GS- /D WIN64 kerberos_tgs.c /Fokerberos_tgs.x64.o
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build x64 version
    exit /b 1
)
echo Built: kerberos_tgs.x64.o

REM Build 32-bit version
cl.exe /c /GS- /D WIN32 kerberos_tgs.c /Fokerberos_tgs.x86.o
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build x86 version
    exit /b 1
)
echo Built: kerberos_tgs.x86.o

echo Build complete!
