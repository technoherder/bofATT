@echo off
REM Build script for Preauthscan BOF using Visual Studio compiler
REM Requires Visual Studio Developer Command Prompt

echo Building Preauthscan BOF...

REM Build 64-bit version
cl.exe /c /GS- /D WIN64 preauthscan.c /Fopreauthscan.x64.o
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build x64 version
    exit /b 1
)
echo Built: preauthscan.x64.o

REM Build 32-bit version
cl.exe /c /GS- /D WIN32 preauthscan.c /Fopreauthscan.x86.o
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build x86 version
    exit /b 1
)
echo Built: preauthscan.x86.o

echo Build complete!
