@echo off
REM Debug build script - shows compiler errors

echo Compiling krb_monitor.c with verbose output...
echo.

cl.exe /c /GS- /I. /I../ /D WIN64 krb_monitor.c /Fobin\krb_monitor.x64.o

echo.
echo ========================================
echo Done - check errors above
echo ========================================
