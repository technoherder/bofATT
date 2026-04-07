@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "c:\Users\techn\Documents\bof_template\certify"
if not exist bin mkdir bin
echo Compiling cert_cas...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 cert_cas.c /Fobin/cert_cas.x64.o
echo Compiling cert_find...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 cert_find.c /Fobin/cert_find.x64.o
echo Done!
