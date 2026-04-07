@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "c:\Users\techn\Documents\bof_template\kerbeus"
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_overpass.c /Fobin/krb_overpass.x64.o
