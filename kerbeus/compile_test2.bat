@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "c:\Users\techn\Documents\bof_template\kerbeus"
echo Compiling krb_asrep2kirbi...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_asrep2kirbi.c /Fobin/krb_asrep2kirbi.x64.o
if errorlevel 1 echo FAILED: krb_asrep2kirbi
echo Compiling krb_stats...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_stats.c /Fobin/krb_stats.x64.o
if errorlevel 1 echo FAILED: krb_stats
echo Compiling krb_delegenum...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_delegenum.c /Fobin/krb_delegenum.x64.o
if errorlevel 1 echo FAILED: krb_delegenum
echo Compiling krb_unconstrained...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_unconstrained.c /Fobin/krb_unconstrained.x64.o
if errorlevel 1 echo FAILED: krb_unconstrained
echo Compiling krb_u2u...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_u2u.c /Fobin/krb_u2u.x64.o
if errorlevel 1 echo FAILED: krb_u2u
echo Compiling krb_dump...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_dump.c /Fobin/krb_dump.x64.o
if errorlevel 1 echo FAILED: krb_dump
echo Done!
