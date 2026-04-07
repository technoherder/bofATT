@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo === Compiling Kerbeus BOFs ===
cd /d "c:\Users\techn\Documents\bof_template\kerbeus"
if not exist bin mkdir bin

echo Compiling krb_delegenum...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_delegenum.c /Fobin/krb_delegenum.x64.o

echo Compiling krb_stats...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_stats.c /Fobin/krb_stats.x64.o

echo Compiling krb_asrep2kirbi...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_asrep2kirbi.c /Fobin/krb_asrep2kirbi.x64.o

echo Compiling krb_dump...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_dump.c /Fobin/krb_dump.x64.o

echo Compiling krb_u2u...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_u2u.c /Fobin/krb_u2u.x64.o

echo Compiling krb_unconstrained...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_unconstrained.c /Fobin/krb_unconstrained.x64.o

echo Compiling krb_unconstrained_enum...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_unconstrained_enum.c /Fobin/krb_unconstrained_enum.x64.o

echo Compiling krb_printerbug...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_printerbug.c /Fobin/krb_printerbug.x64.o

echo Compiling krb_petitpotam...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_petitpotam.c /Fobin/krb_petitpotam.x64.o

echo Compiling krb_dcsync...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_dcsync.c /Fobin/krb_dcsync.x64.o

echo === Compiling Certify BOFs ===
cd /d "c:\Users\techn\Documents\bof_template\certify"
if not exist bin mkdir bin

echo Compiling cert_cas...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 cert_cas.c /Fobin/cert_cas.x64.o

echo Compiling cert_find...
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 cert_find.c /Fobin/cert_find.x64.o

echo.
echo === Done! ===
