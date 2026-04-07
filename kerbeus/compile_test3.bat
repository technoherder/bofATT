@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "c:\Users\techn\Documents\bof_template\kerbeus"
echo Compiling krb_asrep2kirbi... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_asrep2kirbi.c /Fobin/krb_asrep2kirbi.x64.o >> compile_log.txt 2>&1
echo Compiling krb_stats... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_stats.c /Fobin/krb_stats.x64.o >> compile_log.txt 2>&1
echo Compiling krb_delegenum... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_delegenum.c /Fobin/krb_delegenum.x64.o >> compile_log.txt 2>&1
echo Compiling krb_unconstrained... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_unconstrained.c /Fobin/krb_unconstrained.x64.o >> compile_log.txt 2>&1
echo Compiling krb_u2u... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_u2u.c /Fobin/krb_u2u.x64.o >> compile_log.txt 2>&1
echo Compiling krb_dump... >> compile_log.txt 2>&1
cl.exe /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 krb_dump.c /Fobin/krb_dump.x64.o >> compile_log.txt 2>&1
echo Done! >> compile_log.txt 2>&1
