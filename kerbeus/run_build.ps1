# Build script for Kerbeus BOFs
# Explicitly initialize for both x64 and x86 builds

Set-Location "c:\Users\techn\Documents\bof_template\kerbeus"
if (-not (Test-Path bin)) { New-Item -ItemType Directory -Path bin | Out-Null }

# Original BOFs
$bofs_original = @('krb_asktgt', 'krb_asktgs', 'krb_kerberoasting', 'krb_asreproasting',
                   'krb_klist', 'krb_ptt', 'krb_purge', 'krb_describe', 'krb_tgtdeleg',
                   'krb_hash', 'krb_dump', 'krb_triage', 'krb_s4u', 'krb_renew', 'krb_changepw')

# New BOFs
$bofs_new = @('krb_currentluid', 'krb_logonsession', 'krb_createnetonly', 'krb_monitor',
              'krb_harvest', 'krb_brute', 'krb_golden', 'krb_silver', 'krb_diamond',
              'krb_preauthscan', 'krb_showall', 'krb_crossdomain', 'krb_resetpw',
              'krb_anonldap', 'krb_kirbi', 'krb_pac', 'krb_unconstrained', 'krb_rbcd',
              'krb_bronzebit', 'krb_shadowcred', 'krb_stats', 'krb_spnroast', 'krb_spray',
              'krb_spnenum', 'krb_delegenum', 'krb_ccache', 'krb_asktgtrc4', 'krb_overpass',
              'krb_tgssub', 'krb_asrep2kirbi', 'krb_nopac', 'krb_u2u', 'krb_kdcproxy', 'krb_opsec',
              'krb_asreproast_auto', 'krb_unconstrained_enum', 'krb_printerbug', 'krb_petitpotam', 'krb_dcsync')

$allBofs = $bofs_original + $bofs_new

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building Kerbeus BOF Suite" -ForegroundColor Cyan
Write-Host "Total: $($allBofs.Count) BOFs" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$success64 = 0
$success86 = 0
$failed = @()

# BOF compiler flags
$CFLAGS = "/c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../"

# Build 64-bit versions
Write-Host "[Phase 1] Building 64-bit BOFs..." -ForegroundColor Yellow
Write-Host ""

# Initialize x64 environment
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64;$env:PATH"
$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\shared"

foreach ($bof in $allBofs) {
    $result = & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\cl.exe" /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 "$bof.c" /Fobin/"$bof.x64.o" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $bof.x64.o" -ForegroundColor Green
        $success64++
    } else {
        Write-Host "  [FAILED] $bof.x64.o" -ForegroundColor Red
        $failed += "$bof.x64"
    }
}

Write-Host ""
Write-Host "[Phase 2] Building 32-bit BOFs..." -ForegroundColor Yellow
Write-Host ""

# Use x86 compiler for 32-bit
foreach ($bof in $allBofs) {
    $result = & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x86\cl.exe" /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN32 "$bof.c" /Fobin/"$bof.x86.o" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $bof.x86.o" -ForegroundColor Green
        $success86++
    } else {
        Write-Host "  [FAILED] $bof.x86.o" -ForegroundColor Red
        $failed += "$bof.x86"
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build complete!" -ForegroundColor Cyan
Write-Host "64-bit: $success64/$($allBofs.Count) succeeded" -ForegroundColor $(if ($success64 -eq $allBofs.Count) { "Green" } else { "Yellow" })
Write-Host "32-bit: $success86/$($allBofs.Count) succeeded" -ForegroundColor $(if ($success86 -eq $allBofs.Count) { "Green" } else { "Yellow" })
if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed builds:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
Write-Host "========================================" -ForegroundColor Cyan
