# Build script for Toast BOFs
# Explicit compiler paths so this works from any shell (no vcvars needed).

Set-Location "c:\Users\techn\Documents\bof_template\toast"
if (-not (Test-Path bin)) { New-Item -ItemType Directory -Path bin | Out-Null }

$bofs = @('toast_getaumid', 'toast_send', 'toast_custom')

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building Toast BOF Suite" -ForegroundColor Cyan
Write-Host "Total: $($bofs.Count) BOFs" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$success64 = 0
$success86 = 0

$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\shared"

Write-Host "[Phase 1] Building 64-bit BOFs..." -ForegroundColor Yellow
foreach ($bof in $bofs) {
    $out = & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\cl.exe" /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN64 "$bof.c" /Fobin/"$bof.x64.o" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $bof.x64.o" -ForegroundColor Green
        $success64++
    } else {
        Write-Host "  [FAILED] $bof.x64.o" -ForegroundColor Red
        $out | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
    }
}

Write-Host ""
Write-Host "[Phase 2] Building 32-bit BOFs..." -ForegroundColor Yellow
foreach ($bof in $bofs) {
    $out = & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x86\cl.exe" /c /GS- /Gs999999999 /Od /Ob1 /Oi- /I. /I../ /D WIN32 "$bof.c" /Fobin/"$bof.x86.o" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $bof.x86.o" -ForegroundColor Green
        $success86++
    } else {
        Write-Host "  [FAILED] $bof.x86.o" -ForegroundColor Red
        $out | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build complete!" -ForegroundColor Cyan
Write-Host "64-bit: $success64/$($bofs.Count) succeeded"
Write-Host "32-bit: $success86/$($bofs.Count) succeeded"
Write-Host "========================================" -ForegroundColor Cyan
