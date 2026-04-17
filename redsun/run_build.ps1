# Build script for RedSun BOF
# x64 only - exploit targets x64 TieringEngineService.exe

Set-Location "c:\Users\techn\Documents\bof_template\redsun"
if (-not (Test-Path bin)) { New-Item -ItemType Directory -Path bin | Out-Null }

$bofs = @('redsun')

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building RedSun BOF Suite" -ForegroundColor Cyan
Write-Host "Defender cloud-tag privilege escalation" -ForegroundColor Cyan
Write-Host "x64 only" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$success64 = 0

# Include paths
$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\shared"

Write-Host "[Phase 1] Building 64-bit BOFs..." -ForegroundColor Yellow
foreach ($bof in $bofs) {
    $output = & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\cl.exe" `
        /c /GS- /Gs999999999 /Od /Ob1 /Oi- `
        /I. /I../ `
        /D WIN64 /D _WIN32_WINNT=0x0A00 /D NTDDI_VERSION=0x0A000000 `
        "$bof.c" /Fobin/"$bof.x64.o" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $bof.x64.o" -ForegroundColor Green
        $success64++
    } else {
        Write-Host "  [FAILED] $bof.x64.o" -ForegroundColor Red
        $output | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build complete!" -ForegroundColor Cyan
Write-Host "64-bit: $success64/$($bofs.Count) succeeded"
Write-Host "========================================" -ForegroundColor Cyan
