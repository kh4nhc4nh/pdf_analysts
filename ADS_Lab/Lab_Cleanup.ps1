# ==============================================================================
# Script: Lab_Cleanup.ps1
# Muc dich: Don dep toan bo cac file lab da tao de dua thu muc ve trang thai ban dau
# ==============================================================================

$LabDir = $PSScriptRoot
if (-not $LabDir) { $LabDir = "." }

$files = @("confidential.txt", "invoice.txt", "readme.txt", "downloaded_tool.txt")

foreach ($file in $files) {
    $fullPath = Join-Path $LabDir $file
    if (Test-Path $fullPath) {
        Remove-Item -Path $fullPath -Force
        Write-Host "[-] Da xoa file: $file" -ForegroundColor Yellow
    }
}

Write-Host "[OK] Da don dep xong toan bo file lab ADS!" -ForegroundColor Green
