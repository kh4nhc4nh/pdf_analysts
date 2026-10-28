# ==============================================================================
# Script: Lab_Setup.ps1
# Muc dich: Tao moi truong thuc hanh NTFS Alternate Data Streams (ADS)
# ==============================================================================

$LabDir = $PSScriptRoot
if (-not $LabDir) { $LabDir = "." }

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   KHOI TAO PHONG LAB NTFS ALTERNATE DATA STREAMS" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. Kich ban 1: Giau thong tin bi mat (Plaintext Secret)
# File vo boc: confidential.txt
# Stream an: confidential.txt:passwords.txt
# ------------------------------------------------------------------------------
$file1 = Join-Path $LabDir "confidential.txt"
"Day la noi dung cong khai: Tai lieu huong dan noi bo phong CNTT." | Set-Content -Path $file1 -Encoding utf8
"Mat khau quan tri Domain Controller: P@ssw0rd2026!#Admin" | Set-Content -Path $file1 -Stream "passwords.txt" -Encoding utf8
Write-Host "[+] Da tao Kich ban 1: $file1" -ForegroundColor Green
Write-Host "    -> Stream an: confidential.txt:passwords.txt" -ForegroundColor Yellow

# ------------------------------------------------------------------------------
# 2. Kich ban 2: Giau va thuc thi PowerShell Script (LOLBAS / In-Memory Execution)
# File vo boc: invoice.txt
# Stream an: invoice.txt:recon.ps1
# ------------------------------------------------------------------------------
$file2 = Join-Path $LabDir "invoice.txt"
"Hoa don dich vu thang 10/2026. Tong thanh toan: 5.000.000 VND." | Set-Content -Path $file2 -Encoding utf8

$psPayload = @'
Write-Host ""
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host " [!] CANH BAO PHAT HIEN: MA DOC DANG CHAY TU ADS!" -ForegroundColor Red
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host " [*] Host Name      : $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host " [*] Current User   : $env:USERNAME" -ForegroundColor Yellow
Write-Host " [*] OS Version     : $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor Yellow
Write-Host " [*] PID Hien tai   : $PID" -ForegroundColor Yellow
Write-Host " [*] Thoi gian chay : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "[THUC THI THANH CONG: Payload PowerShell an da duoc kich hoat!]`n" -ForegroundColor Green
'@
$psPayload | Set-Content -Path $file2 -Stream "recon.ps1" -Encoding utf8
Write-Host "[+] Da tao Kich ban 2: $file2" -ForegroundColor Green
Write-Host "    -> Stream an: invoice.txt:recon.ps1 (Chua ma doc do tham he thong)" -ForegroundColor Yellow

# ------------------------------------------------------------------------------
# 3. Kich ban 3: Giau va thuc thi qua Windows Script Host (cscript/wscript)
# File vo boc: readme.txt
# Stream an: readme.txt:popup.vbs
# ------------------------------------------------------------------------------
$file3 = Join-Path $LabDir "readme.txt"
"Huong dan su dung phan mem: Vui long doc ky truoc khi cai dat." | Set-Content -Path $file3 -Encoding utf8

$vbsPayload = 'MsgBox "Canh bao! Ma VBScript duoc thuc thi tu NTFS Alternate Data Stream!", vbCritical, "SOC Analyst Lab Demo"'
$vbsPayload | Set-Content -Path $file3 -Stream "popup.vbs" -Encoding ascii
Write-Host "[+] Da tao Kich ban 3: $file3" -ForegroundColor Green
Write-Host "    -> Stream an: readme.txt:popup.vbs (Bat Popup canh bao Windows)" -ForegroundColor Yellow

# ------------------------------------------------------------------------------
# 4. Kich ban 4: Mo phong Mark-of-the-Web (Zone.Identifier)
# File vo boc: downloaded_tool.txt
# Stream an: downloaded_tool.txt:Zone.Identifier
# ------------------------------------------------------------------------------
$file4 = Join-Path $LabDir "downloaded_tool.txt"
"Cong cu phan tich mang duoc tai ve tu Internet." | Set-Content -Path $file4 -Encoding utf8

$motw = @"
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://evil-site.local/malware.zip
HostUrl=https://evil-site.local/files/downloaded_tool.txt
"@
$motw | Set-Content -Path $file4 -Stream "Zone.Identifier" -Encoding ascii
Write-Host "[+] Da tao Kich ban 4: $file4" -ForegroundColor Green
Write-Host "    -> Stream an: downloaded_tool.txt:Zone.Identifier (Mo phong Mark of the Web - ZoneId=3)" -ForegroundColor Yellow

Write-Host "`n[HOAN TAT] Moi truong lab da san sang! Xem huong dan trong file README.md." -ForegroundColor Cyan
