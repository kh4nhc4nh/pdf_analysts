# ==============================================================================
# Script: Analyze_Artifact.ps1
# Muc dich: Kich ban phan tich ky thuat so (Digital Forensics Triage) cho ADS
# ==============================================================================

param (
    [string]$TargetFile = ".\ADS_Lab\invoice.txt",
    [string]$StreamName = "recon.ps1",
    [string]$OutputDir  = ".\ADS_Lab\Analysis_Output"
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "           SOC ANALYST - QUY TRINH PHAN TICH CHUNG CU ADS             " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Kiem tra su ton tai cua file va stream
if (-not (Test-Path $TargetFile)) {
    Write-Error "[-] Khong tim thay file muc tieu: $TargetFile"
    return
}

$streamObj = Get-Item -Path $TargetFile -Stream $StreamName -ErrorAction SilentlyContinue
if (-not $streamObj) {
    Write-Error "[-] File $TargetFile khong chua stream: $StreamName"
    return
}

# 2. Tao thu muc luu tru chung cu cach ly (Quarantine / Evidence folder)
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$extractedPath = Join-Path $OutputDir "extracted_$StreamName"

# 3. Trich xuat an toan du lieu tu Stream
Write-Host "`n[BUOC 1] DANG TRICH XUAT AN TOAN STREAM RA VUNG CACH LY..." -ForegroundColor Yellow
$content = Get-Content -Path $TargetFile -Stream $StreamName -Raw
[System.IO.File]::WriteAllText($extractedPath, $content, [System.Text.Encoding]::UTF8)
Write-Host "[+] Da luu payload vao: $extractedPath" -ForegroundColor Green

# 4. Tinh toan ma bam (Hashing / IOC Generation)
Write-Host "`n[BUOC 2] TINH TOAN MA BAM NHAN DIEN (INDICATORS OF COMPROMISE - IOC)..." -ForegroundColor Yellow
$hashSha256 = (Get-FileHash -Path $extractedPath -Algorithm SHA256).Hash
$hashMd5    = (Get-FileHash -Path $extractedPath -Algorithm MD5).Hash
$fileSize   = (Get-Item $extractedPath).Length

Write-Host "    - Ten file vo boc  : $(Resolve-Path $TargetFile)" -ForegroundColor White
Write-Host "    - Ten Stream bi an : $StreamName" -ForegroundColor White
Write-Host "    - Kich thuoc stream: $fileSize bytes" -ForegroundColor White
Write-Host "    - MD5              : $hashMd5" -ForegroundColor Cyan
Write-Host "    - SHA256           : $hashSha256" -ForegroundColor Cyan

# 5. Phan tich tinh ma nguon (Static Code Analysis)
Write-Host "`n[BUOC 3] PHAN TICH TINH (STATIC CODE AUDIT)..." -ForegroundColor Yellow

$suspiciousPatterns = @(
    @{ Pattern = "Get-CimInstance|Get-WmiObject"; Category = "T1082: System Information Discovery" },
    @{ Pattern = "COMPUTERNAME|USERNAME";        Category = "T1033: System Owner/User Discovery" },
    @{ Pattern = "Invoke-Expression|iex";         Category = "T1059.001: PowerShell Execution" },
    @{ Pattern = "Start-Process|calc.exe";        Category = "T1204: User Execution / Spawn Process" },
    @{ Pattern = "Net\.WebClient|curl|wget";      Category = "T1105: Ingress Tool Transfer" }
)

Write-Host " [*] Ket qua ra quet tu khoa doc hai (Signatures & Behaviors):" -ForegroundColor White
$detectedBehaviors = @()

foreach ($item in $suspiciousPatterns) {
    if ($content -match $item.Pattern) {
        Write-Host "    [!] Phat hien: $($item.Category) (Match: '$($Matches[0])')" -ForegroundColor Red
        $detectedBehaviors += $item.Category
    }
}

if ($detectedBehaviors.Count -eq 0) {
    Write-Host "    [i] Khong phat hien tu khoa nghi van pho bien trong script." -ForegroundColor Gray
}

# 6. Hien thi noi dung payload duoc boc tach
Write-Host "`n[BUOC 4] NOI DUNG MA NGUON TRICH XUAT:" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Get-Content $extractedPath | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray

# 7. Ket luan & Khuyen nghi cho SOC Analyst
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "                    KET LUAN DANH GIA CUA SOC ANALYST                 " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " 1. Danh gia muc do   : NGUY HIEM / DOC HAI (SUSPICIOUS / MALICIOUS)" -ForegroundColor Red
Write-Host " 2. Ky thuat su dung  : MITRE ATT&CK T1564.004 (Alternate Data Streams)" -ForegroundColor Yellow
Write-Host " 3. Muc tieu payload  : Thu thap thong tin may tinh, ten user, he dieu hanh (Reconnaissance)" -ForegroundColor Yellow
Write-Host " 4. Hanh dong tiep theo: " -ForegroundColor White
Write-Host "    + Mang ma bam SHA256 tra cuu tren VirusTotal / AlienVault OTX." -ForegroundColor White
Write-Host "    + Quet cac may khac trong he thong de tim file hash hoac ten stream tuong tu." -ForegroundColor White
Write-Host "    + Loai bo stream bang lenh: Remove-Item '$TargetFile' -Stream '$StreamName'" -ForegroundColor White
Write-Host "======================================================================`n" -ForegroundColor Cyan
