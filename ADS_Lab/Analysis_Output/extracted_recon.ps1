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
