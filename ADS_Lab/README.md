# PHÒNG LAB THỰC HÀNH: NTFS ALTERNATE DATA STREAMS (ADS)
> **Dành cho:** SOC Analyst / DFIR / Windows Security Engineer  
> **MITRE ATT&CK:** [T1564.004 - Defense Evasion: Alternate Data Streams](https://attack.mitre.org/techniques/T1564/004/)

---

## 1. Mục lục các kịch bản Lab đã được tạo sẵn

Thư mục `ADS_Lab` đã được khởi tạo với 4 kịch bản điển hình:

| File vỏ bọc | Stream ẩn (ADS) | Loại nội dung | Kịch bản thực tế |
| :--- | :--- | :--- | :--- |
| `confidential.txt` | `:passwords.txt` | Plaintext Secret | Kẻ tấn công giấu thông tin nội bộ / credentials |
| `invoice.txt` | `:recon.ps1` | PowerShell Payload | Tấn công LOLBAS, chạy recon system script từ bộ nhớ |
| `readme.txt` | `:popup.vbs` | VBScript Payload | Thực thi mã qua Windows Script Host (`cscript`/`wscript`) |
| `downloaded_tool.txt` | `:Zone.Identifier` | Windows Metadata | Mark-of-the-Web (MOTW) - Cơ chế cảnh báo file Internet của Windows |

---

## 2. Hướng dẫn thực hành: Quan sát sự "vô hình" của ADS

### Bước 1: Mở bằng Notepad hoặc File Explorer
1. Nhấp đúp vào file `invoice.txt` hoặc mở bằng Notepad:
   ```cmd
   notepad invoice.txt
   ```
   *Kết quả:* Bạn chỉ thấy nội dung vỏ bọc: `"Hoa don dich vu thang 10/2026. Tong thanh toan: 5.000.000 VND."`
2. Kiểm tra dung lượng trên File Explorer hoặc lệnh `dir`:
   ```cmd
   dir invoice.txt
   ```
   *Kết quả:* Kích thước chỉ vỏn vẹn ~67 bytes! Toàn bộ 896 bytes của file mã độc `recon.ps1` hoàn toàn không làm tăng kích thước hiển thị của file.

---

## 3. Hướng dẫn thực hành: Kích hoạt & Thực thi mã từ ADS

### Kịch bản 1: Đọc mật khẩu ẩn trong ADS
- **Bằng Notepad:**
  ```cmd
  notepad confidential.txt:passwords.txt
  ```
- **Bằng PowerShell:**
  ```powershell
  Get-Content .\confidential.txt -Stream passwords.txt
  ```

---

### Kịch bản 2: Thực thi mã độc PowerShell từ ADS (In-Memory Execution)
Kẻ tấn công không cần ghi payload ra đĩa dưới dạng `.ps1` rời rạc, mà đọc trực tiếp stream ẩn rồi đẩy thẳng vào bộ nhớ để thực thi:
```powershell
Get-Content .\invoice.txt -Stream recon.ps1 | Invoke-Expression
```
> *(Hoặc viết tắt: `gc .\invoice.txt -Stream recon.ps1 | iex`)*

---

### Kịch bản 3: Thực thi VBScript qua `cscript`
Windows Script Host hỗ trợ trực tiếp đường dẫn ADS:
```cmd
cscript //nologo .\readme.txt:popup.vbs
```
*Kết quả:* Một hộp thoại Windows Popup sẽ bật lên trực tiếp từ stream của file text!

---

### Kịch bản 4: Đọc Mark-of-the-Web (MOTW)
Xem thông tin nguồn gốc file được tải từ Internet:
```powershell
Get-Content .\downloaded_tool.txt -Stream Zone.Identifier
```
*Kết quả:* Hiển thị `ZoneId=3` (Internet Zone), kèm thông tin URL nguồn tải về.

---

## 4. Tự tạo ADS thủ công từ đầu (Tự thực hành)

### Cách 1: Bằng Command Prompt (CMD)
```cmd
:: 1. Tạo file text bình thường
echo Day la noi dung binh thuong > mytest.txt

:: 2. Nhồi dữ liệu hoặc script vào stream ẩn ':secret.txt'
echo Day la thong tin bi mat giau trong ADS! > mytest.txt:secret.txt

:: 3. Nhồi một mã script batch
echo @echo off ^& echo Payload chay thanh cong! > mytest.txt:run.bat
```

### Cách 2: Bằng PowerShell
```powershell
# Tạo file gốc
"Noi dung goc" | Set-Content .\mytest.txt

# Tạo stream ẩn
"Write-Host 'Chao mung ban den voi NTFS ADS' -ForegroundColor Green" | Set-Content .\mytest.txt -Stream "test.ps1"

# Thực thi
Get-Content .\mytest.txt -Stream "test.ps1" | Invoke-Expression
```

---

## 5. Góc nhìn SOC Analyst: Phát hiện, Điều tra & Xử lý

### A. Phát hiện bằng dòng lệnh
1. **Trong CMD:** Dùng cờ `/R` (chỉ hiển thị stream bổ sung khi có `/R`):
   ```cmd
   dir /R
   ```
2. **Trong PowerShell:**
   ```powershell
   # Liệt kê tất cả các stream của 1 file cụ thể
   Get-Item .\invoice.txt -Stream *

   # Quét toàn bộ thư mục tìm các file có chứa ADS (ngoại trừ stream mặc định :$DATA)
   Get-ChildItem -Recurse | Get-Item -Stream * | Where-Object { $_.Stream -ne ':$DATA' }
   ```

### B. Giám sát SIEM / EDR qua Sysmon
Để phát hiện kẻ tấn công tạo ADS trong mạng doanh nghiệp, SOC cấu hình **Sysmon Event ID 15: FileCreateStreamHash**:
- **Event ID 15** ghi nhận sự kiện tạo stream trên NTFS:
  - `TargetFilename`: Đường dẫn file chứa ADS (ví dụ: `C:\Users\...\invoice.txt:recon.ps1`).
  - `Hash`: Hàm băm (MD5/SHA256) của chính stream ẩn đó! Giúp SOC tra cứu threat intel hash của payload ngay cả khi nó bị giấu trong ADS.

### C. Xóa bỏ ADS (Remediation)
1. **Xóa chỉ một stream ẩn cụ thể (giữ lại file gốc):**
   ```powershell
   Remove-Item .\invoice.txt -Stream recon.ps1
   ```
2. **Dọn dẹp nhanh toàn bộ lab:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Lab_Cleanup.ps1
   ```
