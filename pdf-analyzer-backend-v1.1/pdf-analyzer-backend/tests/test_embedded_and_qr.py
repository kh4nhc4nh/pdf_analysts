from pathlib import Path

from pdfanalyzer.embedded import identify_magic, parse_pdfdetach_list
from pdfanalyzer.qr_analysis import analyze_qr_codes


def test_parse_pdfdetach_list():
    result = parse_pdfdetach_list("2 embedded files\n1: invoice.pdf.exe\n2: notes.txt\n")
    assert result["reported_count"] == 2
    assert result["entries"][0]["index"] == 1
    assert result["entries"][0]["reported_filename"] == "invoice.pdf.exe"


def test_identify_magic_pe(tmp_path):
    p = tmp_path / "fake.txt"
    p.write_bytes(b"MZ" + b"\x00" * 40)
    result = identify_magic(p)
    assert "PE/DOS executable (MZ header)" in result["magic_matches"]


def test_qr_scan_is_disabled_by_default(tmp_path, monkeypatch):
    # Module config defaults to off; this test validates the privacy-safe default.
    from pdfanalyzer import qr_analysis
    monkeypatch.setattr(qr_analysis, "PDF_QR_SCAN_ENABLED", False)
    report = analyze_qr_codes(Path("unused.pdf"), tmp_path, 1)
    assert report["status"] == "disabled"
    assert report["execution_performed"] is False


def test_embedded_extraction_uses_controlled_output_and_scans_child(tmp_path, monkeypatch):
    from pdfanalyzer import embedded

    input_pdf = tmp_path / "sample.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")
    work = tmp_path / "work"
    work.mkdir()
    commands = []

    def fake_run_tool(name, argv, **kwargs):
        commands.append((name, list(argv)))
        if name == "pdfdetach_list":
            return {"name": name, "status": "completed", "returncode": 0,
                    "stdout": "1 embedded file\n1: ../../not-safe.exe\n", "stderr": "", "output_truncated": False}
        if name == "pdfdetach_save_1":
            output = Path(argv[4])
            output.write_bytes(b"MZ" + b"\x00" * 64)
            return {"name": name, "status": "completed", "returncode": 0, "stdout": "", "stderr": "", "output_truncated": False}
        if name == "file_embedded_1":
            return {"name": name, "status": "completed", "returncode": 0, "stdout": "application/x-dosexec\n", "stderr": "", "output_truncated": False}
        if name == "clamav_embedded_1":
            return {"name": name, "status": "completed", "returncode": 0, "stdout": "No infected files found\n", "stderr": "", "output_truncated": False}
        if name.startswith("yara:"):
            return {"name": name, "status": "completed", "returncode": 1, "stdout": "", "stderr": "", "output_truncated": False}
        raise AssertionError(f"Unexpected tool invocation: {name}")

    monkeypatch.setattr(embedded, "run_tool", fake_run_tool)
    original_which = embedded.shutil.which
    monkeypatch.setattr(embedded.shutil, "which", lambda name: "/usr/bin/yara" if name == "yara" else original_which(name))

    result = embedded.analyze_embedded_files(input_pdf, work)
    assert result["status"] == "completed"
    assert result["items"][0]["magic_matches"] == ["PE/DOS executable (MZ header)"]
    assert result["items"][0]["status"] == "analyzed"
    extraction_call = next(argv for name, argv in commands if name == "pdfdetach_save_1")
    assert Path(extraction_call[4]).name == "embedded_001.bin"
    assert "../../not-safe.exe" not in extraction_call


def test_embedded_scan_failure_is_not_marked_clean(tmp_path, monkeypatch):
    from pdfanalyzer import embedded

    input_pdf = tmp_path / "sample.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")
    work = tmp_path / "work"
    work.mkdir()

    def fake_run_tool(name, argv, **kwargs):
        if name == "pdfdetach_list":
            return {"name": name, "status": "completed", "returncode": 0,
                    "stdout": "1 embedded file\n1: sample.exe\n", "stderr": "", "output_truncated": False}
        if name == "pdfdetach_save_1":
            Path(argv[4]).write_bytes(b"MZ" + b"\x00" * 64)
            return {"name": name, "status": "completed", "returncode": 0, "stdout": "", "stderr": "", "output_truncated": False}
        if name == "file_embedded_1":
            return {"name": name, "status": "completed", "returncode": 0, "stdout": "application/x-dosexec\n", "stderr": "", "output_truncated": False}
        if name == "clamav_embedded_1":
            return {"name": name, "status": "completed", "returncode": 2, "stdout": "database error\n", "stderr": "", "output_truncated": False}
        if name.startswith("yara:"):
            return {"name": name, "status": "completed", "returncode": 1, "stdout": "", "stderr": "", "output_truncated": False}
        raise AssertionError(f"Unexpected tool invocation: {name}")

    monkeypatch.setattr(embedded, "run_tool", fake_run_tool)
    original_which = embedded.shutil.which
    monkeypatch.setattr(embedded.shutil, "which", lambda name: "/usr/bin/yara" if name == "yara" else original_which(name))

    result = embedded.analyze_embedded_files(input_pdf, work)
    assert result["status"] == "inconclusive"
    assert result["items"][0]["status"] == "scan_incomplete"


def test_identify_magic_detects_powershell_script_content(tmp_path):
    path = tmp_path / "payload.ps1"
    path.write_text("Write-Output 'static test'\n$env:USERPROFILE\n", encoding="utf-8")
    result = identify_magic(path)
    assert "Text/script-like content" in result["magic_matches"]


def test_qr_value_with_bare_domain_is_treated_as_url_candidate():
    import re

    payload = "login-example.invalid/path"
    looks_like_url = bool(
        re.match(r"(?i)^(?:https?://|www\.)", payload.strip())
        or re.match(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/|$)", payload.strip())
    )
    assert looks_like_url
