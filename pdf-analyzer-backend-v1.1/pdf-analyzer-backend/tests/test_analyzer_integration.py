import json
from pathlib import Path

from pdfanalyzer import analyzer


def test_analyzer_writes_json_and_builds_object_graph(tmp_path, monkeypatch):
    work = tmp_path / "work"
    reports = tmp_path / "reports"
    work.mkdir()
    reports.mkdir()
    monkeypatch.setattr(analyzer, "WORK_DIR", work)
    monkeypatch.setattr(analyzer, "REPORTS_DIR", reports)
    monkeypatch.setattr(analyzer, "MAX_UPLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(analyzer, "MAX_QPDF_JSON_BYTES", 1024 * 1024)
    monkeypatch.setattr(analyzer, "MAX_QDF_BYTES", 1024 * 1024)

    qpdf_json = {
        "qpdf": [
            {"jsonversion": 2, "pdfversion": "1.4", "maxobjectid": 1},
            {
                "obj:1 0 R": {"value": {"/Type": "/Catalog"}},
                "trailer": {"value": {"/Root": "1 0 R", "/Size": 2}},
            },
        ]
    }

    def fake_run_tool(name, argv, **kwargs):
        if name == "qpdf_json":
            Path(argv[-1]).write_text(json.dumps(qpdf_json), encoding="utf-8")
        elif name == "qpdf_normalize":
            Path(argv[-1]).write_bytes(b"%PDF-1.4\n%%EOF\n")
        outputs = {
            "file_type": (0, "application/pdf\n"),
            "qpdf_check": (0, "checking PDF structure\n"),
            "pdfinfo": (0, "Pages: 1\nEncrypted: no\n"),
            "pdfid": (0, "PDFiD 0.2.10 test.pdf\n PDF Header: %PDF-1.4\n /JS: 0\n /OpenAction: 0\n"),
            "pdf_parser_stats": (0, "PDF statistics\n"),
            "qpdf_json": (0, ""),
            "qpdf_normalize": (0, ""),
            "clamav": (0, "No infected files found.\n"),
        }
        code, stdout = outputs.get(name, (0, ""))
        return {"name": name, "status": "completed", "returncode": code, "stdout": stdout, "stderr": "", "output_truncated": False}

    monkeypatch.setattr(analyzer, "run_tool", fake_run_tool)
    monkeypatch.setattr(analyzer, "_yara_scan", lambda path: {"name": "yara", "status": "completed", "matches": []})
    monkeypatch.setattr(analyzer, "analyze_qdf", lambda path: {
        "status": "completed", "urls": [], "javascript_pattern_indicators": {},
        "obfuscation_indicators": {}, "decoded_candidates": [], "execution_performed": False,
    })
    monkeypatch.setattr(analyzer, "analyze_embedded_files", lambda input_path, work_dir: {
        "status": "completed", "list_tool": {"name": "pdfdetach_list", "status": "completed", "returncode": 0, "stdout": "0 embedded files\n"},
        "reported_count": 0, "items": [], "truncated": False,
        "clamav_infected_count": 0, "yara_match_count": 0,
    })
    monkeypatch.setattr(analyzer, "analyze_qr_codes", lambda input_path, work_dir, page_count: {
        "status": "disabled", "urls": [], "execution_performed": False,
    })

    report = analyzer.analyze_pdf_bytes(b"%PDF-1.4\n%%EOF\n", "benign.pdf")

    assert report["schema_version"] == "1.1.0"
    assert report["structure"]["object_graph"]["root_object_id"] == "1 0 R"
    assert report["verdict"]["execution_performed"] is False
    assert report["report_storage"]["saved"] is True
    saved = Path(report["report_storage"]["path"])
    assert saved.is_file()
    assert json.loads(saved.read_text(encoding="utf-8"))["job_id"] == report["job_id"]
