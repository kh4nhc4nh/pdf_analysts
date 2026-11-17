from __future__ import annotations

import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
HOME = Path.home()
DATA_DIR = Path(os.environ.get("PDF_ANALYZER_DATA_DIR", PROJECT_DIR / "data")).expanduser()
REPORTS_DIR = DATA_DIR / "reports"
WORK_DIR = DATA_DIR / "work"
RULES_DIR = Path(os.environ.get("PDF_ANALYZER_RULES_DIR", PROJECT_DIR / "rules" / "yara")).expanduser()

PDFID_PATH = Path(
    os.environ.get(
        "PDFID_PATH",
        HOME / "malware_lab" / "DidierStevensSuite" / "pdfid.py",
    )
).expanduser()
PDF_PARSER_PATH = Path(
    os.environ.get(
        "PDF_PARSER_PATH",
        HOME / "malware_lab" / "DidierStevensSuite" / "pdf-parser.py",
    )
).expanduser()

MAX_UPLOAD_BYTES = int(os.environ.get("PDF_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
MAX_QDF_BYTES = int(os.environ.get("PDF_MAX_QDF_BYTES", str(64 * 1024 * 1024)))
TOOL_TIMEOUT_SECONDS = int(os.environ.get("PDF_TOOL_TIMEOUT_SECONDS", "20"))
CLAMAV_TIMEOUT_SECONDS = int(os.environ.get("PDF_CLAMAV_TIMEOUT_SECONDS", "45"))
API_TOKEN = os.environ.get("PDF_API_TOKEN", "")

for directory in (DATA_DIR, REPORTS_DIR, WORK_DIR):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError:
        pass

# Resource bounds for the advanced static-analysis stages.
MAX_QPDF_JSON_BYTES = int(os.environ.get("PDF_MAX_QPDF_JSON_BYTES", str(32 * 1024 * 1024)))
MAX_EMBEDDED_FILES = int(os.environ.get("PDF_MAX_EMBEDDED_FILES", "10"))
MAX_EMBEDDED_FILE_BYTES = int(os.environ.get("PDF_MAX_EMBEDDED_FILE_BYTES", str(8 * 1024 * 1024)))
MAX_TOTAL_EMBEDDED_BYTES = int(os.environ.get("PDF_MAX_TOTAL_EMBEDDED_BYTES", str(20 * 1024 * 1024)))
MAX_JS_BYTES = int(os.environ.get("PDF_MAX_JS_BYTES", str(1 * 1024 * 1024)))
PDF_QR_SCAN_ENABLED = os.environ.get("PDF_QR_SCAN_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
MAX_QR_PAGES = int(os.environ.get("PDF_MAX_QR_PAGES", "5"))
QR_RENDER_TIMEOUT_SECONDS = int(os.environ.get("PDF_QR_RENDER_TIMEOUT_SECONDS", "45"))

MAX_JS_OBJECTS = int(os.environ.get("PDF_MAX_JS_OBJECTS", "10"))
JS_STREAM_TIMEOUT_SECONDS = int(os.environ.get("PDF_JS_STREAM_TIMEOUT_SECONDS", "8"))
MAX_ANALYSIS_SECONDS = int(os.environ.get("PDF_MAX_ANALYSIS_SECONDS", "180"))
