from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests

# Try importing concise and PDF generator helpers if available locally
try:
    from pdfanalyzer.concise_report import build_concise_report
except ImportError:
    try:
        from generate_pdf_report import extract_concise_report as build_concise_report
    except ImportError:
        build_concise_report = None

try:
    from pdfanalyzer.pdf_report import generate_pdf_report
except ImportError:
    try:
        from generate_pdf_report import generate_pdf as generate_pdf_report
    except ImportError:
        generate_pdf_report = None


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a PDF to the Ubuntu static analysis API and save JSON/PDF reports.")
    parser.add_argument("pdf", help="Path to the local PDF file")
    parser.add_argument("--url", default=os.environ.get("PDF_ANALYZER_URL", "http://192.168.140.133:8000"), help="Base URL of the Ubuntu API")
    parser.add_argument("--token", default=os.environ.get("PDF_API_TOKEN", ""), help="Bearer token; prefer env var PDF_API_TOKEN")
    parser.add_argument("--out", default="reports", help="Directory in which to save reports")
    parser.add_argument("--timeout", type=int, default=240, help="HTTP request timeout in seconds")
    parser.add_argument("--format", choices=["full", "concise", "both"], default="both", help="JSON format to save (default: both)")
    parser.add_argument("--pdf", action="store_true", help="Generate polished executive & SOC PDF report")
    args = parser.parse_args()

    pdf_path = Path(args.pdf).expanduser().resolve()
    if not pdf_path.is_file():
        print(f"ERROR: PDF not found: {pdf_path}", file=sys.stderr)
        return 2
    if not args.token:
        print("ERROR: set PDF_API_TOKEN or pass --token", file=sys.stderr)
        return 2

    url = args.url.rstrip("/") + "/analyze"
    try:
        with pdf_path.open("rb") as stream:
            response = requests.post(
                url,
                headers={"Authorization": f"Bearer {args.token}"},
                files={"file": (pdf_path.name, stream, "application/pdf")},
                timeout=args.timeout,
            )
        if not response.ok:
            print(f"API ERROR: HTTP {response.status_code}", file=sys.stderr)
            print(response.text[:4000], file=sys.stderr)
            return 1
        report = response.json()
    except requests.RequestException as exc:
        print(f"CONNECTION ERROR: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"INVALID JSON RESPONSE: {exc}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    job_id = report.get("job_id", datetime.now().strftime("%Y%m%d-%H%M%S"))

    # Extract or use concise report
    concise = report.get("concise_report")
    if not concise and build_concise_report:
        concise = build_concise_report(report)

    # Save JSON files according to format
    if args.format in ("full", "both"):
        full_path = out_dir / f"{job_id}.json"
        full_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[✓] Full JSON Report   : {full_path.resolve()}")

    if args.format in ("concise", "both") and concise:
        concise_path = out_dir / f"{job_id}_concise.json"
        concise_path.write_text(json.dumps(concise, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[✓] Concise JSON Report: {concise_path.resolve()}")

    # Generate PDF if requested
    if args.pdf:
        if concise and generate_pdf_report:
            pdf_path_out = out_dir / f"{job_id}_report.pdf"
            try:
                generate_pdf_report(concise, pdf_path_out)
                print(f"[✓] Executive PDF Report: {pdf_path_out.resolve()}")
            except Exception as e:
                print(f"[!] Warning: Could not generate PDF ({e})", file=sys.stderr)
        else:
            print("[!] Warning: PDF generation skipped (missing concise data or ReportLab)", file=sys.stderr)

    # Display dual-tier summary in terminal
    verdict = report.get("verdict", {})
    sample = report.get("sample", {})

    print("\n" + "=" * 65)
    print("      PDF STATIC ANALYSIS — ASSESSMENT SUMMARY")
    print("=" * 65)
    print(f"Job ID   : {job_id}")
    print(f"Sample   : {sample.get('original_filename', pdf_path.name)}")
    print(f"SHA-256  : {sample.get('sha256', 'unknown')}")
    print(f"Verdict  : {verdict.get('label', 'unknown').upper()} (Confidence: {verdict.get('confidence', 'unknown')})")

    if concise:
        exec_s = concise.get("executive_summary", {})
        soc_s = concise.get("soc_technical_attribution", {})
        print("-" * 65)
        print("[1] DÀNH CHO CẤP QUẢN LÝ / NON-TECH (EXECUTIVE SUMMARY):")
        print(f" • Nhận định : {exec_s.get('headline')}")
        print(f" • Giải thích: {exec_s.get('plain_explanation')}")
        print(f" • Tác động  : {exec_s.get('business_impact')}")
        print("-" * 65)
        print("[2] DÀNH CHO SOC ANALYST (OBJECT FORENSICS & IOCS):")
        flagged = soc_s.get("flagged_objects", [])
        if flagged:
            for fo in flagged:
                print(f" • [!] Object ID: {fo.get('object_id')} ({fo.get('role')})")
                print(f"     Path   : {fo.get('hierarchy_path')}")
                print(f"     Trigger: {fo.get('trigger_mechanism')}")
                for d in fo.get("details", []):
                    print(f"     -> {d['field']}: {d['value']}")
        else:
            print(" • Không phát hiện đối tượng nghi vấn rõ ràng.")
    elif verdict.get("reasons"):
        for reason in verdict["reasons"]:
            print(f"Reason   : {reason}")
    print("=" * 65 + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
