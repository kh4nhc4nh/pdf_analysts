from __future__ import annotations

import re
import shutil
from pathlib import Path

from .config import MAX_QR_PAGES, PDF_QR_SCAN_ENABLED, QR_RENDER_TIMEOUT_SECONDS
from .runner import run_tool


def analyze_qr_codes(input_path: Path, work_dir: Path, page_count: int | None) -> dict:
    """Optional static QR scan: rasterize a bounded number of pages and decode QR only."""
    if not PDF_QR_SCAN_ENABLED:
        return {
            "status": "disabled",
            "reason": "Set PDF_QR_SCAN_ENABLED=1 to enable bounded page rasterization and QR decoding.",
            "urls": [],
            "execution_performed": False,
        }
    if not shutil.which("pdftoppm") or not shutil.which("zbarimg"):
        return {
            "status": "missing_tool",
            "missing": [tool for tool in ("pdftoppm", "zbarimg") if not shutil.which(tool)],
            "urls": [],
            "execution_performed": False,
        }
    if not page_count or page_count < 1:
        return {"status": "inconclusive", "reason": "Page count unavailable; QR rendering skipped.", "urls": [], "execution_performed": False}

    pages_to_scan = min(page_count, MAX_QR_PAGES)
    render_dir = work_dir / "qr_render"
    render_dir.mkdir(mode=0o700, exist_ok=True)
    prefix = render_dir / "page"
    render = run_tool(
        "pdftoppm_qr_render",
        [
            "pdftoppm", "-f", "1", "-l", str(pages_to_scan),
            "-scale-to", "1000", "-png", str(input_path), str(prefix),
        ],
        timeout=QR_RENDER_TIMEOUT_SECONDS,
        max_written_file_bytes=4 * 1024 * 1024,
    )
    images = sorted(render_dir.glob("page-*.png"))
    if render.get("status") != "completed" or render.get("returncode") not in (0, 3) or not images:
        return {
            "status": "inconclusive",
            "pages_requested": pages_to_scan,
            "render": {k: render.get(k) for k in ("status", "returncode", "stderr", "output_truncated")},
            "urls": [],
            "execution_performed": False,
        }

    decoded: list[dict] = []
    seen: set[str] = set()
    scan_errors = []
    for image in images[:MAX_QR_PAGES]:
        scan = run_tool(
            "zbarimg_qr_scan",
            ["zbarimg", "--quiet", "--raw", "--set=*.disable", "--set=qrcode.enable", str(image)],
            timeout=15,
        )
        if scan.get("status") != "completed":
            scan_errors.append({"page_image": image.name, "status": scan.get("status")})
            continue
        # zbar exit 4 means no barcode was found; it is not a scanner failure.
        if scan.get("returncode") not in (0, 4):
            scan_errors.append({"page_image": image.name, "returncode": scan.get("returncode")})
            continue
        for line in scan.get("stdout", "").splitlines():
            payload = line.strip()
            if not payload or payload in seen:
                continue
            seen.add(payload)
            decoded.append({
                "page_image": image.name,
                "decoded_value": payload[:2048],
                "looks_like_url": bool(
                    re.match(r"(?i)^(?:https?://|www\.)", payload.strip())
                    or re.match(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/|$)", payload.strip())
                ),
                "execution_performed": False,
            })
            if len(decoded) >= 100:
                break

    urls = [item["decoded_value"] for item in decoded if item["looks_like_url"]]
    return {
        "status": "completed" if not scan_errors else "partial",
        "pages_available": page_count,
        "pages_scanned": len(images[:MAX_QR_PAGES]),
        "page_scan_limit": MAX_QR_PAGES,
        "decoded_codes": decoded[:100],
        "urls": urls[:100],
        "errors": scan_errors[:20],
        "truncated_pages": page_count > pages_to_scan,
        "network_requests_performed": False,
        "execution_performed": False,
        "note": "Only QR decoding from statically rendered page images; decoded URLs are not fetched or opened.",
    }
