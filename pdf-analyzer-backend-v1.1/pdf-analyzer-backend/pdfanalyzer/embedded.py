from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

from .config import (
    MAX_EMBEDDED_FILES,
    MAX_EMBEDDED_FILE_BYTES,
    MAX_TOTAL_EMBEDDED_BYTES,
    RULES_DIR,
    TOOL_TIMEOUT_SECONDS,
)
from .runner import output_mentions_infection, run_tool

ATTACHMENT_LINE_RE = re.compile(r"^\s*(\d+)\s*:\s*(.*?)\s*$")
ATTACHMENT_COUNT_RE = re.compile(r"\b(\d+)\s+embedded\s+files?\b", re.IGNORECASE)

MAGIC_SIGNATURES = [
    (b"MZ", "PE/DOS executable (MZ header)"),
    (b"\x7fELF", "ELF executable/shared object"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
    (b"\x1f\x8b", "GZIP stream"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"#!", "Script with shebang"),
]

EXTENSION_EXPECTATIONS = {
    ".exe": ("PE/DOS executable",),
    ".dll": ("PE/DOS executable",),
    ".scr": ("PE/DOS executable",),
    ".pdf": ("PDF document",),
    ".zip": ("ZIP archive",),
    ".png": ("PNG image",),
    ".jpg": ("JPEG image",),
    ".jpeg": ("JPEG image",),
    ".gif": ("GIF image",),
    ".7z": ("7-Zip archive",),
    ".rar": ("RAR archive",),
    ".docx": ("ZIP archive",),
    ".xlsx": ("ZIP archive",),
    ".pptx": ("ZIP archive",),
    ".jar": ("ZIP archive",),
    ".doc": ("OLE compound document",),
    ".xls": ("OLE compound document",),
    ".ppt": ("OLE compound document",),
    ".ps1": ("Text/script-like content", "Text with script/automation markers"),
    ".psm1": ("Text/script-like content", "Text with script/automation markers"),
    ".psd1": ("Text/script-like content", "Text with script/automation markers"),
    ".vbs": ("Text/script-like content", "Text with script/automation markers"),
    ".vbe": ("Text/script-like content", "Text with script/automation markers"),
    ".bat": ("Text/script-like content", "Text with script/automation markers"),
    ".cmd": ("Text/script-like content", "Text with script/automation markers"),
    ".js": ("Text/script-like content",),
    ".jse": ("Text/script-like content",),
    ".hta": ("Text/script-like content",),
}


def parse_pdfdetach_list(output: str) -> dict:
    entries: dict[int, str] = {}
    for line in output.splitlines():
        match = ATTACHMENT_LINE_RE.match(line)
        if match:
            index = int(match.group(1))
            safe_name = re.sub(r"[\x00-\x1f\x7f]", "?", match.group(2).strip())
            entries[index] = safe_name[:512]
    count_match = ATTACHMENT_COUNT_RE.search(output)
    reported_count = int(count_match.group(1)) if count_match else None
    if reported_count is not None:
        for index in range(1, min(reported_count, MAX_EMBEDDED_FILES) + 1):
            entries.setdefault(index, f"[filename unavailable for attachment {index}]")
    return {
        "reported_count": reported_count if reported_count is not None else len(entries),
        "count_detected": reported_count is not None or bool(entries),
        "entries": [
            {"index": index, "reported_filename": name}
            for index, name in sorted(entries.items())[:MAX_EMBEDDED_FILES]
        ],
    }


def identify_magic(path: Path) -> dict:
    with path.open("rb") as stream:
        prefix = stream.read(4096)
    matches = [label for signature, label in MAGIC_SIGNATURES if prefix.startswith(signature)]
    if not matches:
        if prefix.startswith(b"\xff\xfe"):
            text_prefix = prefix[2:].decode("utf-16le", errors="replace")
        elif prefix.startswith(b"\xfe\xff"):
            text_prefix = prefix[2:].decode("utf-16be", errors="replace")
        else:
            text_prefix = prefix.decode("utf-8", errors="replace")
        stripped_text = text_prefix.lstrip()
        lower_text = stripped_text[:4096].lower()
        if (
            lower_text.startswith(("<script", "function ", "var ", "let ", "const "))
            or re.search(r"(?im)^\s*(?:param\s*\(|write-output\b|write-host\b|invoke-(?:webrequest|expression|restmethod)\b|new-object\b|add-type\b|set-executionpolicy\b|function\s+[a-z_$])", lower_text)
            or re.search(r"(?im)^\s*(?:dim\s+\w+|set\s+\w+\s*=|wscript\.|msgbox\b|execute(?:global)?\b)", lower_text)
            or re.search(r"(?im)^\s*\$[a-z_][a-z0-9_]*\s*=", lower_text)
        ):
            matches.append("Text/script-like content")
        elif any(marker in lower_text for marker in ("powershell", "wscript.shell", "createobject(", "activexobject", "cmd.exe")):
            matches.append("Text with script/automation markers")
        elif prefix:
            matches.append("Unknown or unrecognized magic")
        else:
            matches.append("Empty file")
    return {"magic_matches": matches, "header_hex": prefix[:16].hex(), "header_ascii": prefix[:16].decode("latin-1", errors="replace")}


def _yara_scan(path: Path) -> dict:
    if shutil.which("yara") is None:
        return {"status": "missing_tool", "matches": []}
    rule_files = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return {"status": "not_configured", "matches": []}
    matches: list[str] = []
    runs: list[dict] = []
    any_error = False
    for rule in rule_files:
        result = run_tool(
            f"yara:{rule.name}",
            ["yara", str(rule), str(path)],
            timeout=min(TOOL_TIMEOUT_SECONDS, 10),
        )
        runs.append({"rule_file": rule.name, "status": result.get("status"), "returncode": result.get("returncode")})
        if result.get("status") == "completed" and result.get("returncode") == 0:
            matches.extend(line.strip()[:300] for line in result.get("stdout", "").splitlines() if line.strip())
        elif result.get("status") != "completed" or result.get("returncode") not in (0, 1) or result.get("output_truncated"):
            any_error = True
    return {"status": "partial" if any_error else "completed", "matches": matches[:50], "runs": runs}


def analyze_embedded_files(input_path: Path, work_dir: Path) -> dict:
    """List embedded files and extract each to an application-controlled name.

    We deliberately use pdfdetach -save <index> -o <controlled path> instead of
    -saveall. The filenames stored in a PDF are untrusted and should never select
    extraction paths (path traversal / overwrite risk).
    """
    list_result = run_tool(
        "pdfdetach_list", ["pdfdetach", "-list", str(input_path)], timeout=TOOL_TIMEOUT_SECONDS
    )
    result = {
        "status": "completed" if list_result.get("status") == "completed" and list_result.get("returncode") == 0 else "inconclusive",
        "list_tool": list_result,
        "reported_count": 0,
        "items": [],
        "truncated": False,
        "execution_performed": False,
    }
    if result["status"] != "completed":
        result["reason"] = "pdfdetach could not enumerate embedded files; attachment coverage is incomplete."
        return result

    parsed = parse_pdfdetach_list(list_result.get("stdout", ""))
    if not parsed.get("count_detected") or list_result.get("output_truncated"):
        result["status"] = "inconclusive"
        result["reason"] = "pdfdetach output did not provide a complete, recognizable attachment inventory."
        result["raw_list_preview"] = list_result.get("stdout", "")[:4000]
        return result
    result["reported_count"] = parsed["reported_count"]
    items = parsed["entries"]
    if parsed["reported_count"] > MAX_EMBEDDED_FILES:
        result["truncated"] = True
    attachments_dir = work_dir / "attachments"
    attachments_dir.mkdir(mode=0o700, exist_ok=True)
    total_extracted = 0

    for entry in items:
        index = entry["index"]
        if index > MAX_EMBEDDED_FILES:
            result["truncated"] = True
            continue
        output_path = attachments_dir / f"embedded_{index:03d}.bin"
        save_result = run_tool(
            f"pdfdetach_save_{index}",
            ["pdfdetach", "-save", str(index), "-o", str(output_path), str(input_path)],
            timeout=min(TOOL_TIMEOUT_SECONDS, 15),
            max_written_file_bytes=MAX_EMBEDDED_FILE_BYTES,
        )
        item = {
            "index": index,
            "reported_filename": entry.get("reported_filename"),
            "stored_as": output_path.name,
            "extraction": {"status": save_result.get("status"), "returncode": save_result.get("returncode"), "stderr": save_result.get("stderr", "")[:1000]},
            "execution_performed": False,
        }
        if not output_path.is_file() or save_result.get("status") != "completed" or save_result.get("returncode") != 0:
            partial_size = output_path.stat().st_size if output_path.is_file() else 0
            if partial_size >= MAX_EMBEDDED_FILE_BYTES:
                output_path.unlink(missing_ok=True)
                item["status"] = "size_limit_exceeded"
                item["size_bytes"] = partial_size
                result["truncated"] = True
            else:
                item["status"] = "extraction_failed"
            result["items"].append(item)
            continue

        size = output_path.stat().st_size
        if size > MAX_EMBEDDED_FILE_BYTES or total_extracted + size > MAX_TOTAL_EMBEDDED_BYTES:
            output_path.unlink(missing_ok=True)
            item["status"] = "size_limit_exceeded"
            item["size_bytes"] = size
            result["items"].append(item)
            result["truncated"] = True
            continue
        total_extracted += size
        digest = hashlib.sha256()
        with output_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        item["size_bytes"] = size
        item["sha256"] = digest.hexdigest()
        item.update(identify_magic(output_path))

        file_result = run_tool(
            f"file_embedded_{index}",
            ["file", "--brief", "--mime-type", str(output_path)],
            timeout=10,
        )
        item["detected_mime_type"] = file_result.get("stdout", "").strip() or None
        reported_name = entry.get("reported_filename") or ""
        suffix = Path(reported_name).suffix.lower()
        expected = EXTENSION_EXPECTATIONS.get(suffix)
        magic_matches = item["magic_matches"]
        known_binary = any(
            marker in " ".join(magic_matches)
            for marker in ("PE/DOS executable", "ELF executable", "PDF document", "ZIP archive", "PNG image", "JPEG image", "GIF image", "OLE compound document", "GZIP stream", "RAR archive", "7-Zip archive")
        )
        compatible = expected and any(any(expect in found for found in magic_matches) for expect in expected)
        item["extension_magic_mismatch"] = bool((expected and not compatible) or (known_binary and not expected))
        item["double_extension_suspicious"] = bool(re.search(
            r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf)\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js|hta)$",
            reported_name,
        ))

        item["clamav"] = run_tool(
            f"clamav_embedded_{index}",
            ["clamscan", "--infected", "--no-summary", str(output_path)],
            timeout=min(45, 15),
        )
        item["clamav"]["infected"] = output_mentions_infection(item["clamav"])
        item["yara"] = _yara_scan(output_path)
        clamav_complete = item["clamav"].get("status") == "completed" and item["clamav"].get("returncode") in (0, 1)
        yara_complete = item["yara"].get("status") == "completed"
        item["status"] = "analyzed" if clamav_complete and yara_complete else "scan_incomplete"
        result["items"].append(item)

    result["total_extracted_bytes"] = total_extracted
    if any(item.get("status") != "analyzed" for item in result["items"]):
        result["status"] = "inconclusive"
        result["reason"] = "One or more embedded files could not be fully extracted and scanned, or a required child-file scanner failed."
    result["clamav_infected_count"] = sum(1 for x in result["items"] if x.get("clamav", {}).get("infected"))
    result["yara_match_count"] = sum(len(x.get("yara", {}).get("matches", [])) for x in result["items"])
    result["extension_magic_mismatch_count"] = sum(1 for x in result["items"] if x.get("extension_magic_mismatch"))
    result["double_extension_suspicious_count"] = sum(1 for x in result["items"] if x.get("double_extension_suspicious"))
    return result
