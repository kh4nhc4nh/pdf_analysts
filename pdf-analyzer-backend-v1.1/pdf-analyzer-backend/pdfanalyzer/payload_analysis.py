from __future__ import annotations

import base64
import binascii
import hashlib
import re

from .config import MAX_QDF_BYTES
MAX_URLS = 100
MAX_OBFUSCATION_CANDIDATES = 20
MAX_CANDIDATE_BYTES = 1024 * 1024

URL_RE = re.compile(rb"(?i)https?://[^\s\x00<>\"'()\[\]{}]{4,2048}")
BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
HEX_STRING_RE = re.compile(rb"(?<!<)<([0-9A-Fa-f\s]{32,8192})>(?!>)")

PDF_KEYS = [
    b"/OpenAction", b"/AA", b"/JS", b"/JavaScript", b"/Launch", b"/URI",
    b"/EmbeddedFile", b"/EmbeddedFiles", b"/ObjStm", b"/AcroForm", b"/XFA",
    b"/RichMedia", b"/GoToR", b"/SubmitForm", b"/ImportData", b"/Encrypt",
]

JS_PATTERNS = {
    "eval": rb"\beval\s*\(",
    "unescape": rb"\bunescape\s*\(",
    "decodeURIComponent": rb"\bdecodeURIComponent\s*\(",
    "atob": rb"\batob\s*\(",
    "fromCharCode": rb"\bString\s*\.\s*fromCharCode\s*\(",
    "charCodeAt": rb"\bcharCodeAt\s*\(",
    "app_launchURL": rb"\b(?:app\s*\.\s*)?launchURL\s*\(",
    "submitForm": rb"\bsubmitForm\s*\(",
    "exportDataObject": rb"\bexportDataObject\s*\(",
    "getURL": rb"\bgetURL\s*\(",
    "ActiveXObject": rb"\bActiveXObject\b",
    "XMLHttpRequest": rb"\bXMLHttpRequest\b",
    "PowerShell_reference": rb"(?i)powershell(?:\.exe)?",
    "cmd_reference": rb"(?i)(?:cmd\.exe|/c\s+start)",
    "cmd_word": rb"(?i)\bcmd\b",
    "powershell_word": rb"(?i)\bpowershell(?:\.exe)?\b",
    "wscript_or_cscript": rb"(?i)\b(?:wscript|cscript)(?:\.exe)?\b",
    "download_function_names": rb"(?i)\b(?:download|downloadfile|urlmon|winhttp)\b",
}

JS_OBFUSCATION_PATTERNS = {
    "hex_escaped_chars": r"\\x[0-9a-fA-F]{2}",
    "unicode_escaped_chars": r"\\u[0-9a-fA-F]{4}",
    "percent_u_escaped_chars": r"%u[0-9a-fA-F]{4}",
    "long_base64_candidate": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])",
}

OBFUSCATION_PATTERNS = {
    "javascript_hex_escape": rb"\\x[0-9a-fA-F]{2}",
    "javascript_unicode_escape": rb"\\u[0-9a-fA-F]{4}",
    "percent_u_escape": rb"%u[0-9a-fA-F]{4}",
    "pdf_octal_escape": rb"\\[0-7]{1,3}",
    "long_base64_candidate": rb"[A-Za-z0-9+/]{24,}={0,2}",
    "long_hex_string_candidate": rb"<[0-9A-Fa-f\s]{32,8192}>",
}


def _urls(data: bytes) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(data):
        raw = match.group(0).rstrip(b".,;:")
        value = raw.decode("latin-1", errors="replace")
        if value not in seen:
            seen.add(value)
            found.append(value[:2048])
        if len(found) >= MAX_URLS:
            break
    return found


def _candidate_summary(raw: bytes, encoding: str, offset: int, source: str) -> dict | None:
    if not raw or len(raw) > MAX_CANDIDATE_BYTES:
        return None
    decoded = raw
    detected = []
    if decoded.startswith(b"%PDF-"):
        detected.append("PDF")
    if decoded.startswith(b"MZ"):
        detected.append("PE/MZ")
    if decoded.startswith(b"\x7fELF"):
        detected.append("ELF")
    if decoded.startswith(b"PK\x03\x04"):
        detected.append("ZIP")
    if decoded.startswith(b"\x1f\x8b"):
        detected.append("GZIP")
    urls = _urls(decoded)
    decoded_text = decoded.decode("utf-8", errors="replace")
    decoded_text_indicators: dict[str, int] = {}
    # Inspect decoded bytes as text only. Never feed candidates to a script engine.
    if any(ch.isprintable() for ch in decoded_text[:256]):
        for name, byte_pattern in JS_PATTERNS.items():
            try:
                pattern = re.compile(
                    byte_pattern.decode("ascii"),
                    re.IGNORECASE if b"(?i)" in byte_pattern else 0,
                )
                count = len(pattern.findall(decoded_text[:MAX_CANDIDATE_BYTES]))
            except (UnicodeDecodeError, re.error):
                count = 0
            if count:
                decoded_text_indicators[name] = count
    printable = bytes(ch for ch in decoded[:2048] if ch in b"\r\n\t" or 32 <= ch <= 126)
    preview = printable.decode("ascii", errors="replace")[:240]
    return {
        "encoding": encoding,
        "source": source,
        "offset_in_qdf": offset,
        "decoded_length": len(decoded),
        "sha256": hashlib.sha256(decoded).hexdigest(),
        "detected_magic": detected,
        "printable_preview": preview,
        "decoded_text_indicators": decoded_text_indicators,
        "urls": urls[:10],
        "execution_performed": False,
    }


def analyze_qdf(path) -> dict:
    """Inspect a qpdf-normalized PDF as bytes. Never executes extracted content."""
    p = path
    if not p.exists():
        return {"status": "not_available", "reason": "QDF output not available"}
    size = p.stat().st_size
    if size > MAX_QDF_BYTES:
        return {
            "status": "size_limit_exceeded",
            "size_bytes": size,
            "limit_bytes": MAX_QDF_BYTES,
            "note": "Static string analysis skipped to avoid excessive resource use.",
        }
    data = p.read_bytes()

    key_counts = {
        key.decode("ascii"): len(re.findall(re.escape(key), data))
        for key in PDF_KEYS
    }
    js_indicators = {}
    for name, pattern in JS_PATTERNS.items():
        matches = list(re.finditer(pattern, data))
        if matches:
            js_indicators[name] = {
                "count": len(matches),
                "offsets_in_qdf": [m.start() for m in matches[:20]],
            }

    obfuscation = {}
    for name, pattern in OBFUSCATION_PATTERNS.items():
        count = sum(1 for _ in re.finditer(pattern, data))
        if count:
            obfuscation[name] = {"count": count}

    candidates: list[dict] = []
    seen_hashes: set[str] = set()
    # Candidate Base64 decoding is limited to a single static decoding layer.
    for match in BASE64_RE.finditer(data):
        token = match.group(0)
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        summary = _candidate_summary(decoded, "base64", match.start(), "qdf_stream_or_object")
        if summary and summary["sha256"] not in seen_hashes:
            seen_hashes.add(summary["sha256"])
            candidates.append(summary)
        if len(candidates) >= MAX_OBFUSCATION_CANDIDATES:
            break

    if len(candidates) < MAX_OBFUSCATION_CANDIDATES:
        for match in HEX_STRING_RE.finditer(data):
            token = re.sub(rb"\s+", b"", match.group(1))
            if len(token) % 2 or len(token) < 32:
                continue
            try:
                decoded = bytes.fromhex(token.decode("ascii"))
            except ValueError:
                continue
            summary = _candidate_summary(decoded, "hex_string", match.start(), "qdf_pdf_hex_string")
            if summary and summary["sha256"] not in seen_hashes:
                seen_hashes.add(summary["sha256"])
                candidates.append(summary)
            if len(candidates) >= MAX_OBFUSCATION_CANDIDATES:
                break

    urls = _urls(data)
    decoded_urls = []
    for candidate in candidates:
        for url in candidate.get("urls", []):
            if url not in urls and url not in decoded_urls:
                decoded_urls.append(url)

    # qdf offsets are analysis offsets, not original-file offsets. Do not claim exact object mapping here.
    return {
        "status": "completed",
        "qdf_size_bytes": size,
        "pdf_key_occurrences_in_normalized_data": key_counts,
        "urls": urls,
        "urls_found_after_single_layer_decode": decoded_urls[:50],
        "javascript_pattern_indicators": js_indicators,
        "obfuscation_indicators": obfuscation,
        "decoded_candidates": candidates,
        "mapping_note": "Offsets refer to normalized QDF bytes, not original PDF offsets or guaranteed object IDs.",
        "execution_performed": False,
    }


def parse_pdfid_output(output: str) -> dict:
    keywords: dict[str, int] = {}
    version = None
    header = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("PDFiD "):
            version = stripped
        if stripped.startswith("PDF Header:"):
            header = stripped.split(":", 1)[1].strip()
        match = re.match(r"^\s*(/[^:\s]+|obj|endobj|stream|endstream|xref|trailer|startxref)\s*:?[ \t]+(\d+)\s*$", line)
        if match:
            keywords[match.group(1)] = int(match.group(2))
    return {"version": version, "pdf_header": header, "keyword_counts": keywords}


def parse_pdfinfo_output(output: str) -> dict:
    fields = {}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def extract_object_ids(search_output: str) -> list[int]:
    ids = []
    seen = set()
    patterns = [
        r"(?m)^\s*(\d+)\s+\d+\s+obj\b",
        r"(?m)^\s*obj\s+(\d+)\s+\d+\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, search_output):
            value = int(match.group(1))
            if value not in seen:
                seen.add(value)
                ids.append(value)
    return ids[:100]


# Static JavaScript inspection helpers. These functions never invoke a JS engine.
JS_STRING_CHAIN_RE = re.compile(
    r'''(?P<chain>(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')(?:\s*\+\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')){1,})'''
)
JS_STRING_TOKEN_RE = re.compile(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')''')
MAX_JS_ANALYSIS_CHARS = 1_000_000
MAX_DECONCAT_ITEMS = 100
MAX_JS_PREVIEW = 8_000


def _decode_js_string_literal(token: str) -> str:
    """Decode common JS string escapes without evaluating JavaScript."""
    if len(token) < 2 or token[0] not in ("'", '"') or token[-1] != token[0]:
        return token
    source = token[1:-1]
    out: list[str] = []
    i = 0
    simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while i < len(source):
        ch = source[i]
        if ch != "\\" or i + 1 >= len(source):
            out.append(ch)
            i += 1
            continue
        nxt = source[i + 1]
        if nxt == "x" and i + 3 < len(source) and re.fullmatch(r"[0-9a-fA-F]{2}", source[i + 2:i + 4]):
            out.append(chr(int(source[i + 2:i + 4], 16)))
            i += 4
        elif nxt == "u" and i + 5 < len(source) and re.fullmatch(r"[0-9a-fA-F]{4}", source[i + 2:i + 6]):
            codepoint = int(source[i + 2:i + 6], 16)
            # Combine a valid UTF-16 surrogate pair; replace any unpaired surrogate
            # so malformed input cannot later break UTF-8 JSON report writing.
            if 0xD800 <= codepoint <= 0xDBFF and source[i + 6:i + 8] == "\\u" and i + 11 < len(source) and re.fullmatch(r"[0-9a-fA-F]{4}", source[i + 8:i + 12]):
                low = int(source[i + 8:i + 12], 16)
                if 0xDC00 <= low <= 0xDFFF:
                    combined = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                    out.append(chr(combined))
                    i += 12
                else:
                    out.append("\ufffd")
                    i += 6
            elif 0xD800 <= codepoint <= 0xDFFF:
                out.append("\ufffd")
                i += 6
            else:
                out.append(chr(codepoint))
                i += 6
        elif nxt in ("\n", "\r"):
            i += 2
            if nxt == "\r" and i < len(source) and source[i] == "\n":
                i += 1
        elif nxt in simple:
            out.append(simple[nxt])
            i += 2
        else:
            # In JS, most non-special escapes collapse to the escaped char.
            out.append(nxt)
            i += 2
    return "".join(out)


def decode_js_string_literals(source: str) -> list[dict]:
    """Decode common escapes inside JavaScript string literals without evaluation."""
    source = source[:MAX_JS_ANALYSIS_CHARS]
    results: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for match in JS_STRING_TOKEN_RE.finditer(source):
        token = match.group(1)
        decoded = _decode_js_string_literal(token)
        original_content = token[1:-1]
        if decoded == original_content or not decoded:
            continue
        key = (match.start(), decoded)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "source_expression": token[:1000],
            "decoded_string": decoded[:4096],
            "source_offset": match.start(),
            "method": "javascript_string_escape_decoding_only_no_execution",
        })
        if len(results) >= MAX_DECONCAT_ITEMS:
            break
    return results


def deconcatenate_string_literals(source: str) -> list[dict]:
    """Find adjacent literal-only chains such as 'c' + 'm' + 'd'; no evaluation."""
    source = source[:MAX_JS_ANALYSIS_CHARS]
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for match in JS_STRING_CHAIN_RE.finditer(source):
        chain = match.group("chain")
        tokens = JS_STRING_TOKEN_RE.findall(chain)
        if len(tokens) < 2 or len(tokens) > 64:
            continue
        combined = "".join(_decode_js_string_literal(token) for token in tokens)
        if not combined or len(combined) > 4096:
            continue
        key = (combined, chain)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "source_expression": chain[:1000],
            "literal_count": len(tokens),
            "reconstructed_string": combined[:4096],
            "source_offset": match.start(),
            "method": "literal_concatenation_only_no_execution",
        })
        if len(results) >= MAX_DECONCAT_ITEMS:
            break
    return results


def _decode_qpdf_string(value: str) -> bytes | None:
    if value.startswith("u:"):
        return value[2:].encode("utf-8", errors="replace")
    if value.startswith("b:"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            return None
    return None


def analyze_javascript_bytes(raw: bytes, *, source_object: str, source_path: str) -> dict:
    """Beautify/inspect extracted JS text in memory; never execute it."""
    original_hash = hashlib.sha256(raw).hexdigest()
    size = len(raw)
    if size > MAX_CANDIDATE_BYTES:
        return {
            "status": "size_limit_exceeded",
            "source_object": source_object,
            "source_path": source_path,
            "size_bytes": size,
            "sha256": original_hash,
            "execution_performed": False,
        }
    if raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16le", errors="replace")
    elif raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16be", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw[3:].decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    text = text[:MAX_JS_ANALYSIS_CHARS]

    beautified = text
    beautifier_status = "not_installed"
    try:
        import jsbeautifier
        options = jsbeautifier.default_options()
        options.indent_size = 2
        options.max_preserve_newlines = 2
        beautified = jsbeautifier.beautify(text, options)
        beautifier_status = "completed"
    except Exception as exc:
        beautifier_status = f"error:{type(exc).__name__}"

    decoded_string_literals = decode_js_string_literals(beautified)
    concatenations = deconcatenate_string_literals(beautified)
    indicator_source = beautified
    for item in decoded_string_literals:
        indicator_source += "\n" + item["decoded_string"]
    for item in concatenations:
        indicator_source += "\n" + item["reconstructed_string"]

    js_indicators: dict[str, int] = {}
    for name, byte_pattern in JS_PATTERNS.items():
        try:
            pattern = re.compile(byte_pattern.decode("ascii"), re.IGNORECASE if b"(?i)" in byte_pattern else 0)
            count = len(pattern.findall(indicator_source))
        except (UnicodeDecodeError, re.error):
            count = 0
        if count:
            js_indicators[name] = count

    obfuscation_indicators: dict[str, int] = {}
    for name, pattern_source in JS_OBFUSCATION_PATTERNS.items():
        try:
            count = len(re.findall(pattern_source, indicator_source, flags=re.IGNORECASE))
        except re.error:
            count = 0
        if count:
            obfuscation_indicators[name] = count

    # Define URLs before deriving hypotheses; later, decoded candidates may add more.
    urls = _urls(indicator_source.encode("utf-8", errors="replace"))

    behavior_hypotheses = []
    if any(name in js_indicators for name in ("eval", "unescape", "decodeURIComponent", "atob", "fromCharCode")):
        behavior_hypotheses.append({
            "hypothesis": "dynamic_decode_or_code_construction",
            "evidence": [name for name in ("eval", "unescape", "decodeURIComponent", "atob", "fromCharCode") if name in js_indicators],
            "confidence": "heuristic",
        })
    if urls and any(name in js_indicators for name in ("app_launchURL", "getURL", "XMLHttpRequest", "download_function_names")):
        behavior_hypotheses.append({
            "hypothesis": "external_navigation_or_network_retrieval_candidate",
            "evidence": ["URL present"] + [name for name in ("app_launchURL", "getURL", "XMLHttpRequest", "download_function_names") if name in js_indicators],
            "confidence": "heuristic",
        })
    if any(name in js_indicators for name in ("ActiveXObject", "PowerShell_reference", "cmd_reference", "cmd_word", "powershell_word", "wscript_or_cscript")):
        behavior_hypotheses.append({
            "hypothesis": "host_command_or_automation_reference",
            "evidence": [name for name in ("ActiveXObject", "PowerShell_reference", "cmd_reference", "cmd_word", "powershell_word", "wscript_or_cscript") if name in js_indicators],
            "confidence": "heuristic",
        })
    if any(name in js_indicators for name in ("submitForm", "exportDataObject")):
        behavior_hypotheses.append({
            "hypothesis": "form_submission_or_data_export_candidate",
            "evidence": [name for name in ("submitForm", "exportDataObject") if name in js_indicators],
            "confidence": "heuristic",
        })

    decoded_summaries: list[dict] = []
    seen_hashes: set[str] = set()
    encoded_source = indicator_source.encode("utf-8", errors="replace")
    for match in BASE64_RE.finditer(encoded_source):
        token = match.group(0)
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        summary = _candidate_summary(decoded, "base64", match.start(), source_object + source_path)
        if summary and summary["sha256"] not in seen_hashes:
            seen_hashes.add(summary["sha256"])
            decoded_summaries.append(summary)
        if len(decoded_summaries) >= MAX_OBFUSCATION_CANDIDATES:
            break

    if len(decoded_summaries) < MAX_OBFUSCATION_CANDIDATES:
        for match in HEX_STRING_RE.finditer(encoded_source):
            token = re.sub(rb"\s+", b"", match.group(1))
            if len(token) % 2:
                continue
            try:
                decoded = bytes.fromhex(token.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                continue
            summary = _candidate_summary(decoded, "hex_string", match.start(), source_object + source_path)
            if summary and summary["sha256"] not in seen_hashes:
                seen_hashes.add(summary["sha256"])
                decoded_summaries.append(summary)
            if len(decoded_summaries) >= MAX_OBFUSCATION_CANDIDATES:
                break

    for candidate in decoded_summaries:
        for url in candidate.get("urls", []):
            if url not in urls and len(urls) < MAX_URLS:
                urls.append(url)

    network_keys = ("app_launchURL", "getURL", "XMLHttpRequest", "download_function_names")
    if urls and any(name in js_indicators for name in network_keys) and not any(
        item.get("hypothesis") == "external_navigation_or_network_retrieval_candidate"
        for item in behavior_hypotheses
    ):
        behavior_hypotheses.append({
            "hypothesis": "external_navigation_or_network_retrieval_candidate",
            "evidence": ["URL present after single-layer static decoding"] + [name for name in network_keys if name in js_indicators],
            "confidence": "heuristic",
        })

    return {
        "status": "completed",
        "source_object": source_object,
        "source_path": source_path,
        "size_bytes": size,
        "sha256": original_hash,
        "beautifier_status": beautifier_status,
        "beautified_preview": beautified[:MAX_JS_PREVIEW],
        "beautified_truncated": len(beautified) > MAX_JS_PREVIEW,
        "javascript_indicators": js_indicators,
        "obfuscation_indicators": obfuscation_indicators,
        "behavior_hypotheses": behavior_hypotheses,
        "decoded_string_literals": decoded_string_literals,
        "string_concatenations": concatenations,
        "urls": urls[:MAX_URLS],
        "decoded_candidates": decoded_summaries,
        "execution_performed": False,
        "analysis_note": "Static decoding and literal concatenation only. No JavaScript engine or eval was used.",
    }
