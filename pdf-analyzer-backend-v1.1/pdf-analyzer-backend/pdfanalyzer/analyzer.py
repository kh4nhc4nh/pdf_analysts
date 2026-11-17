from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    CLAMAV_TIMEOUT_SECONDS,
    MAX_JS_BYTES,
    MAX_JS_OBJECTS,
    MAX_ANALYSIS_SECONDS,
    JS_STREAM_TIMEOUT_SECONDS,
    MAX_QDF_BYTES,
    MAX_QPDF_JSON_BYTES,
    MAX_UPLOAD_BYTES,
    PDFID_PATH,
    PDF_PARSER_PATH,
    REPORTS_DIR,
    RULES_DIR,
    TOOL_TIMEOUT_SECONDS,
    WORK_DIR,
)
from .concise_report import build_concise_report
from .embedded import analyze_embedded_files
from .graph_analysis import build_object_graph, load_qpdf_json, parse_reference
from .payload_analysis import (
    _decode_qpdf_string,
    analyze_javascript_bytes,
    analyze_qdf,
    parse_pdfid_output,
    parse_pdfinfo_output,
)
from .qr_analysis import analyze_qr_codes
from .runner import (
    output_mentions_infection,
    reset_analysis_deadline,
    run_binary_to_path,
    run_tool,
    set_analysis_deadline,
)

ACTIVE_KEYS = [
    "/OpenAction", "/AA", "/JS", "/JavaScript", "/Launch", "/URI",
    "/EmbeddedFile", "/EmbeddedFiles", "/ObjStm", "/AcroForm", "/XFA",
    "/RichMedia", "/GoToR", "/SubmitForm", "/ImportData",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(value: str | None) -> str:
    name = Path(value or "upload.pdf").name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return (name or "upload.pdf")[:160]


def _tool_ok(result: dict) -> bool:
    return result.get("status") == "completed"


def _yara_scan(target: Path) -> dict:
    if shutil.which("yara") is None:
        return {"name": "yara", "status": "missing_tool", "matches": []}
    rule_files = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return {"name": "yara", "status": "not_configured", "matches": []}
    all_matches = []
    runs = []
    any_error = False
    for rule_file in rule_files:
        result = run_tool(
            f"yara:{rule_file.name}",
            ["yara", str(rule_file), str(target)],
            timeout=min(TOOL_TIMEOUT_SECONDS, 10),
        )
        runs.append({k: v for k, v in result.items() if k not in {"stdout", "stderr", "command"}})
        if result.get("status") == "completed" and result.get("returncode") == 0:
            all_matches.extend(line.strip()[:500] for line in result.get("stdout", "").splitlines() if line.strip())
        elif result.get("status") != "completed" or result.get("returncode") not in (0, 1) or result.get("output_truncated"):
            any_error = True
    return {
        "name": "yara",
        "status": "partial" if any_error else "completed",
        "matches": all_matches[:100],
        "runs": runs,
    }


def _walk(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}{key}" if str(key).startswith("/") else (f"{path}/{key}" if path else str(key))
            yield child_path, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield child_path, child
            yield from _walk(child, child_path)


def _collect_javascript_entries(qpdf_data: dict) -> list[dict]:
    entries = []
    for identity, item in qpdf_data.get("objects", {}).items():
        for path, value in _walk(item.get("body")):
            last = "/" + path.rsplit("/", 1)[-1].split("]", 1)[-1]
            if last in {"/JS", "/JavaScript"}:
                entries.append({
                    "source_object": f"{identity[0]} {identity[1]} R",
                    "source_id": identity,
                    "path": path,
                    "value": value,
                    "target_reference": parse_reference(value),
                })
                if len(entries) >= 500:
                    return entries
    return entries


def _analyze_javascript_payloads(qpdf_data: dict, input_path: Path, work_dir: Path, tools: dict) -> dict:
    js_entries = _collect_javascript_entries(qpdf_data)
    payloads = []
    seen = set()
    extraction_errors = []
    selected_js_entries = js_entries[:MAX_JS_OBJECTS]
    truncated_entries = len(js_entries) > MAX_JS_OBJECTS
    if truncated_entries:
        extraction_errors.append({
            "status": "javascript_object_limit_reached",
            "discovered_entries": len(js_entries),
            "analyzed_entries_limit": MAX_JS_OBJECTS,
        })
    for index, entry in enumerate(selected_js_entries, start=1):
        raw: bytes | None = None
        ref = entry.get("target_reference")
        if ref:
            target = qpdf_data.get("objects", {}).get(tuple(ref))
            if target and target.get("kind") == "stream":
                obj_num, generation = ref
                output_path = work_dir / f"javascript-object-{obj_num}-{generation}.bin"
                result = run_binary_to_path(
                    f"javascript_stream_object_{obj_num}_{generation}",
                    ["qpdf", "--filtered-stream-data", f"--show-object={obj_num},{generation}", str(input_path)],
                    output_path,
                    timeout=min(TOOL_TIMEOUT_SECONDS, JS_STREAM_TIMEOUT_SECONDS),
                    max_bytes=MAX_JS_BYTES,
                )
                tools[f"javascript_stream_object_{obj_num}_{generation}"] = result
                if result.get("status") == "completed" and result.get("returncode") in (0, 3) and output_path.is_file():
                    raw = output_path.read_bytes()
                else:
                    extraction_errors.append({
                        "object_id": f"{obj_num} {generation} R",
                        "source_object": entry["source_object"],
                        "path": entry["path"],
                        "status": result.get("status"),
                        "returncode": result.get("returncode"),
                    })
            elif target:
                body = target.get("body")
                if isinstance(body, str):
                    raw = _decode_qpdf_string(body)
                elif isinstance(body, dict):
                    # Some PDFs wrap a script string in a nested object/value.
                    for nested_path, nested in _walk(body):
                        if nested_path.endswith(("/JS", "/JavaScript")) and isinstance(nested, str):
                            raw = _decode_qpdf_string(nested)
                            if raw is not None:
                                break
        elif isinstance(entry.get("value"), str):
            raw = _decode_qpdf_string(entry["value"])
            if raw is None:
                raw = entry["value"].encode("utf-8", errors="replace")

        if raw is None:
            # A reference could be dangling or point to a value type this extractor does not decode.
            extraction_errors.append({
                "source_object": entry["source_object"],
                "path": entry["path"],
                "target_reference": f"{ref[0]} {ref[1]} R" if ref else None,
                "status": "unresolved_javascript_value",
            })
            continue

        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        if not raw:
            payload = {
                "status": "empty_payload",
                "source_object": entry["source_object"],
                "source_path": entry["path"],
                "size_bytes": 0,
                "sha256": digest,
                "execution_performed": False,
            }
        else:
            payload = analyze_javascript_bytes(
                raw,
                source_object=entry["source_object"],
                source_path=entry["path"],
            )
            payload["target_object"] = f"{ref[0]} {ref[1]} R" if ref else None
        payloads.append(payload)
        if len(payloads) >= 100:
            break

    return {
        "status": "inconclusive" if extraction_errors or truncated_entries else "completed",
        "javascript_entry_count": len(js_entries),
        "javascript_entries_analyzed": len(selected_js_entries),
        "truncated": truncated_entries,
        "payload_count": len(payloads),
        "payloads": payloads,
        "extraction_errors": extraction_errors[:100],
        "execution_performed": False,
        "note": "JavaScript is decoded, beautified, and inspected as data only; no JS engine, eval, or shell was invoked.",
    }


def _is_bad_tool_result(name: str, result: dict) -> bool:
    if result.get("status") != "completed":
        return True
    code = result.get("returncode")
    if name in {"qpdf_check", "qpdf_json", "qpdf_normalize"}:
        return code not in (0, 3)
    if name == "yara":
        # The wrapper checks each rule's exit code; 0=match, 1=no match.
        return result.get("status") != "completed"
    if name == "clamav":
        return code not in (0, 1) or bool(result.get("output_truncated"))  # 1 indicates a detected infection; 2+ indicates an error.
    if name in {"pdfdetach_list", "pdf_parser_stats", "pdfid"}:
        return code != 0 or bool(result.get("output_truncated"))
    if result.get("output_truncated"):
        return True
    return code not in (0, 1, 3)


def analyze_pdf_bytes(content: bytes, filename: str) -> dict:
    start = time.monotonic()
    job_id = str(uuid.uuid4())
    sample_sha256 = hashlib.sha256(content).hexdigest()
    original_name = _safe_filename(filename)
    tools: dict[str, dict] = {}
    findings: list[dict] = []
    pdfid_summary: dict = {}
    pdfinfo_fields: dict = {}
    object_graph: dict = {"status": "not_run"}
    qpdf_data: dict | None = None
    payload: dict = {"status": "not_run"}
    javascript_analysis: dict = {"status": "not_run", "payloads": []}
    attachments_analysis: dict = {"status": "not_run", "items": []}
    qr_analysis: dict = {"status": "not_run", "urls": []}

    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"File exceeds configured limit of {MAX_UPLOAD_BYTES} bytes")
    if b"%PDF-" not in content[:1024]:
        raise ValueError("No PDF header found in the first 1024 bytes")

    work_dir = Path(tempfile.mkdtemp(prefix=f"{job_id}-", dir=WORK_DIR))
    deadline_token = set_analysis_deadline(MAX_ANALYSIS_SECONDS)
    try:
        work_dir.chmod(0o700)
        input_path = work_dir / "input.pdf"
        qdf_path = work_dir / "normalized.qdf.pdf"
        qpdf_json_path = work_dir / "qpdf-objects.json"
        input_path.write_bytes(content)
        input_path.chmod(0o600)

        # 1. Intake, type and structure validation.
        tools["file_type"] = run_tool(
            "file_type", ["file", "--brief", "--mime-type", str(input_path)], timeout=10
        )
        tools["qpdf_check"] = run_tool(
            "qpdf_check", ["qpdf", "--check", str(input_path)], timeout=TOOL_TIMEOUT_SECONDS
        )
        tools["pdfinfo"] = run_tool(
            "pdfinfo", ["pdfinfo", str(input_path)], timeout=TOOL_TIMEOUT_SECONDS
        )
        if _tool_ok(tools["pdfinfo"]):
            pdfinfo_fields = parse_pdfinfo_output(tools["pdfinfo"].get("stdout", ""))

        # ExifTool is an additional static metadata source; it is enrichment, not a required verdict gate.
        tools["exiftool"] = run_tool(
            "exiftool", ["exiftool", "-json", "-G1", "-s", str(input_path)], timeout=min(TOOL_TIMEOUT_SECONDS, 15)
        )
        exiftool_metadata: list | dict | None = None
        if tools["exiftool"].get("status") == "completed" and not tools["exiftool"].get("output_truncated"):
            try:
                parsed_metadata = json.loads(tools["exiftool"].get("stdout", ""))
                if isinstance(parsed_metadata, (list, dict)):
                    exiftool_metadata = parsed_metadata
            except (json.JSONDecodeError, TypeError):
                exiftool_metadata = None

        # 2. Keyword triage and parser sanity check.
        if PDFID_PATH.is_file():
            tools["pdfid"] = run_tool(
                "pdfid", [sys.executable, str(PDFID_PATH), str(input_path)], timeout=TOOL_TIMEOUT_SECONDS
            )
            if _tool_ok(tools["pdfid"]):
                pdfid_summary = parse_pdfid_output(tools["pdfid"].get("stdout", ""))
        else:
            tools["pdfid"] = {"name": "pdfid", "status": "missing_tool", "path": str(PDFID_PATH)}

        if PDF_PARSER_PATH.is_file():
            tools["pdf_parser_stats"] = run_tool(
                "pdf_parser_stats",
                [sys.executable, str(PDF_PARSER_PATH), "-a", str(input_path)],
                timeout=TOOL_TIMEOUT_SECONDS,
            )
        else:
            tools["pdf_parser_stats"] = {"name": "pdf_parser_stats", "status": "missing_tool", "path": str(PDF_PARSER_PATH)}

        # 3. Parse qpdf JSON without stream bytes. This gives actual object IDs and references.
        tools["qpdf_json"] = run_tool(
            "qpdf_json",
            ["qpdf", "--json", "--json-key=qpdf", "--json-stream-data=none", str(input_path), str(qpdf_json_path)],
            timeout=max(TOOL_TIMEOUT_SECONDS, 30),
            max_written_file_bytes=MAX_QPDF_JSON_BYTES,
        )
        if (
            tools["qpdf_json"].get("status") == "completed"
            and tools["qpdf_json"].get("returncode") in (0, 3)
            and qpdf_json_path.is_file()
            and qpdf_json_path.stat().st_size <= MAX_QPDF_JSON_BYTES
        ):
            try:
                qpdf_data = load_qpdf_json(qpdf_json_path)
                object_graph = build_object_graph(qpdf_data)
                object_graph["json_file_size_bytes"] = qpdf_json_path.stat().st_size
                if tools["qpdf_json"].get("returncode") == 3:
                    object_graph["qpdf_warnings_present"] = True
            except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
                object_graph = {"status": "inconclusive", "reason": f"Could not parse qpdf JSON safely: {type(exc).__name__}"}
        else:
            object_graph = {
                "status": "inconclusive",
                "reason": "qpdf JSON export failed, timed out or exceeded the configured output limit.",
            }

        # 4. Normalize/decompress supported streams for byte-level static triage.
        qdf_result = run_tool(
            "qpdf_normalize",
            [
                "qpdf", "--qdf", "--object-streams=disable", "--stream-data=uncompress",
                str(input_path), str(qdf_path),
            ],
            timeout=max(TOOL_TIMEOUT_SECONDS, 30),
            max_written_file_bytes=MAX_QDF_BYTES,
        )
        tools["qpdf_normalize"] = qdf_result
        if qdf_result.get("status") == "completed" and qdf_result.get("returncode") in (0, 3) and qdf_path.is_file() and qdf_path.stat().st_size <= MAX_QDF_BYTES:
            payload = analyze_qdf(qdf_path)
        else:
            payload = {
                "status": "inconclusive",
                "reason": "QDF normalization failed, timed out or exceeded output-size limit; byte-level payload inspection is incomplete.",
                "execution_performed": False,
            }

        # 5. Inspect actual /JS values and referenced JS stream objects.
        if qpdf_data:
            javascript_analysis = _analyze_javascript_payloads(qpdf_data, input_path, work_dir, tools)
        else:
            javascript_analysis = {
                "status": "inconclusive",
                "payload_count": 0,
                "payloads": [],
                "extraction_errors": [{"status": "qpdf_object_graph_unavailable"}],
                "execution_performed": False,
            }
        js_urls = [
            url
            for js_payload in javascript_analysis.get("payloads", [])
            for url in js_payload.get("urls", [])
        ]
        qdf_urls = payload.get("urls", [])
        qdf_decoded_urls = payload.get("urls_found_after_single_layer_decode", [])
        direct_uri_urls = [
            item.get("url", "")
            for item in object_graph.get("direct_uri_values", [])
            if item.get("url")
        ] if object_graph.get("status") == "completed" else []
        merged_urls = list(dict.fromkeys(qdf_urls + qdf_decoded_urls + js_urls + direct_uri_urls))[:200]
        payload["urls"] = merged_urls

        # 6. Embedded files: inventory first, then extract each using a controlled path and scan.
        attachments_analysis = analyze_embedded_files(input_path, work_dir)
        tools["pdfdetach_list"] = attachments_analysis.get("list_tool", {"status": attachments_analysis.get("status")})

        # 7. Optional quishing detection by static page rasterization + QR decode. No URLs are fetched.
        page_count = None
        try:
            page_count = int(pdfinfo_fields.get("Pages", ""))
        except (TypeError, ValueError):
            pass
        qr_analysis = analyze_qr_codes(input_path, work_dir, page_count)
        qr_urls = qr_analysis.get("urls", [])
        payload["urls"] = list(dict.fromkeys(payload.get("urls", []) + qr_urls))[:200]
        if object_graph.get("status") == "completed":
            def _js_payload_summary(item: dict) -> dict:
                return {
                    "sha256": item.get("sha256"),
                    "javascript_indicators": item.get("javascript_indicators", {}),
                    "urls": item.get("urls", [])[:20],
                    "string_concatenations": item.get("string_concatenations", [])[:20],
                    "decoded_string_literals": item.get("decoded_string_literals", [])[:20],
                    "obfuscation_indicators": item.get("obfuscation_indicators", {}),
                    "behavior_hypotheses": item.get("behavior_hypotheses", [])[:20],
                    "decoded_candidates": item.get("decoded_candidates", [])[:10],
                    "beautifier_status": item.get("beautifier_status"),
                    "execution_performed": False,
                }

            analyzed_payloads_by_object = {
                item.get("target_object"): _js_payload_summary(item)
                for item in javascript_analysis.get("payloads", [])
                if item.get("target_object")
            }
            analyzed_payloads_by_source = {
                (item.get("source_object"), item.get("source_path")): _js_payload_summary(item)
                for item in javascript_analysis.get("payloads", [])
            }
            for chain in object_graph.get("behavior_chains", []):
                if chain.get("target_object") in analyzed_payloads_by_object:
                    chain["javascript_payload_analysis"] = analyzed_payloads_by_object[chain["target_object"]]
            for chain in object_graph.get("trigger_to_javascript_chains", []):
                js_target = chain.get("javascript_object")
                summary = analyzed_payloads_by_object.get(js_target) if js_target else None
                if summary is None:
                    final_relation = next(
                        (step.get("relation") for step in reversed(chain.get("steps", []))
                         if "/JS" in step.get("relation", "") or "/JavaScript" in step.get("relation", "")),
                        None,
                    )
                    summary = analyzed_payloads_by_source.get((chain.get("javascript_source_object"), final_relation))
                if summary is not None:
                    chain["javascript_payload_analysis"] = summary

        # 8. Signature scanning of the PDF and YARA scanning of normalized content.
        tools["clamav"] = run_tool(
            "clamav", ["clamscan", "--infected", "--no-summary", str(input_path)], timeout=CLAMAV_TIMEOUT_SECONDS
        )
        tools["clamav"]["infected"] = output_mentions_infection(tools["clamav"])
        yara_target = qdf_path if qdf_path.exists() and payload.get("status") == "completed" else input_path
        tools["yara"] = _yara_scan(yara_target)

        # 9. Correlate evidence. Indicators remain evidence, not proof of runtime execution.
        counts = pdfid_summary.get("keyword_counts", {})
        active_counts = {key: counts.get(key, 0) for key in ACTIVE_KEYS if counts.get(key, 0) > 0}
        if active_counts:
            findings.append({
                "severity": "informational",
                "type": "active_content_keywords",
                "source": "pdfid",
                "detail": "Active-content/action-related PDF names were found; their presence alone does not prove maliciousness.",
                "counts": active_counts,
            })

        if object_graph.get("status") == "completed":
            trigger_to_js = object_graph.get("trigger_to_javascript_chains", [])
            if trigger_to_js:
                findings.append({
                    "severity": "medium",
                    "type": "action_to_javascript_reference_chain",
                    "source": "qpdf_object_graph",
                    "detail": "A static reference path connects /OpenAction or /AA to a JavaScript value/stream. This reconstructs PDF structure; it does not prove execution occurred.",
                    "chains": trigger_to_js[:50],
                })

        if tools.get("clamav", {}).get("infected"):
            findings.append({
                "severity": "high",
                "type": "antivirus_signature_match",
                "source": "clamav",
                "detail": "ClamAV reported a signature match; review the exact detection name and sample context.",
            })
        yara_matches = tools.get("yara", {}).get("matches", [])
        if yara_matches:
            generic_only = all("PDF_Static_ActiveContent_Indicators" in match for match in yara_matches)
            findings.append({
                "severity": "informational" if generic_only else "medium",
                "type": "yara_rule_match",
                "source": "yara",
                "detail": "One or more local YARA rules matched. The generic active-content rule is informational; other custom matches require review and are not an automatic malware verdict.",
                "matches": yara_matches,
            })

        if payload.get("status") == "completed":
            if payload.get("urls"):
                findings.append({
                    "severity": "informational",
                    "type": "urls_found",
                    "source": "static_pdf_and_javascript_content",
                    "count": len(payload["urls"]),
                    "urls": payload["urls"][:100],
                })
            if payload.get("javascript_pattern_indicators"):
                findings.append({
                    "severity": "medium",
                    "type": "javascript_or_script_patterns",
                    "source": "normalized_pdf",
                    "patterns": payload["javascript_pattern_indicators"],
                })
            if payload.get("obfuscation_indicators"):
                findings.append({
                    "severity": "medium",
                    "type": "possible_obfuscation",
                    "source": "normalized_pdf",
                    "patterns": payload["obfuscation_indicators"],
                })
            candidates = payload.get("decoded_candidates", [])
            if candidates:
                findings.append({
                    "severity": "informational",
                    "type": "statically_decoded_candidates",
                    "source": "normalized_pdf",
                    "count": len(candidates),
                    "details": candidates[:30],
                    "detail": "Candidates were decoded in memory only; none were executed.",
                })

        js_payloads = javascript_analysis.get("payloads", [])
        deconcat_items = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), **entry}
            for item in js_payloads for entry in item.get("string_concatenations", [])
        ]
        decoded_literal_items = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), **entry}
            for item in js_payloads for entry in item.get("decoded_string_literals", [])
        ]
        if decoded_literal_items:
            findings.append({
                "severity": "medium" if any(
                    re.search(r"(?i)(?:\bcmd\b|powershell|wscript|cscript|https?://|launchURL|eval|unescape|atob|ActiveXObject|XMLHttpRequest)", str(item.get("decoded_string", "")))
                    for item in decoded_literal_items
                ) else "informational",
                "type": "javascript_escaped_string_decoding",
                "source": "javascript_static_string_decoder",
                "detail": "Common hexadecimal/Unicode escape sequences in string literals were decoded as data only.",
                "items": decoded_literal_items[:100],
            })
        if deconcat_items:
            risk_words = re.compile(r"(?i)(?:\bcmd\b|powershell|wscript|cscript|eval|unescape|atob|https?://|launchURL|XMLHttpRequest|ActiveXObject|shell)")
            risky_deconcat = [item for item in deconcat_items if risk_words.search(str(item.get("reconstructed_string", "")))]
            findings.append({
                "severity": "medium" if risky_deconcat else "informational",
                "type": "javascript_literal_concatenation",
                "source": "javascript_static_deconcatenation",
                "detail": "Adjacent string literals joined by + were reconstructed as data; no variables were resolved and no JavaScript was executed.",
                "items": deconcat_items[:100],
                "higher_risk_items": risky_deconcat[:100],
            })
        js_patterns = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), "patterns": item.get("javascript_indicators", {})}
            for item in js_payloads if item.get("javascript_indicators")
        ]
        if js_patterns:
            findings.append({"severity": "medium", "type": "javascript_payload_indicators", "source": "javascript_static_analysis", "items": js_patterns[:100]})
        js_obfuscation = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), "patterns": item.get("obfuscation_indicators", {})}
            for item in js_payloads if item.get("obfuscation_indicators")
        ]
        if js_obfuscation:
            findings.append({"severity": "medium", "type": "javascript_obfuscation_indicators", "source": "javascript_static_analysis", "items": js_obfuscation[:100]})
        js_external_urls = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), "urls": item.get("urls", [])[:20], "indicators": item.get("javascript_indicators", {})}
            for item in js_payloads if item.get("urls")
        ]
        if js_external_urls:
            elevating_keys = {"app_launchURL", "getURL", "XMLHttpRequest", "download_function_names", "eval", "atob", "unescape", "decodeURIComponent"}
            elevated = any(elevating_keys.intersection(item.get("javascript_indicators", {})) for item in js_payloads if item.get("urls"))
            findings.append({
                "severity": "medium" if elevated else "informational",
                "type": "javascript_external_url_candidate",
                "source": "javascript_static_analysis",
                "detail": "A URL was found inside a JavaScript value. It has not been contacted; URL presence alone does not prove maliciousness.",
                "items": js_external_urls[:100],
            })
        decoded_js_candidates = [
            {"source_object": item.get("source_object"), "source_path": item.get("source_path"), "candidate": candidate}
            for item in js_payloads for candidate in item.get("decoded_candidates", [])
        ]
        if decoded_js_candidates:
            findings.append({
                "severity": "informational",
                "type": "javascript_encoded_candidates",
                "source": "javascript_static_analysis",
                "items": decoded_js_candidates[:100],
            })
            active_decoded_candidates = []
            high_signal_names = {
                "eval", "unescape", "decodeURIComponent", "atob", "fromCharCode",
                "ActiveXObject", "XMLHttpRequest", "PowerShell_reference",
                "cmd_reference", "cmd_word", "powershell_word", "wscript_or_cscript",
                "download_function_names", "app_launchURL", "getURL",
            }
            for wrapped in decoded_js_candidates:
                candidate = wrapped.get("candidate", {})
                decoded_indicators = candidate.get("decoded_text_indicators", {})
                magic = candidate.get("detected_magic", [])
                if high_signal_names.intersection(decoded_indicators) or any(
                    marker in magic for marker in ("PE/MZ", "ELF executable/shared object")
                ) or candidate.get("urls"):
                    active_decoded_candidates.append({
                        **wrapped,
                        "matched_indicator_names": sorted(high_signal_names.intersection(decoded_indicators)),
                    })
            if active_decoded_candidates:
                findings.append({
                    "severity": "medium",
                    "type": "decoded_payload_behavior_indicators",
                    "source": "javascript_static_decode",
                    "detail": "A statically decoded candidate contains script/command/network indicators or executable magic. This is a lead for analyst review, not proof of execution.",
                    "items": active_decoded_candidates[:50],
                })

        qdf_decoded_candidates = payload.get("decoded_candidates", [])
        notable_qdf_candidates = []
        qdf_signal_names = {
            "eval", "unescape", "decodeURIComponent", "atob", "fromCharCode",
            "ActiveXObject", "XMLHttpRequest", "PowerShell_reference",
            "cmd_reference", "cmd_word", "powershell_word", "wscript_or_cscript",
            "download_function_names", "app_launchURL", "getURL",
        }
        for candidate in qdf_decoded_candidates:
            candidate_indicators = candidate.get("decoded_text_indicators", {})
            candidate_magic = candidate.get("detected_magic", [])
            if qdf_signal_names.intersection(candidate_indicators) or any(
                marker in candidate_magic for marker in ("PE/MZ", "ELF executable/shared object")
            ) or candidate.get("urls"):
                notable_qdf_candidates.append({
                    **candidate,
                    "matched_indicator_names": sorted(qdf_signal_names.intersection(candidate_indicators)),
                })
        if notable_qdf_candidates:
            findings.append({
                "severity": "medium",
                "type": "decoded_payload_behavior_indicators",
                "source": "qdf_static_decode",
                "detail": "A statically decoded QDF candidate contains script/command/network indicators or executable magic. No candidate was executed.",
                "items": notable_qdf_candidates[:50],
            })

        embedded_items = attachments_analysis.get("items", [])
        if attachments_analysis.get("reported_count", 0):
            findings.append({
                "severity": "informational",
                "type": "embedded_files_found",
                "source": "pdfdetach",
                "reported_count": attachments_analysis.get("reported_count"),
                "analyzed_count": sum(1 for item in embedded_items if item.get("status") == "analyzed"),
                "items": [
                    {k: item.get(k) for k in ("index", "reported_filename", "stored_as", "status", "size_bytes", "sha256", "magic_matches", "header_hex", "detected_mime_type", "extension_magic_mismatch", "double_extension_suspicious")}
                    for item in embedded_items
                ][:50],
            })
        infected_embedded = [item for item in embedded_items if item.get("clamav", {}).get("infected")]
        if infected_embedded:
            findings.append({
                "severity": "high",
                "type": "embedded_file_antivirus_match",
                "source": "clamav_embedded_files",
                "items": [{"index": x.get("index"), "reported_filename": x.get("reported_filename"), "sha256": x.get("sha256"), "clamav": x.get("clamav", {}).get("stdout", "")[:1000]} for x in infected_embedded],
            })
        child_yara_matches = [
            {"index": item.get("index"), "reported_filename": item.get("reported_filename"), "matches": item.get("yara", {}).get("matches", [])}
            for item in embedded_items if item.get("yara", {}).get("matches")
        ]
        if child_yara_matches:
            findings.append({"severity": "medium", "type": "embedded_file_yara_match", "source": "yara_embedded_files", "items": child_yara_matches[:50]})
        mismatch_items = [item for item in embedded_items if item.get("extension_magic_mismatch")]
        executable_children = [
            item for item in embedded_items
            if any(marker in " ".join(item.get("magic_matches", [])) for marker in ("PE/DOS executable", "ELF executable", "Script with shebang", "script/automation markers", "Text/script-like content"))
        ]
        if mismatch_items:
            findings.append({"severity": "medium", "type": "embedded_extension_magic_mismatch", "source": "embedded_file_magic", "items": [{"index": x.get("index"), "reported_filename": x.get("reported_filename"), "magic_matches": x.get("magic_matches")} for x in mismatch_items[:50]]})
        double_extension_items = [item for item in embedded_items if item.get("double_extension_suspicious")]
        if double_extension_items:
            findings.append({"severity": "medium", "type": "embedded_double_extension", "source": "embedded_filename_analysis", "items": [{"index": x.get("index"), "reported_filename": x.get("reported_filename")} for x in double_extension_items[:50]]})
        if executable_children:
            findings.append({"severity": "medium", "type": "embedded_executable_or_script_like_content", "source": "embedded_file_magic", "items": [{"index": x.get("index"), "reported_filename": x.get("reported_filename"), "magic_matches": x.get("magic_matches"), "sha256": x.get("sha256")} for x in executable_children[:50]]})

        if qr_analysis.get("status") in {"completed", "partial"} and qr_analysis.get("decoded_codes"):
            findings.append({
                "severity": "medium" if qr_analysis.get("urls") else "informational",
                "type": "qr_code_detected",
                "source": "static_qr_analysis",
                "code_count": len(qr_analysis["decoded_codes"]),
                "urls": qr_analysis.get("urls", [])[:50],
                "detail": "QR payloads were decoded but never opened or fetched. QR URLs need reputation and phishing-context checks.",
            })

        # 10. Verdict: a strong signature can confirm known malware; other combinations remain heuristic.
        encrypted = pdfinfo_fields.get("Encrypted", "").lower().startswith("yes")
        required_tool_names = ["file_type", "qpdf_check", "qpdf_json", "pdfid", "pdf_parser_stats", "qpdf_normalize", "clamav", "yara", "pdfdetach_list"]
        failed_required = [name for name in required_tool_names if name not in tools or _is_bad_tool_result(name, tools[name])]
        if object_graph.get("status") != "completed" or object_graph.get("truncated"):
            failed_required.append("object_graph")
        if payload.get("status") != "completed":
            failed_required.append("payload_analysis")
        if attachments_analysis.get("status") != "completed" or attachments_analysis.get("truncated"):
            failed_required.append("embedded_file_analysis")
        if javascript_analysis.get("status") != "completed" and javascript_analysis.get("javascript_entry_count", 0):
            failed_required.append("javascript_payload_analysis")

        all_signature_hits = bool(tools.get("clamav", {}).get("infected") or infected_embedded)
        if all_signature_hits:
            verdict = "malicious"
            confidence = "high"
            reasons = ["ClamAV reported a signature match on the PDF or an extracted embedded file; verify the detection name and context."]
        elif failed_required or encrypted or tools.get("qpdf_check", {}).get("returncode") == 2:
            verdict = "inconclusive"
            confidence = "limited"
            reasons = []
            if failed_required:
                reasons.append("Static coverage was incomplete: " + ", ".join(sorted(set(failed_required))))
            if encrypted:
                reasons.append("PDF metadata indicates encryption; content visibility may be limited.")
            if tools.get("qpdf_check", {}).get("returncode") == 2:
                reasons.append("qpdf reported structural errors; interpretation is limited.")
        else:
            # Verdict elevation is severity-driven: ordinary hyperlinks, a bare
            # /OpenAction, a generic low-confidence YARA rule, or a non-URL QR code
            # are recorded but do not alone make the PDF suspicious.
            has_suspicious = (
                any(item.get("severity") in {"medium", "high"} for item in findings)
                or counts.get("/Launch", 0) > 0
                or tools.get("qpdf_check", {}).get("returncode") == 3
            )
            if has_suspicious:
                verdict = "suspicious"
                confidence = "medium"
                reasons = ["One or more static indicators or object relationships need analyst review; indicators alone do not prove malware execution."]
            else:
                verdict = "low_risk"
                confidence = "limited"
                reasons = ["No strong malicious indicator was found in the completed checks. This is not proof that the PDF is safe."]
        if qr_analysis.get("status") == "disabled":
            reasons.append("QR inspection was disabled; visual QR-based phishing was not evaluated in this run.")
        elif qr_analysis.get("status") in {"missing_tool", "inconclusive", "partial"}:
            reasons.append("QR inspection was incomplete or unavailable; visual QR-based phishing may not have been evaluated fully.")
        if javascript_analysis.get("status") == "completed" and not any(x.get("beautifier_status") == "completed" for x in javascript_analysis.get("payloads", [])) and javascript_analysis.get("payload_count", 0):
            reasons.append("JavaScript beautification was unavailable or failed; raw static string indicators were still analyzed where possible.")

        report = {
            "schema_version": "1.1.0",
            "job_id": job_id,
            "created_at_utc": _utc_now(),
            "sample": {
                "original_filename": original_name,
                "sha256": sample_sha256,
                "size_bytes": len(content),
                "file_header": content[:16].decode("latin-1", errors="replace"),
                "detected_mime_type": tools.get("file_type", {}).get("stdout", "").strip() or None,
            },
            "workflow": [
                {"stage": "intake_and_hash", "status": "completed"},
                {"stage": "structure_check_qpdf", "status": tools.get("qpdf_check", {}).get("status")},
                {"stage": "metadata_extraction_exiftool", "status": tools.get("exiftool", {}).get("status")},
                {"stage": "keyword_triage_pdfid", "status": tools.get("pdfid", {}).get("status")},
                {"stage": "object_inventory_pdf_parser", "status": tools.get("pdf_parser_stats", {}).get("status")},
                {"stage": "qpdf_object_graph_and_reference_reconstruction", "status": object_graph.get("status")},
                {"stage": "normalize_and_decode_supported_streams", "status": tools.get("qpdf_normalize", {}).get("status")},
                {"stage": "javascript_beautify_and_static_deconcatenation", "status": javascript_analysis.get("status")},
                {"stage": "embedded_file_inventory_extract_magic_and_scan", "status": attachments_analysis.get("status")},
                {"stage": "static_qr_inspection", "status": qr_analysis.get("status")},
                {"stage": "signature_and_yara_scanning", "status": "completed" if tools.get("clamav", {}).get("status") == "completed" and tools.get("yara", {}).get("status") == "completed" else "partial" if tools.get("clamav", {}).get("status") == "completed" else "inconclusive"},
                {"stage": "evidence_correlation_and_verdict", "status": "completed"},
            ],
            "structure": {
                "pdfid": pdfid_summary,
                "pdfinfo": pdfinfo_fields,
                "exiftool_metadata": exiftool_metadata,
                "qpdf_check": {k: tools.get("qpdf_check", {}).get(k) for k in ("status", "returncode", "stdout", "stderr", "output_truncated")},
                "pdf_parser_summary": {k: tools.get("pdf_parser_stats", {}).get(k) for k in ("status", "returncode", "stdout", "stderr", "output_truncated")},
                "object_graph": object_graph,
            },
            "payload_analysis": payload,
            "javascript_analysis": javascript_analysis,
            "embedded_files": attachments_analysis,
            "qr_analysis": qr_analysis,
            "findings": findings,
            "tools": tools,
            "verdict": {
                "label": verdict,
                "confidence": confidence,
                "reasons": reasons,
                "execution_performed": False,
                "limitations": [
                    "Static analysis only: no PDF JavaScript or extracted file was executed.",
                    "Object relationships are reconstructed from qpdf JSON; unusual or malformed PDFs may still cause incomplete parsing.",
                    "JavaScript beautification and literal concatenation are static heuristics; they do not resolve arbitrary runtime variables or encryption.",
                    "Embedded filenames are metadata only. Extracted files are written to controlled numbered paths, not the PDF-provided names.",
                    "QR scanning is optional and limited to the configured number of rendered pages; decoded URLs are never contacted.",
                    "A low_risk result means no strong indicator was found in completed checks and does not prove safety.",
                ],
            },
            "duration_seconds": round(time.monotonic() - start, 3),
        }

        report["concise_report"] = build_concise_report(report)

        report_path = REPORTS_DIR / f"{job_id}.json"
        report["report_storage"] = {"saved": True, "path": str(report_path)}
        report["analysis_limits"] = {
            "wall_clock_seconds": MAX_ANALYSIS_SECONDS,
            "javascript_objects_limit": MAX_JS_OBJECTS,
            "javascript_stream_timeout_seconds": JS_STREAM_TIMEOUT_SECONDS,
        }
        temp_report = REPORTS_DIR / f".{job_id}.tmp"
        temp_report.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        temp_report.chmod(0o600)
        temp_report.replace(report_path)
        return report
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        reset_analysis_deadline(deadline_token)
