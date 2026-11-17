#!/usr/bin/env python3
"""PDF Static Security Analysis — Concise Report & PDF Generator

Extracts essential, high-signal information from full static analysis JSON
and renders a clean, executive- and SOC-grade PDF report.

Dual-audience architecture:
1. Non-Technical / Executive: Clear verdict, threat severity, plain language explanation, business impact, user actions.
2. SOC Analyst: Exact object attribution (Object IDs, reference hierarchy, trigger mechanics), IOCs, obfuscation offsets, MITRE ATT&CK mapping, IR playbook.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _init_fonts() -> tuple[str, str, str]:
    font_candidates = [
        # Windows Fonts
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/ariali.ttf"),
        ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/segoeuii.ttf"),
        # Linux Fonts
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"),
        ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf"),
    ]

    for reg, bold, italic in font_candidates:
        if os.path.exists(reg) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("CustomSans", reg))
                pdfmetrics.registerFont(TTFont("CustomSans-Bold", bold))
                if os.path.exists(italic):
                    pdfmetrics.registerFont(TTFont("CustomSans-Italic", italic))
                else:
                    pdfmetrics.registerFont(TTFont("CustomSans-Italic", reg))
                return "CustomSans", "CustomSans-Bold", "CustomSans-Italic"
            except Exception:
                pass

    return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


BASE_FONT, BOLD_FONT, ITALIC_FONT = _init_fonts()


def extract_concise_report(report_data: dict[str, Any]) -> dict[str, Any]:
    """Extract and synthesize the concise, distilled model from the full report JSON."""
    # If the report already has pre-computed concise_report, return it
    if "concise_report" in report_data and isinstance(report_data["concise_report"], dict):
        return report_data["concise_report"]

    sample = report_data.get("sample", {})
    verdict_raw = report_data.get("verdict", {})
    structure = report_data.get("structure", {})
    pdfinfo = structure.get("pdfinfo", {})
    og = structure.get("object_graph", {})
    findings = report_data.get("findings", [])
    payload = report_data.get("payload_analysis", {})
    js_analysis = report_data.get("javascript_analysis", {})
    embedded = report_data.get("embedded_files", {})
    qr = report_data.get("qr_analysis", {})

    label = str(verdict_raw.get("label", "low_risk")).lower()
    confidence = str(verdict_raw.get("confidence", "limited")).lower()

    if label == "malicious":
        risk_level = "CRITICAL / HIGH"
        badge_title = "NGUY HIỂM CAO - MÃ ĐỘC ĐÃ ĐƯỢC XÁC NHẬN"
    elif label == "suspicious":
        risk_level = "MEDIUM - HIGH"
        badge_title = "ĐÁNG NGỜ - CẢNH BÁO BẢO MẬT"
    elif label == "inconclusive":
        risk_level = "CHƯA XÁC ĐỊNH"
        badge_title = "CẦN PHÂN TÍCH THỦ CÔNG BỔ SUNG"
    else:
        risk_level = "THẤP"
        badge_title = "RỦI RO THẤP - KHÔNG PHÁT HIỆN DẤU HIỆU RÕ RÀNG"

    flagged_objects: list[dict[str, Any]] = []
    seen_objs: set[tuple[str, str]] = set()

    # 1. Trigger to JavaScript chains
    for chain in og.get("trigger_to_javascript_chains", []):
        target_obj = chain.get("javascript_object") or chain.get("javascript_source_object")
        key = (str(target_obj), "javascript")
        if target_obj and key not in seen_objs:
            seen_objs.add(key)
            steps = " ➔ ".join([f"{s.get('from_object')} ({s.get('relation')})" for s in chain.get("steps", [])])
            if chain.get("steps"):
                steps += f" ➔ {chain['steps'][-1].get('to_object')}"
            flagged_objects.append({
                "object_id": target_obj,
                "role": "JavaScript Trigger / Execution Target",
                "hierarchy_path": steps or f"Catalog ({og.get('root_object_id', 'Unknown')}) ➔ {target_obj}",
                "trigger_mechanism": f"Tự động kích hoạt khi mở tài liệu ({chain.get('trigger_type', '/OpenAction')})",
                "details": [
                    {"field": "Trigger Type", "value": chain.get("trigger_type")},
                    {"field": "Catalog Root", "value": chain.get("catalog_object")},
                ],
            })

    # 2. Behavior chains (e.g. URI actions, Page Annotations)
    for chain in og.get("behavior_chains", []):
        target_obj = chain.get("target_object")
        key = (str(target_obj), "behavior")
        if target_obj and key not in seen_objs:
            seen_objs.add(key)
            path_steps = " ➔ ".join([f"{s.get('from_object')} ({s.get('relation')})" for s in chain.get("path_from_catalog", [])])
            if chain.get("path_from_catalog"):
                path_steps += f" ➔ {chain['path_from_catalog'][-1].get('to_object')}"

            entries = []
            for entry in chain.get("local_special_entries", []):
                val = entry.get("value")
                val_str = val if isinstance(val, str) else json.dumps(val)
                entries.append({"field": entry.get("path"), "value": val_str})

            is_uri = any("/URI" in r for r in chain.get("target_roles", []))
            trigger_desc = (
                "Tương tác người dùng (User Click / Annotation Link)"
                if is_uri
                else "Hành động đối tượng (Object Action)"
            )
            flagged_objects.append({
                "object_id": target_obj,
                "role": f"Tương tác / Liên kết ({', '.join(chain.get('target_roles', []))})",
                "hierarchy_path": path_steps or f"Catalog ({og.get('root_object_id', 'Unknown')}) ➔ {target_obj}",
                "trigger_mechanism": trigger_desc,
                "details": entries[:6],
            })

    # 3. Direct URIs attribution if not yet in flagged_objects
    for uri_item in og.get("direct_uri_values", []):
        src_obj = uri_item.get("source_object")
        if src_obj and not any(fo["object_id"] == src_obj for fo in flagged_objects):
            flagged_objects.append({
                "object_id": src_obj,
                "role": "Đối tượng chứa URL ngoại vi",
                "hierarchy_path": f"Vị trí: {uri_item.get('path', 'N/A')}",
                "trigger_mechanism": "Click chuột vào liên kết",
                "details": [{"field": uri_item.get("path"), "value": uri_item.get("url")}],
            })

    # 4. JavaScript stream payloads
    for js_p in js_analysis.get("payloads", []):
        src_obj = js_p.get("target_object") or js_p.get("source_object")
        if src_obj and not any(fo["object_id"] == src_obj for fo in flagged_objects):
            flagged_objects.append({
                "object_id": src_obj,
                "role": "JavaScript Code Stream",
                "hierarchy_path": f"Vị trí: {js_p.get('source_path', 'N/A')}",
                "trigger_mechanism": "Thực thi kịch bản (Script Execution)",
                "details": [
                    {"field": "SHA-256", "value": js_p.get("sha256")},
                    {"field": "Indicators", "value": ", ".join(js_p.get("javascript_indicators", {}).keys()) or "None"},
                ],
            })

    # 5. Embedded files
    for item in embedded.get("items", []):
        is_susp = bool(item.get("extension_magic_mismatch") or item.get("double_extension_suspicious") or item.get("clamav", {}).get("infected"))
        if is_susp:
            flagged_objects.append({
                "object_id": f"Embedded File #{item.get('index')}",
                "role": "Tệp đính kèm đáng ngờ (Embedded Payload)",
                "hierarchy_path": f"Embedded File Index: {item.get('index')} ({item.get('reported_filename')})",
                "trigger_mechanism": "Người dùng mở tệp đính kèm hoặc tự động trích xuất",
                "details": [
                    {"field": "Filename", "value": item.get("reported_filename")},
                    {"field": "MIME Thực tế", "value": item.get("detected_mime_type")},
                    {"field": "SHA-256", "value": item.get("sha256")},
                    {"field": "Cảnh báo", "value": "Phát hiện giả mạo phần mở rộng hoặc chữ ký mã độc"},
                ],
            })

    # Collect IOCs
    network_iocs = []
    seen_urls = set()
    benign_keywords = ["apache.org", "adobe.com", "w3.org", "schema.org", "xml.org"]
    for f in findings:
        if f.get("type") == "urls_found":
            for u in f.get("urls", []):
                if u not in seen_urls:
                    seen_urls.add(u)
                    is_benign = any(b in u.lower() for b in benign_keywords)
                    network_iocs.append({
                        "type": "URL",
                        "indicator": u,
                        "severity": "INFORMATIONAL" if is_benign else "HIGH",
                        "context": "Tham chiếu chuẩn / Giấy phép" if is_benign else "Liên kết ngoại vi trỏ đến máy chủ ngoài (Cần chặn)",
                    })

    for q_url in qr.get("urls", []):
        if q_url not in seen_urls:
            seen_urls.add(q_url)
            network_iocs.append({
                "type": "QR-URL",
                "indicator": q_url,
                "severity": "HIGH",
                "context": "URL giải mã từ mã QR trong trang (Quishing)",
            })

    # Obfuscation
    obf_techniques = []
    for f in findings:
        if f.get("type") == "possible_obfuscation":
            patterns = f.get("patterns", {})
            for p_name, p_data in patterns.items():
                obf_techniques.append({
                    "technique": p_name.replace("_", " ").title(),
                    "count": p_data.get("count", 0),
                    "note": "Kỹ thuật che giấu payload/stream nhằm né tránh phát hiện signature",
                })

    # Embedded files list
    emb_files = []
    for item in embedded.get("items", []):
        emb_files.append({
            "index": item.get("index"),
            "filename": item.get("reported_filename"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
            "mime_detected": item.get("detected_mime_type"),
            "is_suspicious": bool(item.get("extension_magic_mismatch") or item.get("double_extension_suspicious")),
            "clamav_hit": item.get("clamav", {}).get("infected", False),
        })

    # MITRE ATT&CK Mapping
    mitre_attack = []
    if any("Tương tác" in fo.get("trigger_mechanism", "") for fo in flagged_objects):
        mitre_attack.append({
            "tactic": "Initial Access / Execution",
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File",
            "evidence": "Tài liệu dụ dỗ người dùng tương tác với link/nút bấm ẩn trong trang.",
        })
    if any("Tự động kích hoạt" in fo.get("trigger_mechanism", "") for fo in flagged_objects):
        mitre_attack.append({
            "tactic": "Execution",
            "technique_id": "T1204.002",
            "technique_name": "Automatic Execution on Open (/OpenAction)",
            "evidence": "Tài liệu sử dụng /OpenAction hoặc /AA để chạy mã hoặc mở link khi vừa mở file.",
        })
    if obf_techniques:
        mitre_attack.append({
            "tactic": "Defense Evasion",
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "evidence": f"Phát hiện {len(obf_techniques)} cơ chế làm mờ chuỗi (Base64/Hex/Octal) trong stream.",
        })
    if any(i["severity"] == "HIGH" for i in network_iocs):
        mitre_attack.append({
            "tactic": "Initial Access",
            "technique_id": "T1566.002",
            "technique_name": "Phishing: Spearphishing Link",
            "evidence": "Chứa liên kết URL ngoại vi trỏ đến máy chủ ngoài không xác thực.",
        })
    if js_analysis.get("payload_count", 0) > 0:
        mitre_attack.append({
            "tactic": "Execution",
            "technique_id": "T1059.007",
            "technique_name": "Command and Scripting Interpreter: JavaScript",
            "evidence": "Nhúng mã JavaScript vào cấu trúc đối tượng PDF.",
        })
    if any(ef["is_suspicious"] or ef["clamav_hit"] for ef in emb_files):
        mitre_attack.append({
            "tactic": "Defense Evasion / Execution",
            "technique_id": "T1027.009",
            "technique_name": "Embedded Payloads / Fake Extension",
            "evidence": "Tệp nhúng bên trong có dấu hiệu giả mạo định dạng hoặc nhiễm mã độc.",
        })

    # Plain language explanation for Non-tech
    meta_author = pdfinfo.get("Author") or "Không rõ"
    meta_creator = pdfinfo.get("Creator") or "Không rõ"
    meta_pages = pdfinfo.get("Pages") or "1"

    explanation_parts = []
    explanation_parts.append(
        f"Tệp PDF này tự nhận là tài liệu do '{meta_author}' soạn thảo bằng {meta_creator} (dung lượng {sample.get('size_bytes', 0):,} bytes, gồm {meta_pages} trang)."
    )

    high_urls = [i["indicator"] for i in network_iocs if i["severity"] == "HIGH"]
    if high_urls:
        explanation_parts.append(
            f"Điểm đáng ngờ chính: Tài liệu đã cài cắm liên kết ngầm trỏ đến máy chủ ngoài không rõ nguồn gốc ({high_urls[0]}). Đây là dấu hiệu điển hình của thủ đoạn lừa đảo (phishing) nhằm chiếm đoạt tài khoản hoặc lừa nạn nhân tải về mã độc."
        )

    if obf_techniques:
        explanation_parts.append(
            "Đồng thời, cấu trúc bên trong tệp chứa nhiều đoạn mã bị mã hóa che giấu bất thường (Base64/Hex/Octal) - kỹ thuật tin tặc thường dùng để 'qua mặt' các phần mềm diệt virus."
        )

    if js_analysis.get("payload_count", 0) > 0:
        explanation_parts.append(
            "Tài liệu còn nhúng kịch bản lập trình (JavaScript) có khả năng kích hoạt tự động ngoài ý muốn của người dùng."
        )

    if not high_urls and not obf_techniques and js_analysis.get("payload_count", 0) == 0:
        explanation_parts.append(
            "Qua quá trình phân tích tĩnh, không phát hiện thấy liên kết độc hại, mã lệnh ẩn hoặc tệp thực thi nhúng bất thường."
        )

    plain_explanation = " ".join(explanation_parts)

    primary_url = high_urls[0] if high_urls else None

    # SOC Action Playbook
    playbook_actions = []
    if primary_url:
        domain = primary_url.split("/")[2] if "//" in primary_url else primary_url
        playbook_actions.append(f"Cấu hình chặn Domain [{domain}] và URL đầy đủ trên hệ thống Firewall / DNS Sinkhole / Web Proxy.")
    playbook_actions.append(f"Thực hiện truy vấn (Threat Hunting) mã SHA-256 [{sample.get('sha256', '')}] trên EDR và SIEM để tìm kiếm máy trạm nào đã tiếp nhận tệp.")
    if primary_url:
        playbook_actions.append(f"Truy soát nhật ký DNS và Proxy trong 7 ngày gần nhất để phát hiện endpoint đã bấm vào liên kết.")
    playbook_actions.append("Tiến hành cách ly thiết bị liên quan và đưa mẫu PDF vào môi trường Sandbox động để giám sát thêm.")

    return {
        "metadata": {
            "job_id": report_data.get("job_id"),
            "timestamp_utc": report_data.get("created_at_utc"),
            "analyzer_version": report_data.get("schema_version", "1.1.0"),
        },
        "sample": {
            "filename": sample.get("original_filename"),
            "sha256": sample.get("sha256"),
            "size_bytes": sample.get("size_bytes"),
            "pages": meta_pages,
            "author": meta_author,
            "creator": meta_creator,
        },
        "executive_summary": {
            "verdict": label.upper(),
            "risk_level": risk_level,
            "badge_title": badge_title,
            "confidence": confidence.upper(),
            "headline": "Tài liệu chứa liên kết mờ ám và kỹ thuật che giấu nội dung đáng ngờ.",
            "plain_explanation": plain_explanation,
            "business_impact": "Nguy cơ lừa đảo chiếm đoạt tài khoản (Phishing), lộ lọt thông tin nhạy cảm hoặc bị cài cắm mã độc từ xa.",
            "recommendations": [
                "TUYỆT ĐỐI KHÔNG mở tài liệu hoặc nhấp vào bất kỳ đường link/nút bấm nào.",
                "Thực hiện cách ly/xóa tệp ngay khỏi hòm thư và thiết bị người dùng.",
                "Nếu đã nhấp vào liên kết, cần báo ngay cho bộ phận An toàn thông tin (SOC) để kiểm tra lịch sử kết nối mạng và đổi mật khẩu tài khoản.",
            ],
        },
        "soc_technical_attribution": {
            "flagged_objects": flagged_objects,
            "iocs": {
                "network": network_iocs,
                "sample_sha256": sample.get("sha256"),
                "embedded_files": emb_files,
            },
            "obfuscation_analysis": {
                "techniques": obf_techniques,
                "summary": f"Phát hiện tổng cộng {sum(t['count'] for t in obf_techniques)} vị trí sử dụng kỹ thuật mã hóa/che giấu.",
            },
            "mitre_attack": mitre_attack,
            "playbook_actions": playbook_actions,
        },
    }


def generate_pdf(concise_data: dict[str, Any], output_path: str | Path) -> Path:
    """Render the concise report dictionary into a 2-page executive + SOC PDF report."""
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=32,
        bottomMargin=32,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        fontName=BOLD_FONT,
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#1A365D"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        fontName=BASE_FONT,
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=10,
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        fontName=BOLD_FONT,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=10,
        spaceAfter=4,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        fontName=BOLD_FONT,
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=6,
        spaceAfter=3,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        fontName=BASE_FONT,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#2D3748"),
    )
    body_bold = ParagraphStyle(
        "Body_Bold",
        fontName=BOLD_FONT,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1A202C"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        fontName=BASE_FONT,
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#2D3748"),
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName=BOLD_FONT,
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#1A202C"),
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("BÁO CÁO ĐIỀU TRA & PHÂN TÍCH TĨNH TỆP TIN PDF", title_style))
    story.append(Paragraph("PDF Static Advanced Security Assessment — Automated Analysis Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=8))

    # Sample Metadata Table
    sample = concise_data.get("sample", {})
    meta = concise_data.get("metadata", {})

    meta_table_data = [
        [
            Paragraph("<b>Tên tệp:</b>", table_cell_bold),
            Paragraph(sample.get("filename", "N/A"), table_cell),
            Paragraph("<b>Thời gian:</b>", table_cell_bold),
            Paragraph(meta.get("timestamp_utc", "N/A"), table_cell),
        ],
        [
            Paragraph("<b>SHA-256:</b>", table_cell_bold),
            Paragraph(f"<font size=6.5>{sample.get('sha256', 'N/A')}</font>", table_cell),
            Paragraph("<b>Dung lượng:</b>", table_cell_bold),
            Paragraph(f"{sample.get('size_bytes', 0):,} bytes ({sample.get('pages', 'N/A')} trang)", table_cell),
        ],
        [
            Paragraph("<b>Tác giả / Ứng dụng:</b>", table_cell_bold),
            Paragraph(f"{sample.get('author', 'Không rõ')} | {sample.get('creator', 'Không rõ')}", table_cell),
            Paragraph("<b>Job ID:</b>", table_cell_bold),
            Paragraph(f"<font size=6.5>{meta.get('job_id', 'N/A')}</font>", table_cell),
        ],
    ]
    t_meta = Table(meta_table_data, colWidths=[90, 200, 75, 155])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))

    # SECTION 1: EXECUTIVE & NON-TECH SUMMARY
    story.append(Paragraph("1. TÓM TẮT DÀNH CHO CẤP QUẢN LÝ & NGƯỜI DÙNG (EXECUTIVE SUMMARY)", h1_style))

    exec_sum = concise_data.get("executive_summary", {})
    verdict = exec_sum.get("verdict", "UNKNOWN")
    risk_level = exec_sum.get("risk_level", "UNKNOWN")

    if verdict == "MALICIOUS":
        bg_card = colors.HexColor("#FFF5F5")
        border_card = colors.HexColor("#E53E3E")
        badge_bg = colors.HexColor("#E53E3E")
    elif verdict == "SUSPICIOUS":
        bg_card = colors.HexColor("#FFFAF0")
        border_card = colors.HexColor("#DD6B20")
        badge_bg = colors.HexColor("#DD6B20")
    else:
        bg_card = colors.HexColor("#F0FFF4")
        border_card = colors.HexColor("#38A169")
        badge_bg = colors.HexColor("#38A169")

    badge_cell = [
        [
            Paragraph(f"<font color='white'><b>KẾT LUẬN: {exec_sum.get('badge_title', verdict)}</b></font>", ParagraphStyle("Badge", fontName=BOLD_FONT, fontSize=10, textColor=colors.white)),
            Paragraph(f"<b>Mức độ rủi ro:</b> {risk_level}  |  <b>Độ tin cậy:</b> {exec_sum.get('confidence', 'N/A')}", ParagraphStyle("SubBadge", fontName=BASE_FONT, fontSize=8.5, textColor=colors.HexColor("#2D3748"))),
        ]
    ]
    t_badge = Table(badge_cell, colWidths=[260, 260])
    t_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), badge_bg),
        ("BACKGROUND", (1, 0), (1, 0), bg_card),
        ("BOX", (0, 0), (-1, -1), 1, border_card),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t_badge)
    story.append(Spacer(1, 6))

    plain_box_data = [
        [Paragraph("<b>Bản chất cảnh báo & Nhận diện rủi ro:</b>", body_bold)],
        [Paragraph(exec_sum.get("plain_explanation", ""), body_style)],
        [Paragraph(f"<b>Tác động kinh doanh tiềm ẩn:</b> {exec_sum.get('business_impact', '')}", body_style)],
    ]
    t_plain = Table(plain_box_data, colWidths=[520])
    t_plain.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t_plain)
    story.append(Spacer(1, 6))

    recs = exec_sum.get("recommendations", [])
    if recs:
        rec_data = [[Paragraph("<b>Hành động khuyến nghị khẩn cấp cho người dùng & IT:</b>", body_bold)]]
        for r in recs:
            rec_data.append([Paragraph(f"• {r}", body_style)])
        t_recs = Table(rec_data, colWidths=[520])
        t_recs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEFCBF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D69E2E")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(t_recs)

    story.append(Spacer(1, 10))

    # SECTION 2: SOC ANALYST TECHNICAL ATTRIBUTION
    story.append(Paragraph("2. PHÂN TÍCH KỸ THUẬT & ĐỊNH DANH ĐỐI TƯỢNG (SOC ANALYST ATTRIBUTION)", h1_style))
    story.append(Paragraph("Xác định chính xác <b>Object ID</b>, <b>đường dẫn cấu trúc</b> và <b>vị trí chứa yếu tố khả nghi</b> trong tài liệu PDF.", body_style))
    story.append(Spacer(1, 4))

    soc = concise_data.get("soc_technical_attribution", {})
    flagged_objects = soc.get("flagged_objects", [])

    # 2.1 Suspicious Objects
    story.append(Paragraph("2.1. Danh Sách Đối Tượng Khả Nghi & Đường Dẫn Tham Chiếu (Flagged Objects)", h2_style))
    if flagged_objects:
        obj_table_data = [
            [
                Paragraph("<b>Object ID</b>", table_cell_bold),
                Paragraph("<b>Vai trò / Cơ chế Kích hoạt</b>", table_cell_bold),
                Paragraph("<b>Đường dẫn cấu trúc (Hierarchy Path)</b>", table_cell_bold),
                Paragraph("<b>Chi tiết thuộc tính / Payload nghi vấn</b>", table_cell_bold),
            ]
        ]
        for fo in flagged_objects:
            details_str = "<br/>".join([f"<b>{d['field']}:</b> <font color='#C53030'>{d['value']}</font>" for d in fo.get("details", [])])
            obj_table_data.append([
                Paragraph(f"<b><font size=8 color='#C53030'>{fo.get('object_id')}</font></b>", table_cell),
                Paragraph(f"{fo.get('role')}<br/><font color='#4A5568'>Trigger: {fo.get('trigger_mechanism')}</font>", table_cell),
                Paragraph(fo.get("hierarchy_path", ""), table_cell),
                Paragraph(details_str, table_cell),
            ])
        t_objs = Table(obj_table_data, colWidths=[65, 135, 140, 180])
        t_objs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#A0AEC0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_objs)
    else:
        story.append(Paragraph("Không phát hiện đối tượng chứa liên kết nguy hiểm hoặc mã script nhúng.", body_style))

    story.append(Spacer(1, 8))

    # 2.2 IOCs
    story.append(Paragraph("2.2. Chỉ Số Thỏa Hiệp (Indicators of Compromise - IOCs)", h2_style))
    iocs = soc.get("iocs", {})
    network_iocs = iocs.get("network", [])

    if network_iocs:
        ioc_table_data = [
            [
                Paragraph("<b>Loại</b>", table_cell_bold),
                Paragraph("<b>Giá trị Indicator (URL / Domain / Hash)</b>", table_cell_bold),
                Paragraph("<b>Mức độ</b>", table_cell_bold),
                Paragraph("<b>Ngữ cảnh phát hiện</b>", table_cell_bold),
            ]
        ]
        for item in network_iocs:
            sev = item.get("severity", "INFORMATIONAL")
            sev_color = "#E53E3E" if sev == "HIGH" else "#4A5568"
            ioc_table_data.append([
                Paragraph(item.get("type", "N/A"), table_cell),
                Paragraph(f"<font color='{sev_color}'><b>{item.get('indicator', '')}</b></font>", table_cell),
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell),
                Paragraph(item.get("context", ""), table_cell),
            ])
        t_iocs = Table(ioc_table_data, colWidths=[55, 255, 70, 140])
        t_iocs.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#A0AEC0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_iocs)
    else:
        story.append(Paragraph("Không tìm thấy network indicators.", body_style))

    story.append(Spacer(1, 8))

    # 2.3 Obfuscation & MITRE
    story.append(Paragraph("2.3. Dấu Hiệu Làm Mờ & Chiếu Xạ MITRE ATT&CK", h2_style))
    obf = soc.get("obfuscation_analysis", {})
    techniques = obf.get("techniques", [])
    mitre_list = soc.get("mitre_attack", [])

    col_w = [110, 50, 360]
    obf_table_data = [
        [
            Paragraph("<b>Kỹ thuật mã hóa/che giấu</b>", table_cell_bold),
            Paragraph("<b>Số lượng</b>", table_cell_bold),
            Paragraph("<b>Ý nghĩa kỹ thuật / Đánh giá SOC</b>", table_cell_bold),
        ]
    ]
    for tech in techniques:
        obf_table_data.append([
            Paragraph(tech.get("technique", ""), table_cell),
            Paragraph(f"<b>{tech.get('count', 0)}</b>", table_cell),
            Paragraph(tech.get("note", ""), table_cell),
        ])
    t_obf = Table(obf_table_data, colWidths=col_w)
    t_obf.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t_obf)
    story.append(Spacer(1, 4))

    if mitre_list:
        mitre_table_data = [
            [
                Paragraph("<b>Chiến thuật (Tactic)</b>", table_cell_bold),
                Paragraph("<b>Kỹ thuật (ID & Tên)</b>", table_cell_bold),
                Paragraph("<b>Bằng chứng thực tế thu thập</b>", table_cell_bold),
            ]
        ]
        for m in mitre_list:
            mitre_table_data.append([
                Paragraph(m.get("tactic", ""), table_cell),
                Paragraph(f"<b>{m.get('technique_id')}</b>: {m.get('technique_name')}", table_cell),
                Paragraph(m.get("evidence", ""), table_cell),
            ])
        t_mitre = Table(mitre_table_data, colWidths=[130, 160, 230])
        t_mitre.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_mitre)

    story.append(Spacer(1, 8))

    # 2.4 Playbook Actions
    story.append(Paragraph("2.4. Kế Hoạch Ứng Cứu Sự Cố Dành Cho Đội SOC (Action Playbook)", h2_style))
    playbook = soc.get("playbook_actions", [])
    if playbook:
        pb_data = []
        for act in playbook:
            pb_data.append([
                Paragraph("<b>[ ]</b>", ParagraphStyle("chk", fontName=BOLD_FONT, fontSize=8.5, textColor=colors.HexColor("#2B6CB0"))),
                Paragraph(act, body_style),
            ])
        t_pb = Table(pb_data, colWidths=[22, 498])
        t_pb.setStyle(TableStyle([
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_pb)

    doc.build(story)
    return out_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a concise JSON and executive/SOC PDF report from PDF analysis JSON.")
    parser.add_argument("json_file", nargs="?", default="report.json", help="Path to the input analysis JSON file (default: report.json)")
    parser.add_argument("-o", "--pdf-out", help="Path for the output PDF report (default: <basename>.pdf)")
    parser.add_argument("--json-out", help="Path for the output concise JSON file (default: <basename>_concise.json)")
    args = parser.parse_args()

    in_path = Path(args.json_file).resolve()
    if not in_path.is_file():
        print(f"ERROR: Input JSON file not found: {in_path}", file=sys.stderr)
        return 1

    try:
        raw_data = json.loads(in_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR: Failed to read JSON file: {exc}", file=sys.stderr)
        return 1

    base_name = in_path.stem
    pdf_out = Path(args.pdf_out).resolve() if args.pdf_out else in_path.parent / f"{base_name}.pdf"
    json_out = Path(args.json_out).resolve() if args.json_out else in_path.parent / f"{base_name}_concise.json"

    concise = extract_concise_report(raw_data)
    json_out.write_text(json.dumps(concise, indent=2, ensure_ascii=False), encoding="utf-8")
    generate_pdf(concise, pdf_out)

    exec_s = concise.get("executive_summary", {})
    soc_s = concise.get("soc_technical_attribution", {})
    sample = concise.get("sample", {})

    print("\n" + "=" * 65)
    print("      PDF STATIC ANALYSIS — CONCISE EXECUTIVE & SOC REPORT")
    print("=" * 65)
    print(f"Sample File : {sample.get('filename')}")
    print(f"SHA-256     : {sample.get('sha256')}")
    print(f"Verdict     : {exec_s.get('verdict')} ({exec_s.get('risk_level')})")
    print("-" * 65)
    print("[1] DÀNH CHO CẤP QUẢN LÝ & NGƯỜI DÙNG (EXECUTIVE SUMMARY):")
    print(f" • Nhận định: {exec_s.get('headline')}")
    print(f" • Giải thích: {exec_s.get('plain_explanation')}")
    print(f" • Tác động: {exec_s.get('business_impact')}")
    print("-" * 65)
    print("[2] DÀNH CHO SOC ANALYST (TECHNICAL OBJECT ATTRIBUTION):")
    for fo in soc_s.get("flagged_objects", []):
        print(f" • [!] Flagged Object ID: {fo.get('object_id')} ({fo.get('role')})")
        print(f"     Path   : {fo.get('hierarchy_path')}")
        print(f"     Trigger: {fo.get('trigger_mechanism')}")
        for d in fo.get("details", []):
            print(f"     -> {d['field']}: {d['value']}")
    print("-" * 65)
    print(f"[✓] Concise JSON Saved : {json_out}")
    print(f"[✓] Executive PDF Saved: {pdf_out}")
    print("=" * 65 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
