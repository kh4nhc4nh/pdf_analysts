from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _init_fonts() -> tuple[str, str, str]:
    font_candidates = [
        # Windows
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/ariali.ttf"),
        ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/segoeuii.ttf"),
        # Linux / Ubuntu
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


def generate_pdf_report(concise_data: dict[str, Any], output_path: str | Path) -> Path:
    """Generate a clean, high-impact 2-page PDF report designed for both

    executives/non-technical readers and SOC analysts.
    """
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

    # ==========================================
    # SECTION 1: EXECUTIVE & NON-TECH SUMMARY
    # ==========================================
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

    # ==========================================
    # SECTION 2: SOC ANALYST TECHNICAL ATTRIBUTION
    # ==========================================
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
