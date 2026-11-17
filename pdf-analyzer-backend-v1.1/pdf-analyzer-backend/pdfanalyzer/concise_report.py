from __future__ import annotations

import json
from typing import Any


def build_concise_report(report_data: dict[str, Any]) -> dict[str, Any]:
    """Extract and synthesize a concise, high-signal report from raw static analysis.

    Structured for two primary audiences:
    1. Non-technical users / Management (Executive Summary, plain language, business risk).
    2. SOC Analysts (Precise object attribution, hierarchy paths, triggers, IOCs, obfuscation, MITRE ATT&CK).
    """
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

    # Determine risk level & badge
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

    # Flagged objects and exact forensic attribution
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

    # 5. Embedded files attribution
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

    # QR URL IOCs
    for q_url in qr.get("urls", []):
        if q_url not in seen_urls:
            seen_urls.add(q_url)
            network_iocs.append({
                "type": "QR-URL",
                "indicator": q_url,
                "severity": "HIGH",
                "context": "URL giải mã từ mã QR trong trang (Quishing)",
            })

    # Obfuscation indicators
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
