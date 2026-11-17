from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any

OBJECT_KEY_RE = re.compile(r"^obj:(\d+)\s+(\d+)\s+R$")
REFERENCE_RE = re.compile(r"^(\d+)\s+(\d+)\s+R$")
SPECIAL_KEYS = {
    "/OpenAction", "/AA", "/A", "/S", "/JS", "/JavaScript", "/URI",
    "/Launch", "/EmbeddedFiles", "/EmbeddedFile", "/EF", "/AcroForm",
    "/XFA", "/RichMedia", "/SubmitForm", "/ImportData", "/GoToR",
}
ACTION_TYPES = {"/JavaScript", "/URI", "/Launch", "/GoToR", "/SubmitForm", "/ImportData", "/GoTo"}
JS_KEYS = {"/JS", "/JavaScript"}


def parse_reference(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    match = REFERENCE_RE.fullmatch(value.strip())
    return (int(match.group(1)), int(match.group(2))) if match else None


def object_id_from_key(key: str) -> tuple[int, int] | None:
    match = OBJECT_KEY_RE.fullmatch(key)
    return (int(match.group(1)), int(match.group(2))) if match else None


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


def _string_value(value: Any) -> str | None:
    if isinstance(value, str):
        if value.startswith("u:"):
            return value[2:]
        if value.startswith("b:"):
            try:
                return bytes.fromhex(value[2:]).decode("utf-8", errors="replace")
            except ValueError:
                return "[invalid qpdf binary string]"
        return value
    return None


def _summarize_value(value: Any, max_chars: int = 300) -> Any:
    if isinstance(value, str):
        ref = parse_reference(value)
        if ref:
            return {"reference": f"{ref[0]} {ref[1]} R"}
        value_text = _string_value(value)
        if value_text is not None:
            return value_text[:max_chars]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_summarize_value(item, max_chars) for item in value[:20]]
    if isinstance(value, dict):
        return {str(k): _summarize_value(v, max_chars) for k, v in list(value.items())[:30]}
    return str(value)[:max_chars]


def load_qpdf_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    qpdf = data.get("qpdf")
    if not isinstance(qpdf, list) or len(qpdf) < 2 or not isinstance(qpdf[1], dict):
        raise ValueError("Unsupported qpdf JSON layout; expected JSON version 2 object dictionary")
    meta, raw_objects = qpdf[0], qpdf[1]
    objects: dict[tuple[int, int], dict] = {}
    trailer = raw_objects.get("trailer", {})
    for key, wrapper in raw_objects.items():
        identity = object_id_from_key(key)
        if identity is None or not isinstance(wrapper, dict):
            continue
        if "value" in wrapper:
            body = wrapper.get("value")
            kind = "value"
        elif isinstance(wrapper.get("stream"), dict):
            body = wrapper["stream"].get("dict", {})
            kind = "stream"
        else:
            body = {}
            kind = "unknown"
        objects[identity] = {
            "key": key,
            "body": body,
            "kind": kind,
            "wrapper": wrapper,
        }
    trailer_body = trailer.get("value", {}) if isinstance(trailer, dict) else {}
    root = parse_reference(trailer_body.get("/Root")) if isinstance(trailer_body, dict) else None
    return {
        "json_version": meta.get("jsonversion"),
        "pdf_version": meta.get("pdfversion"),
        "max_object_id": meta.get("maxobjectid"),
        "objects": objects,
        "trailer_body": trailer_body,
        "root": root,
    }


def _object_roles(body: Any, kind: str) -> list[str]:
    roles: set[str] = set()
    if kind == "stream":
        roles.add("stream_object")
    entries = list(_walk(body))
    top = body if isinstance(body, dict) else {}
    if top.get("/Type") == "/Catalog":
        roles.add("catalog")
    if any(path.endswith("/OpenAction") for path, _ in entries):
        roles.add("open_action_entry")
    if any(path.endswith("/AA") for path, _ in entries):
        roles.add("additional_actions_entry")
    if any(path.endswith("/JS") or path.endswith("/JavaScript") for path, _ in entries):
        roles.add("javascript_reference_or_value")
    if any(path.endswith("/URI") for path, _ in entries):
        roles.add("uri_entry")
    if any(path.endswith("/Launch") for path, _ in entries):
        roles.add("launch_entry")
    if any(path.endswith("/EmbeddedFiles") for path, _ in entries):
        roles.add("embedded_files_name_tree")
    if any(path.endswith("/EmbeddedFile") for path, _ in entries) or top.get("/Type") == "/EmbeddedFile":
        roles.add("embedded_file_stream_or_entry")
    if any(path.endswith("/EF") for path, _ in entries):
        roles.add("embedded_file_specification")
    if any(path.endswith("/AcroForm") for path, _ in entries):
        roles.add("acroform_entry")
    if any(path.endswith("/XFA") for path, _ in entries):
        roles.add("xfa_entry")
    if top.get("/S") in ACTION_TYPES:
        roles.add("action_type:" + str(top.get("/S")))
    # Retain nested action dictionaries, not just top-level /S entries.
    for path, value in entries:
        if path.endswith("/S") and isinstance(value, str) and value in ACTION_TYPES:
            roles.add("nested_action_type:" + value)
    return sorted(roles)


def build_object_graph(qpdf_data: dict, *, max_objects: int = 5000, max_edges: int = 15000) -> dict:
    objects = qpdf_data["objects"]
    edges: list[dict] = []
    inventory: list[dict] = []
    js_values: list[dict] = []
    direct_urls: list[dict] = []

    truncated_objects = len(objects) > max_objects
    selected_items = list(objects.items())[:max_objects]
    selected_ids = {key for key, _ in selected_items}

    for identity, item in selected_items:
        body = item["body"]
        roles = _object_roles(body, item["kind"])
        body_dict = body if isinstance(body, dict) else {}
        object_summary = {
            "object_id": f"{identity[0]} {identity[1]} R",
            "kind": item["kind"],
            "type": body_dict.get("/Type"),
            "subtype": body_dict.get("/Subtype"),
            "roles": roles,
            "dictionary_keys": sorted(list(body_dict.keys()))[:100],
            "special_entries": [],
        }
        for path, value in _walk(body):
            key = "/" + path.rsplit("/", 1)[-1].split("]", 1)[-1]
            if key in SPECIAL_KEYS:
                entry = {"path": path, "value": _summarize_value(value)}
                ref = parse_reference(value)
                if ref:
                    entry["target_object"] = f"{ref[0]} {ref[1]} R"
                object_summary["special_entries"].append(entry)
            if key in JS_KEYS:
                js_values.append({
                    "source_object": f"{identity[0]} {identity[1]} R",
                    "source_id": identity,
                    "path": path,
                    "value": value,
                    "target_reference": parse_reference(value),
                })
            if key == "/URI":
                string_value = _string_value(value)
                if string_value:
                    direct_urls.append({
                        "source_object": f"{identity[0]} {identity[1]} R",
                        "path": path,
                        "url": string_value[:2048],
                    })
            ref = parse_reference(value)
            if ref and ref in selected_ids and len(edges) < max_edges:
                edges.append({
                    "from_object": f"{identity[0]} {identity[1]} R",
                    "from_id": identity,
                    "relation": path,
                    "to_object": f"{ref[0]} {ref[1]} R",
                    "to_id": ref,
                })
        inventory.append(object_summary)

    root = qpdf_data.get("root")
    root_path: dict[tuple[int, int], list[dict]] = {}
    if root in selected_ids:
        root_path[root] = []
        adjacency: dict[tuple[int, int], list[dict]] = {}
        for edge in edges:
            adjacency.setdefault(edge["from_id"], []).append(edge)
        queue = deque([root])
        while queue:
            current = queue.popleft()
            for edge in adjacency.get(current, []):
                target = edge["to_id"]
                if target in root_path:
                    continue
                root_path[target] = root_path[current] + [{
                    "from_object": edge["from_object"],
                    "relation": edge["relation"],
                    "to_object": edge["to_object"],
                }]
                queue.append(target)

    inventory_by_id = {tuple(map(int, row["object_id"].replace(" R", "").split())): row for row in inventory}
    js_target_ids = {
        edge["to_id"] for edge in edges
        if edge["relation"].endswith(("/JS", "/JavaScript"))
    }
    embedded_target_ids = {
        edge["to_id"] for edge in edges
        if "/EF" in edge["relation"] or "/EmbeddedFiles" in edge["relation"]
    }
    behavior_chains = []
    for identity, row in inventory_by_id.items():
        roles = list(row["roles"])
        if identity in js_target_ids:
            roles.append("referenced_javascript_payload")
        if identity in embedded_target_ids:
            roles.append("referenced_embedded_file_payload")
        important = identity in js_target_ids or identity in embedded_target_ids or any(
            role in roles for role in (
                "open_action_entry", "additional_actions_entry", "javascript_reference_or_value",
                "uri_entry", "launch_entry", "embedded_files_name_tree",
                "embedded_file_stream_or_entry", "embedded_file_specification", "acroform_entry", "xfa_entry",
            )
        ) or any(role.startswith(("action_type:", "nested_action_type:")) for role in roles)
        if important:
            behavior_chains.append({
                "target_object": row["object_id"],
                "target_roles": sorted(set(roles)),
                "reachable_from_catalog": identity in root_path,
                "path_from_catalog": root_path.get(identity, []),
                "local_special_entries": row["special_entries"],
            })
        for entry in row["special_entries"]:
            if entry.get("path", "").endswith("/JS") or entry.get("path", "").endswith("/JavaScript"):
                if "value" in entry and isinstance(entry["value"], str) and not entry.get("target_object"):
                    behavior_chains.append({
                        "target_object": row["object_id"],
                        "target_roles": roles,
                        "reachable_from_catalog": identity in root_path,
                        "path_from_catalog": root_path.get(identity, []),
                        "local_evidence": {
                            "relation": entry["path"],
                            "description": "Inline JavaScript string value; content is inspected statically only.",
                            "value_preview": entry["value"][:240],
                        },
                    })

    # Build explicit paths from an action trigger (/OpenAction or /AA) to
    # JavaScript references. This is separate from the single shortest path to
    # each object, so an unrelated shorter Catalog path cannot hide the trigger.
    adjacency: dict[tuple[int, int], list[dict]] = {}
    for edge in edges:
        adjacency.setdefault(edge["from_id"], []).append(edge)

    def shortest_edges(start_id: tuple[int, int], goal_id: tuple[int, int]) -> list[dict] | None:
        queue = deque([(start_id, [])])
        visited = {start_id}
        while queue:
            current, path = queue.popleft()
            if current == goal_id:
                return path
            for next_edge in adjacency.get(current, []):
                target = next_edge["to_id"]
                if target not in visited:
                    visited.add(target)
                    queue.append((target, path + [next_edge]))
        return None

    js_edges = [
        edge for edge in edges
        if edge["relation"].endswith(("/JS", "/JavaScript"))
    ]
    trigger_edges = [
        edge for edge in edges
        if re.search(r"/(?:OpenAction|AA)(?:/|$)", edge["relation"])
    ]
    trigger_chains: list[dict] = []
    for trigger_edge in trigger_edges:
        trigger_match = re.search(r"/(OpenAction|AA)(?:/|$)", trigger_edge["relation"])
        trigger_name = "/" + trigger_match.group(1) if trigger_match else "action_trigger"
        # If the trigger edge itself points to JavaScript (e.g. a direct
        # /OpenAction/JS entry), it is already the final edge in the chain.
        for js_edge in js_edges:
            if js_edge is trigger_edge:
                path_to_source = []
            else:
                path_to_source = shortest_edges(trigger_edge["to_id"], js_edge["from_id"])
                if path_to_source is None:
                    continue
            serial_steps = [{
                "from_object": trigger_edge["from_object"],
                "relation": trigger_edge["relation"],
                "to_object": trigger_edge["to_object"],
            }]
            for step in path_to_source:
                serial_steps.append({
                    "from_object": step["from_object"],
                    "relation": step["relation"],
                    "to_object": step["to_object"],
                })
            if js_edge is not trigger_edge:
                serial_steps.append({
                    "from_object": js_edge["from_object"],
                    "relation": js_edge["relation"],
                    "to_object": js_edge["to_object"],
                })
            trigger_chains.append({
                "trigger": trigger_name,
                "trigger_object": trigger_edge["from_object"],
                "javascript_source_object": js_edge["from_object"],
                "javascript_object": js_edge["to_object"],
                "steps": serial_steps,
                "execution_performed": False,
                "interpretation": "Static reference chain only; this does not prove the JavaScript executed.",
            })
            if len(trigger_chains) >= 200:
                break
        if len(trigger_chains) >= 200:
            break

    # Inline JavaScript strings can appear without a /JS reference edge. Link
    # them to an indirect /OpenAction or /AA trigger where possible; otherwise
    # preserve direct inline trigger paths such as /OpenAction/JS in one object.
    for entry in js_values:
        if entry.get("target_reference") is not None:
            continue
        source_id = entry["source_id"]
        source_path = entry["path"]
        linked_to_trigger = False
        for trigger_edge in trigger_edges:
            path_to_source = shortest_edges(trigger_edge["to_id"], source_id)
            if path_to_source is None:
                continue
            trigger_match = re.search(r"/(OpenAction|AA)(?:/|$)", trigger_edge["relation"])
            trigger_name = "/" + trigger_match.group(1) if trigger_match else "action_trigger"
            steps = [{
                "from_object": trigger_edge["from_object"],
                "relation": trigger_edge["relation"],
                "to_object": trigger_edge["to_object"],
            }]
            steps.extend({
                "from_object": step["from_object"],
                "relation": step["relation"],
                "to_object": step["to_object"],
            } for step in path_to_source)
            steps.append({
                "from_object": entry["source_object"],
                "relation": source_path,
                "to_object": "inline JavaScript value (same containing object)",
            })
            trigger_chains.append({
                "trigger": trigger_name,
                "trigger_object": trigger_edge["from_object"],
                "javascript_source_object": entry["source_object"],
                "javascript_object": None,
                "steps": steps,
                "inline_javascript": True,
                "execution_performed": False,
                "interpretation": "Inline JavaScript is statically present in an action path; this does not prove execution.",
            })
            linked_to_trigger = True
            if len(trigger_chains) >= 200:
                break
        if not linked_to_trigger:
            inline_trigger = re.search(r"/(OpenAction|AA)(?:/|$)", source_path)
            if inline_trigger:
                trigger_chains.append({
                    "trigger": "/" + inline_trigger.group(1),
                    "trigger_object": entry["source_object"],
                    "javascript_source_object": entry["source_object"],
                    "javascript_object": None,
                    "steps": [{
                        "from_object": entry["source_object"],
                        "relation": source_path,
                        "to_object": "inline JavaScript value (same containing object)",
                    }],
                    "inline_javascript": True,
                    "execution_performed": False,
                    "interpretation": "Inline JavaScript is statically present in an action path; this does not prove execution.",
                })
        if len(trigger_chains) >= 200:
            break

    return {
        "status": "completed",
        "qpdf_json_version": qpdf_data.get("json_version"),
        "pdf_version": qpdf_data.get("pdf_version"),
        "object_count": len(objects),
        "object_inventory": inventory,
        "reference_edges": [
            {k: v for k, v in edge.items() if k not in {"from_id", "to_id"}}
            for edge in edges
        ],
        "root_object_id": f"{root[0]} {root[1]} R" if root else None,
        "behavior_chains": behavior_chains[:500],
        "trigger_to_javascript_chains": trigger_chains[:200],
        "direct_uri_values": direct_urls[:500],
        "truncated": truncated_objects or len(edges) >= max_edges,
        "note": "Reference paths are reconstructed from qpdf JSON object references. They describe static structure, not proof that the runtime behavior occurs.",
    }
