import json

from pdfanalyzer.graph_analysis import build_object_graph, load_qpdf_json


def test_reconstructs_openaction_to_javascript_stream(tmp_path):
    sample = {
        "qpdf": [
            {"jsonversion": 2, "pdfversion": "1.7", "maxobjectid": 3},
            {
                "obj:1 0 R": {"value": {"/Type": "/Catalog", "/OpenAction": "2 0 R"}},
                "obj:2 0 R": {"value": {"/S": "/JavaScript", "/JS": "3 0 R"}},
                "obj:3 0 R": {"stream": {"dict": {"/Length": 30, "/Type": "/JavaScript"}}},
                "trailer": {"value": {"/Root": "1 0 R", "/Size": 4}},
            },
        ]
    }
    source = tmp_path / "qpdf.json"
    source.write_text(json.dumps(sample), encoding="utf-8")
    parsed = load_qpdf_json(source)
    graph = build_object_graph(parsed)

    assert graph["root_object_id"] == "1 0 R"
    assert graph["object_count"] == 3
    assert any(edge["relation"] == "/OpenAction" and edge["to_object"] == "2 0 R" for edge in graph["reference_edges"])
    assert any(edge["relation"] == "/JS" and edge["to_object"] == "3 0 R" for edge in graph["reference_edges"])
    chain = next(x for x in graph["behavior_chains"] if x["target_object"] == "3 0 R")
    assert chain["reachable_from_catalog"] is True
    assert [step["relation"] for step in chain["path_from_catalog"]] == ["/OpenAction", "/JS"]
    explicit = next(x for x in graph["trigger_to_javascript_chains"] if x["javascript_object"] == "3 0 R")
    assert explicit["trigger"] == "/OpenAction"
    assert [step["relation"] for step in explicit["steps"]] == ["/OpenAction", "/JS"]
    assert explicit["execution_performed"] is False


def test_reconstructs_openaction_to_inline_javascript():
    graph = build_object_graph({
        "json_version": 2,
        "pdf_version": "1.7",
        "root": (1, 0),
        "objects": {
            (1, 0): {"kind": "value", "body": {"/Type": "/Catalog", "/OpenAction": "2 0 R"}},
            (2, 0): {"kind": "value", "body": {"/S": "/JavaScript", "/JS": "u:var x = 1;"}},
        },
    })
    chain = next(x for x in graph["trigger_to_javascript_chains"] if x.get("inline_javascript"))
    assert chain["trigger"] == "/OpenAction"
    assert chain["javascript_source_object"] == "2 0 R"
