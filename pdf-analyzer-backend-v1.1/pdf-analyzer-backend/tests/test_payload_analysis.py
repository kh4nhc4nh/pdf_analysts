from pdfanalyzer.payload_analysis import parse_pdfid_output, parse_pdfinfo_output, extract_object_ids


def test_parse_pdfid_output():
    result = parse_pdfid_output("""PDFiD 0.2.10 sample.pdf
 PDF Header: %PDF-1.4
 /JS: 1
 /OpenAction: 0
 obj: 5
""")
    assert result["version"] == "PDFiD 0.2.10 sample.pdf"
    assert result["pdf_header"] == "%PDF-1.4"
    assert result["keyword_counts"]["/JS"] == 1
    assert result["keyword_counts"]["/OpenAction"] == 0


def test_parse_pdfinfo_output():
    result = parse_pdfinfo_output("Pages:          1\nEncrypted:      no\n")
    assert result["Pages"] == "1"
    assert result["Encrypted"] == "no"


def test_extract_object_ids():
    text = "1 0 obj\n<< /Type /Catalog >>\nendobj\n5 0 obj\n<< /JS true >>\nendobj\n"
    assert extract_object_ids(text) == [1, 5]

from pdfanalyzer.payload_analysis import deconcatenate_string_literals, analyze_javascript_bytes


def test_deconcatenate_literal_strings_without_execution():
    source = 'var a = "c" + "m" + "d"; eval(a);'
    results = deconcatenate_string_literals(source)
    assert any(item["reconstructed_string"] == "cmd" for item in results)
    assert results[0]["method"] == "literal_concatenation_only_no_execution"


def test_javascript_analysis_surfaces_concat_and_eval():
    report = analyze_javascript_bytes(
        b'var a = "c" + "m" + "d"; eval(a);',
        source_object="4 0 R",
        source_path="/OpenAction/JS",
    )
    assert report["execution_performed"] is False
    assert any(x["reconstructed_string"] == "cmd" for x in report["string_concatenations"])
    assert report["javascript_indicators"].get("eval", 0) >= 1
    assert report["javascript_indicators"].get("cmd_word", 0) >= 1


def test_javascript_hypotheses_urls_and_obfuscation_are_static_only():
    report = analyze_javascript_bytes(
        b'var a = "c" + "m" + "d"; eval(a); app.launchURL("https://example.invalid/path");',
        source_object="4 0 R",
        source_path="/OpenAction/JS",
    )
    assert report["execution_performed"] is False
    assert "https://example.invalid/path" in report["urls"]
    hypotheses = {item["hypothesis"] for item in report["behavior_hypotheses"]}
    assert "dynamic_decode_or_code_construction" in hypotheses
    assert "external_navigation_or_network_retrieval_candidate" in hypotheses
    assert any(item["reconstructed_string"] == "cmd" for item in report["string_concatenations"])


def test_decoded_base64_candidate_is_inspected_as_text_without_execution():
    import base64
    from pdfanalyzer.payload_analysis import _candidate_summary

    decoded = b'cmd.exe powershell'
    encoded = base64.b64encode(decoded)
    result = _candidate_summary(base64.b64decode(encoded), "base64", 12, "unit-test")
    assert result is not None
    assert result["execution_performed"] is False
    assert result["decoded_text_indicators"].get("cmd_reference", 0) >= 1
    assert result["decoded_text_indicators"].get("PowerShell_reference", 0) >= 1


def test_decodes_hex_and_unicode_escapes_as_data_without_execution():
    from pdfanalyzer.payload_analysis import analyze_javascript_bytes

    report = analyze_javascript_bytes(
        b'var a = "\\x63\\u006d\\x64.exe";',
        source_object="8 0 R",
        source_path="/OpenAction/JS",
    )
    decoded = [item["decoded_string"] for item in report["decoded_string_literals"]]
    assert any(value == "cmd.exe" for value in decoded)
    assert report["javascript_indicators"].get("cmd_reference", 0) >= 1
    assert report["execution_performed"] is False


def test_unpaired_unicode_surrogate_is_safe_for_json_text():
    from pdfanalyzer.payload_analysis import _decode_js_string_literal

    decoded = _decode_js_string_literal('"\\uD800"')
    assert decoded == "\ufffd"
    decoded_pair = _decode_js_string_literal('"\\uD83D\\uDE00"')
    assert decoded_pair == "😀"


def test_decoded_base64_url_is_correlated_with_launch_url_hypothesis():
    import base64
    from pdfanalyzer.payload_analysis import analyze_javascript_bytes

    encoded = base64.b64encode(b"https://example.invalid/").decode("ascii")
    source = f'app.launchURL(atob("{encoded}"));'.encode("ascii")
    report = analyze_javascript_bytes(source, source_object="2 0 R", source_path="/OpenAction/JS")
    assert any(url.startswith("https://example.invalid/") for url in report["urls"])
    assert any(
        item["hypothesis"] == "external_navigation_or_network_retrieval_candidate"
        for item in report["behavior_hypotheses"]
    )
