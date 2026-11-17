rule PDF_Static_ActiveContent_Indicators
{
    meta:
        description = "Static indicator for PDF action or script-related tokens; NOT a malware verdict"
        author = "PDF Analyzer lab"
        confidence = "low"

    strings:
        $pdf_js1 = "/JavaScript" ascii
        $pdf_js2 = "/JS" ascii
        $pdf_open = "/OpenAction" ascii
        $pdf_aa = "/AA" ascii
        $pdf_launch = "/Launch" ascii
        $pdf_embedded = "/EmbeddedFile" ascii

    condition:
        uint16be(0) == 0x2550 and 1 of them
}
