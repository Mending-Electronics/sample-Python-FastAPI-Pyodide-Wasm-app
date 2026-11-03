import json
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from vba_audit.analyzer import analyze_source, analyze_workbook
from vba_audit.api import LocalAuditAPI
from vba_audit.database import ReportStore


class AnalyzerTests(unittest.TestCase):
    def test_source_scan_reports_indicators_and_static_character_decoding(self):
        source = """
Sub AutoOpen()
    CreateObject("WScript.Shell").Run Chr(99) & ChrW(109) & "d"
    Set request = CreateObject("MSXML2.XMLHTTP")
    SaveSetting "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "x", "y"
End Sub
"""

        report = analyze_source("module.bas", source)

        self.assertEqual(report["risk"], "high")
        self.assertEqual(report["dridex"]["status"], "suspicious")
        self.assertIn('Run "cmd"', report["deobfuscation"]["preview"])
        self.assertGreaterEqual(report["deobfuscation"]["replacement_count"], 2)
        self.assertEqual(
            {finding["identifier"] for finding in report["findings"]},
            {"VBA-NETWORK", "VBA-SHELL", "VBA-PERSISTENCE", "VBA-ENCODING"},
        )

    def test_source_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "2 Mio"):
            analyze_source("large.bas", "A" * (2 * 1024 * 1024 + 1))

    def test_string_literals_are_not_decoded_as_code(self):
        report = analyze_source("module.bas", 'MsgBox "Chr(65)": value = Chr(66)')

        self.assertIn('MsgBox "Chr(65)": value = "B"', report["deobfuscation"]["preview"])
        self.assertEqual(report["deobfuscation"]["replacement_count"], 1)

    def test_workbook_inspection_reports_but_does_not_change_protection(self):
        content = BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr(
                "xl/workbook.xml",
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<workbookProtection lockStructure="1"/></workbook>',
            )
            archive.writestr(
                "xl/worksheets/sheet1.xml",
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheetProtection sheet="1"/></worksheet>',
            )
            archive.writestr("xl/vbaProject.bin", b"binary")

        report = analyze_workbook("book.xlsm", content.getvalue())

        self.assertEqual(report["protections"]["protected_sheets"], ["sheet1.xml"])
        self.assertTrue(report["protections"]["workbook_structure_locked"])
        self.assertTrue(report["protections"]["vba_project_embedded"])
        self.assertFalse(report["protections"]["vba_project_lock_inspected"])

    def test_invalid_workbook_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "XLSX ou XLSM"):
            analyze_workbook("bad.xlsx", b"not a workbook")


class ReportStoreTests(unittest.TestCase):
    def test_reports_round_trip_through_sqlite_snapshot(self):
        store = ReportStore()
        report = analyze_source("test.bas", "Sub Test(): End Sub")
        saved = store.add(report)
        restored = ReportStore()
        restored.restore_base64(store.serialize_base64())

        self.assertEqual(restored.get(saved["id"])["sha256"], report["sha256"])
        self.assertEqual(restored.list()[0]["filename"], "test.bas")

    def test_api_persists_metadata_without_retaining_source_preview(self):
        api = LocalAuditAPI()
        result = json.loads(
            api.analyze_source_json("module.bas", "Sub Secret(): MsgBox \"sensitive\" : End Sub")
        )

        self.assertIn("sensitive", result["deobfuscation"]["preview"])
        persisted = api.store.get(result["id"])
        self.assertEqual(persisted["deobfuscation"]["preview"], "")


class OpenApiTests(unittest.TestCase):
    def test_swagger_document_lists_local_api_contract(self):
        path = Path(__file__).parents[1] / "web" / "openapi.json"
        document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(document["openapi"], "3.1.0")
        self.assertIn("/api/analyze/source", document["paths"])
        self.assertIn("/api/analyze/workbook", document["paths"])
        self.assertIn("/api/reports", document["paths"])


if __name__ == "__main__":
    unittest.main()
