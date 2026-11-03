from __future__ import annotations

import json
from typing import Any

from .analyzer import analyze_source, analyze_workbook
from .database import ReportStore

class LocalAuditAPI:
    """Python API facade invoked by Vue through Pyodide."""

    def __init__(self) -> None:
        self.store = ReportStore()

    def status_json(self) -> str:
        return json.dumps({"status": "ready", "storage": "sqlite"}, ensure_ascii=False)

    def analyze_source_json(self, filename: str, source: str) -> str:
        report = analyze_source(filename, source)
        stored_report = {
            **report,
            "deobfuscation": {
                "replacement_count": report["deobfuscation"]["replacement_count"],
                "preview": "",
            },
        }
        return json.dumps(
            {**self.store.add(stored_report), "deobfuscation": report["deobfuscation"]},
            ensure_ascii=False,
        )

    def analyze_workbook_path_json(self, filename: str, path: str) -> str:
        with open(path, "rb") as file:
            report = analyze_workbook(filename, file.read())
        return json.dumps(self.store.add(report), ensure_ascii=False)

    def reports_json(self) -> str:
        return json.dumps(self.store.list(), ensure_ascii=False)

    def report_json(self, report_id: int) -> str:
        return json.dumps(self.store.get(report_id), ensure_ascii=False)

    def database_base64(self) -> str:
        return self.store.serialize_base64()

    def restore_database_base64(self, value: str) -> None:
        self.store.restore_base64(value)

def create_api() -> LocalAuditAPI:
    return LocalAuditAPI()
