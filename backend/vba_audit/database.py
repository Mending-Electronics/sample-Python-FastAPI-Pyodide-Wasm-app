from __future__ import annotations

import json
import sqlite3
from typing import Any


class ReportStore:
    def __init__(self) -> None:
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                risk TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    def add(self, report: dict[str, Any]) -> dict[str, Any]:
        cursor = self._connection.execute(
            """
            INSERT INTO reports (filename, sha256, analyzed_at, risk, report_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                report["filename"],
                report["sha256"],
                report["analyzed_at"],
                report["risk"],
                json.dumps(report, ensure_ascii=False),
            ),
        )
        self._connection.commit()
        return {"id": cursor.lastrowid, **report}

    def list(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            """
            SELECT id, filename, sha256, analyzed_at, risk
            FROM reports
            ORDER BY id DESC
            """
        )
        return [dict(row) for row in rows]

    def get(self, report_id: int) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT id, report_json FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row["id"], **json.loads(row["report_json"])}

    def serialize_base64(self) -> str:
        import base64

        return base64.b64encode(self._connection.serialize()).decode("ascii")

    def restore_base64(self, value: str) -> None:
        import base64

        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError("La sauvegarde SQLite locale est invalide.") from error
        self._connection.deserialize(raw)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                risk TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        self._connection.commit()
