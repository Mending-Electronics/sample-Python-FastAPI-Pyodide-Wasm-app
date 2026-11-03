from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from xml.etree import ElementTree

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_WORKBOOK_BYTES = 50 * 1024 * 1024
MAX_WORKBOOK_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_WORKBOOK_XML_BYTES = 5 * 1024 * 1024
MAX_WORKBOOK_ENTRIES = 10_000


@dataclass(frozen=True)
class Finding:
    identifier: str
    severity: str
    title: str
    detail: str
    matches: int


_INDICATORS: tuple[tuple[str, str, str, str], ...] = (
    (
        "VBA-NETWORK",
        "medium",
        "Réseau depuis VBA",
        r"\b(?:XMLHTTP|WinHttpRequest|URLDownloadToFile|InternetOpenUrl)\b",
    ),
    (
        "VBA-SHELL",
        "medium",
        "Exécution de commande",
        r"\b(?:WScript\.Shell|Shell\s*\(|CreateProcess(?:A|W)?)\b",
    ),
    (
        "VBA-PERSISTENCE",
        "high",
        "Indicateur de persistance",
        r"CurrentVersion\\Run|\\Startup\\|schtasks(?:\.exe)?",
    ),
    (
        "VBA-INJECTION",
        "high",
        "API d’allocation ou d’exécution mémoire",
        r"\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread)\b",
    ),
    (
        "VBA-ENCODING",
        "low",
        "Construction de chaînes potentiellement obfusquée",
        r"(?:\bChrW?\$?\s*\(|\bStrReverse\s*\(|\bBase64\b)",
    ),
)

_DRIDEX_RULES = (
    (
        "network",
        re.compile(
            r"\b(?:XMLHTTP|WinHttpRequest|URLDownloadToFile|InternetOpenUrl)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command",
        re.compile(r"\b(?:WScript\.Shell|Shell\s*\(|CreateProcess(?:A|W)?)\b", re.IGNORECASE),
    ),
    (
        "persistence",
        re.compile(r"CurrentVersion\\Run|\\Startup\\|schtasks(?:\.exe)?", re.IGNORECASE),
    ),
    (
        "obfuscation",
        re.compile(
            r"(?:\bChrW?\$?\s*\(|\bStrReverse\s*\(|\bBase64\b)",
            re.IGNORECASE,
        ),
    ),
)


def _validate_text(filename: str, source: str) -> None:
    if not filename.strip():
        raise ValueError("Le nom du fichier est obligatoire.")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Le fichier VBA dépasse la limite de 2 Mio.")


def deobfuscate_vba(source: str) -> tuple[str, int]:
    """Resolve constant Chr/ChrW expressions without evaluating VBA."""
    pattern = re.compile(
        r"(?<![\"'])\bChrW?\$?\s*\(\s*(\d{1,5})\s*\)(?![\"'])",
        re.IGNORECASE,
    )
    atom = r'"(?:[^"]|"")*"|ChrW?\$?\s*\(\s*\d{1,5}\s*\)'
    chain = re.compile(rf"(?<![\w])(?:{atom})(?:\s*&\s*(?:{atom}))+", re.IGNORECASE)
    replacements = 0

    def decode_chain(match: re.Match[str]) -> str:
        nonlocal replacements
        parts = re.split(r"\s*&\s*", match.group(0))
        if not any(re.match(r"\s*ChrW?\$?\s*\(", part, re.IGNORECASE) for part in parts):
            return match.group(0)
        decoded: list[str] = []
        call_count = 0
        for part in parts:
            character = pattern.fullmatch(part.strip())
            if character:
                value = int(character.group(1))
                if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                    return match.group(0)
                decoded.append(chr(value))
                call_count += 1
            else:
                literal = re.fullmatch(r'"((?:[^"]|"")*)"', part.strip())
                if literal is None:
                    return match.group(0)
                decoded.append(literal.group(1).replace('""', '"'))
        value = "".join(decoded)
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            return match.group(0)
        replacements += call_count
        return f'"{value.replace(chr(34), chr(34) * 2)}"'

    def replace(match: re.Match[str]) -> str:
        nonlocal replacements
        value = int(match.group(1))
        if (
            value > 0x10FFFF
            or 0xD800 <= value <= 0xDFFF
            or value < 32
            or value == 127
        ):
            return match.group(0)
        replacements += 1
        return f'"{chr(value).replace(chr(34), chr(34) * 2)}"'

    decoded_source = chain.sub(decode_chain, source)
    return pattern.sub(replace, decoded_source), replacements


def _findings(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for identifier, severity, title, expression in _INDICATORS:
        matches = len(re.findall(expression, source, re.IGNORECASE))
        if matches:
            findings.append(
                Finding(
                    identifier=identifier,
                    severity=severity,
                    title=title,
                    detail=f"{matches} occurrence(s) statique(s) détectée(s).",
                    matches=matches,
                )
            )
    return findings


def _dridex_assessment(source: str) -> dict[str, Any]:
    categories = [name for name, expression in _DRIDEX_RULES if expression.search(source)]
    likely = (
        "network" in categories
        and "command" in categories
        and ("obfuscation" in categories or "persistence" in categories)
    )
    return {
        "status": "suspicious" if likely else "not_indicated",
        "matched_categories": categories,
        "message": (
            "Combinaison d’indicateurs compatible avec un comportement de type Dridex; "
            "ce résultat heuristique n’est pas une attribution."
            if likely
            else "Aucune combinaison d’indicateurs Dridex suffisante détectée. "
            "Cela ne prouve pas l’absence de malware."
        ),
    }


def _report(filename: str, source: str) -> dict[str, Any]:
    _validate_text(filename, source)
    decoded, replacements = deobfuscate_vba(source)
    findings = _findings(source)
    return {
        "filename": filename,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "risk": "high" if any(item.severity == "high" for item in findings) else (
            "medium" if findings else "low"
        ),
        "findings": [asdict(item) for item in findings],
        "dridex": _dridex_assessment(source),
        "deobfuscation": {
            "replacement_count": replacements,
            "preview": decoded,
        },
        "limitations": [
            "Analyse statique uniquement : aucun code VBA n’est exécuté.",
            "Les heuristiques ne remplacent pas une analyse antivirus ou sandbox.",
        ],
    }


def analyze_source(filename: str, source: str) -> dict[str, Any]:
    return _report(filename, source)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _inspect_protections(archive: zipfile.ZipFile) -> dict[str, Any]:
    protected_sheets: list[str] = []
    workbook_structure_locked = False
    xml_total = 0

    for info in archive.infolist():
        name = info.filename
        is_workbook_xml = name == "xl/workbook.xml"
        is_sheet_xml = (
            name.startswith("xl/worksheets/")
            and name.endswith(".xml")
            and "/" not in name[len("xl/worksheets/") :]
        )
        if not (is_workbook_xml or is_sheet_xml):
            continue
        if info.file_size > MAX_WORKBOOK_XML_BYTES:
            raise ValueError("Un fichier XML du classeur dépasse la limite de taille autorisée.")
        xml_total += info.file_size
        if xml_total > MAX_WORKBOOK_EXPANDED_BYTES:
            raise ValueError("Le contenu décompressé du classeur dépasse la limite autorisée.")
        try:
            root = ElementTree.fromstring(archive.read(info))
        except ElementTree.ParseError as error:
            raise ValueError(f"XML de classeur invalide : {name}") from error
        for element in root.iter():
            if _local_name(element.tag) == "sheetProtection" and is_sheet_xml:
                protected_sheets.append(name.rsplit("/", 1)[-1])
            if _local_name(element.tag) == "workbookProtection" and is_workbook_xml:
                workbook_structure_locked = True

    return {
        "protected_sheets": protected_sheets,
        "workbook_structure_locked": workbook_structure_locked,
        "vba_project_embedded": "xl/vbaProject.bin" in archive.namelist(),
        "vba_project_lock_inspected": False,
        "note": (
            "Les marqueurs de protection sont uniquement signalés. "
            "Aucune protection n’est supprimée ni contournée."
        ),
    }


def analyze_workbook(filename: str, content: bytes) -> dict[str, Any]:
    if not filename.strip():
        raise ValueError("Le nom du fichier est obligatoire.")
    if len(content) > MAX_WORKBOOK_BYTES:
        raise ValueError("Le classeur dépasse la limite de 50 Mio.")
    if not zipfile.is_zipfile(BytesIO(content)):
        raise ValueError("Format non pris en charge : fournir un fichier XLSX ou XLSM valide.")

    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_WORKBOOK_ENTRIES:
                raise ValueError("Le classeur contient trop d’éléments ZIP.")
            total_size = sum(info.file_size for info in entries)
            if total_size > MAX_WORKBOOK_EXPANDED_BYTES:
                raise ValueError("Le classeur décompressé dépasse la limite de 100 Mio.")
            if "xl/workbook.xml" not in archive.namelist():
                raise ValueError("Le fichier ZIP ne contient pas de classeur Excel.")
            protections = _inspect_protections(archive)
    except zipfile.BadZipFile as error:
        raise ValueError("Le fichier XLSX/XLSM est endommagé.") from error

    result = {
        "filename": filename,
        "sha256": hashlib.sha256(content).hexdigest(),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "risk": "low",
        "findings": [],
        "dridex": {
            "status": "not_scanned",
            "matched_categories": [],
            "message": (
                "Le projet VBA intégré est binaire et n’a pas été analysé. "
                "Exportez les modules en .bas/.cls pour l’analyse statique."
            ),
        },
        "protections": protections,
        "limitations": [
            "Seuls les marqueurs de protection XLSX/XLSM sont lus; ils ne sont pas modifiés.",
            "Les modules VBA intégrés ne sont pas extraits ni exécutés.",
        ],
    }
    return result
