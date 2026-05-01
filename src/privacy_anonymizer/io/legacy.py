from __future__ import annotations

import re
from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class RtfAdapter(FileAdapter):
    extensions = {".rtf"}

    def read_text(self, path: Path) -> FileContent:
        raw = path.read_text(encoding="utf-8", errors="ignore")
        try:
            from striprtf.striprtf import rtf_to_text
        except ImportError:
            return FileContent(_fallback_rtf_to_text(raw), warnings=["striprtf non installato: usato parser RTF minimale."])
        return FileContent(rtf_to_text(raw))

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements=None,
        original_text: str | None = None,
    ) -> WriteResult:
        del source, keep_metadata, replacements, original_text
        escaped = anonymized_text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
        destination.write_text(r"{\rtf1\ansi " + escaped.replace("\n", r"\par ") + "}", encoding="utf-8")
        return WriteResult(warnings=["RTF ricostruito con formattazione semplificata."], metadata_stripped=True)


class LegacyDocAdapter(FileAdapter):
    extensions = {".doc"}

    def output_suffix(self, source: Path) -> str:
        del source
        return ".txt"

    def read_text(self, path: Path) -> FileContent:
        return FileContent(_best_effort_binary_text(path.read_bytes()), warnings=["DOC legacy letto in modalità best-effort; installa LibreOffice per conversioni più fedeli."])

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements=None,
        original_text: str | None = None,
    ) -> WriteResult:
        del source, keep_metadata, replacements, original_text
        destination.write_text(anonymized_text, encoding="utf-8")
        return WriteResult(warnings=["Output DOC legacy prodotto come .txt anonimizzato."], metadata_stripped=True)


class LegacyXlsAdapter(FileAdapter):
    extensions = {".xls"}

    def output_suffix(self, source: Path) -> str:
        del source
        return ".txt"

    def read_text(self, path: Path) -> FileContent:
        try:
            import xlrd
        except ImportError as exc:
            raise MissingOptionalDependencyError("xlrd", "documents") from exc
        workbook = xlrd.open_workbook(str(path))
        values: list[str] = []
        for sheet in workbook.sheets():
            values.append(sheet.name)
            for row_index in range(sheet.nrows):
                for value in sheet.row_values(row_index):
                    if isinstance(value, str) and value:
                        values.append(value)
        return FileContent("\n".join(values))

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements=None,
        original_text: str | None = None,
    ) -> WriteResult:
        del source, keep_metadata, replacements, original_text
        destination.write_text(anonymized_text, encoding="utf-8")
        return WriteResult(warnings=["Output XLS legacy prodotto come .txt anonimizzato."], metadata_stripped=True)


def _fallback_rtf_to_text(raw: str) -> str:
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", raw)
    text = re.sub(r"\\[a-zA-Z]+\d* ?", "", text)
    text = text.replace("{", "").replace("}", "")
    return re.sub(r"\s+", " ", text).strip()


def _best_effort_binary_text(data: bytes) -> str:
    text = data.decode("latin-1", errors="ignore")
    chunks = re.findall(r"[A-Za-z0-9À-ÿ@._:+/\-\s]{4,}", text)
    return "\n".join(chunk.strip() for chunk in chunks if chunk.strip())
