from __future__ import annotations

import re
from pathlib import Path

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

    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        del source, keep_metadata
        escaped = anonymized_text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
        destination.write_text(r"{\rtf1\ansi " + escaped.replace("\n", r"\par ") + "}", encoding="utf-8")
        return WriteResult(warnings=["RTF ricostruito con formattazione semplificata."], metadata_stripped=True)


def _fallback_rtf_to_text(raw: str) -> str:
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", raw)
    text = re.sub(r"\\[a-zA-Z]+\d* ?", "", text)
    text = text.replace("{", "").replace("}", "")
    return re.sub(r"\s+", " ", text).strip()

