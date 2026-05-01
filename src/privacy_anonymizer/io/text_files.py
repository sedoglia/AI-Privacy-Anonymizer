from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class TextFileAdapter(FileAdapter):
    extensions = {".txt", ".md", ".log", ".csv"}

    def read_text(self, path: Path) -> FileContent:
        return FileContent(path.read_text(encoding="utf-8"))

    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        del source, keep_metadata
        destination.write_text(anonymized_text, encoding="utf-8")
        return WriteResult(metadata_stripped=False)

