from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileContent


class DoclingTextExtractor:
    def read_text(self, path: Path) -> FileContent:
        try:
            from docling.document_converter import DocumentConverter
        except ImportError as exc:
            raise MissingOptionalDependencyError("docling", "docling") from exc

        converter = DocumentConverter()
        result = converter.convert(str(path))
        document = result.document
        if hasattr(document, "export_to_markdown"):
            text = document.export_to_markdown()
        elif hasattr(document, "export_to_text"):
            text = document.export_to_text()
        else:
            text = str(document)
        return FileContent(text, warnings=["Parsing eseguito con Docling."])
