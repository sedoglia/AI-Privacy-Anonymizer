from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class PdfAdapter(FileAdapter):
    extensions = {".pdf"}

    def read_text(self, path: Path) -> FileContent:
        PdfReader, _ = _import_pypdf()
        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        warnings = []
        if not any(page.strip() for page in pages):
            warnings.append("PDF senza testo selezionabile: usa OCR immagini/PDF scansionati in un passaggio dedicato.")
        return FileContent("\n\n".join(pages), warnings=warnings)

    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        del source
        canvas, pagesizes = _import_reportlab()
        c = canvas.Canvas(str(destination), pagesize=pagesizes.A4)
        width, height = pagesizes.A4
        margin = 42
        y = height - margin
        for line in _wrap_lines(anonymized_text, max_chars=95):
            if y < margin:
                c.showPage()
                y = height - margin
            c.drawString(margin, y, line)
            y -= 14
        c.save()
        return WriteResult(
            warnings=["PDF MVP: output PDF ricostruito come testo anonimizzato, layout originale non preservato."],
            metadata_stripped=not keep_metadata,
        )


def _wrap_lines(text: str, max_chars: int) -> list[str]:
    lines: list[str] = []
    for original_line in text.splitlines() or [""]:
        line = original_line
        while len(line) > max_chars:
            split_at = line.rfind(" ", 0, max_chars)
            if split_at <= 0:
                split_at = max_chars
            lines.append(line[:split_at])
            line = line[split_at:].lstrip()
        lines.append(line)
    return lines


def _import_pypdf():
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError as exc:
        raise MissingOptionalDependencyError("pypdf", "documents") from exc
    return PdfReader, PdfWriter


def _import_reportlab():
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib import pagesizes
    except ImportError as exc:
        raise MissingOptionalDependencyError("reportlab", "documents") from exc
    return canvas, pagesizes

