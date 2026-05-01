from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult
from privacy_anonymizer.masking import ReplacementSpan


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

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements: list[ReplacementSpan] | None = None,
        original_text: str | None = None,
    ) -> WriteResult:
        del original_text
        if replacements:
            try:
                redacted = _write_coordinate_redacted_pdf(source, destination, replacements, keep_metadata)
            except MissingOptionalDependencyError:
                redacted = 0
            if redacted:
                return WriteResult(
                    warnings=[f"PDF redatto a coordinate con PyMuPDF: {redacted} occorrenze coperte."],
                    metadata_stripped=not keep_metadata,
                )

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


def _write_coordinate_redacted_pdf(
    source: Path,
    destination: Path,
    replacements: list[ReplacementSpan],
    keep_metadata: bool,
) -> int:
    fitz = _import_fitz()
    document = fitz.open(source)
    redaction_count = 0
    for page in document:
        for replacement in replacements:
            original = replacement.original.strip()
            if not original:
                continue
            for rect in page.search_for(original):
                fill = (0, 0, 0) if set(replacement.replacement) == {"█"} else (1, 1, 1)
                text = "" if fill == (0, 0, 0) else replacement.replacement
                page.add_redact_annot(rect, text=text, fill=fill)
                redaction_count += 1
        if redaction_count:
            page.apply_redactions()
    if not keep_metadata:
        document.set_metadata({})
    document.save(destination, garbage=4, deflate=True)
    document.close()
    return redaction_count


def _import_fitz():
    try:
        import fitz
    except ImportError as exc:
        raise MissingOptionalDependencyError("pymupdf", "documents") from exc
    return fitz
