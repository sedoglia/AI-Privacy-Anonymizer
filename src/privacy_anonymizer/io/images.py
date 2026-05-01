from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class ImageAdapter(FileAdapter):
    extensions = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp"}

    def read_text(self, path: Path) -> FileContent:
        Image, pytesseract = _import_ocr()
        image = Image.open(path)
        text = pytesseract.image_to_string(image, lang="ita+eng")
        warnings = []
        if not text.strip():
            warnings.append("OCR non ha estratto testo dall'immagine.")
        return FileContent(text, warnings=warnings)

    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        Image, ImageDraw, ImageFont = _import_pillow()
        del keep_metadata
        image = Image.open(source).convert("RGB")
        output = Image.new("RGB", image.size, "white")
        draw = ImageDraw.Draw(output)
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None
        y = 10
        for line in _wrap_lines(anonymized_text, max_chars=max(20, image.width // 8)):
            draw.text((10, y), line, fill="black", font=font)
            y += 14
        output.save(destination)
        return WriteResult(
            warnings=["Immagine MVP: output ricostruito come immagine con testo OCR anonimizzato, layout originale non preservato."],
            metadata_stripped=True,
        )


def _wrap_lines(text: str, max_chars: int) -> list[str]:
    lines: list[str] = []
    for original_line in text.splitlines() or [""]:
        line = original_line
        while len(line) > max_chars:
            lines.append(line[:max_chars])
            line = line[max_chars:]
        lines.append(line)
    return lines


def _import_ocr():
    Image, _, _ = _import_pillow()
    try:
        import pytesseract
    except ImportError as exc:
        raise MissingOptionalDependencyError("pytesseract", "documents") from exc
    return Image, pytesseract


def _import_pillow():
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise MissingOptionalDependencyError("pillow", "documents") from exc
    return Image, ImageDraw, ImageFont

