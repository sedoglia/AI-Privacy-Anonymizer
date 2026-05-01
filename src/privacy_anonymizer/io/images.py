from __future__ import annotations

from pathlib import Path
import re

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult
from privacy_anonymizer.masking import ReplacementSpan


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

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements: list[ReplacementSpan] | None = None,
        original_text: str | None = None,
    ) -> WriteResult:
        Image, ImageDraw, ImageFont = _import_pillow()
        del keep_metadata, original_text
        if replacements:
            try:
                redacted = _write_coordinate_redacted_image(source, destination, replacements)
            except Exception:
                redacted = 0
            if redacted:
                return WriteResult(
                    warnings=[f"Immagine redatta a coordinate OCR: {redacted} occorrenze coperte."],
                    metadata_stripped=True,
                )

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


def _write_coordinate_redacted_image(source: Path, destination: Path, replacements: list[ReplacementSpan]) -> int:
    Image, ImageDraw, ImageFont = _import_pillow()
    _, pytesseract = _import_ocr()
    image = Image.open(source).convert("RGB")
    draw = ImageDraw.Draw(image)
    data = pytesseract.image_to_data(image, lang="ita+eng", output_type=pytesseract.Output.DICT)
    words = [_OcrWord.from_data(data, index) for index in range(len(data.get("text", [])))]
    words = [word for word in words if word.text]
    redacted = 0
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    for replacement in replacements:
        for match in _find_word_matches(words, replacement.original):
            left = min(word.left for word in match)
            top = min(word.top for word in match)
            right = max(word.left + word.width for word in match)
            bottom = max(word.top + word.height for word in match)
            fill = "black" if set(replacement.replacement) == {"█"} else "white"
            draw.rectangle((left, top, right, bottom), fill=fill)
            if fill == "white":
                draw.text((left, top), replacement.replacement, fill="black", font=font)
            redacted += 1
    if redacted:
        image.save(destination)
    return redacted


class _OcrWord:
    def __init__(self, text: str, left: int, top: int, width: int, height: int) -> None:
        self.text = text
        self.left = left
        self.top = top
        self.width = width
        self.height = height

    @classmethod
    def from_data(cls, data: dict, index: int) -> "_OcrWord":
        return cls(
            text=str(data["text"][index]).strip(),
            left=int(data["left"][index]),
            top=int(data["top"][index]),
            width=int(data["width"][index]),
            height=int(data["height"][index]),
        )


def _find_word_matches(words: list[_OcrWord], original: str) -> list[list[_OcrWord]]:
    target = [_normalize_token(token) for token in original.split()]
    target = [token for token in target if token]
    if not target:
        return []
    normalized_words = [_normalize_token(word.text) for word in words]
    matches: list[list[_OcrWord]] = []
    for index in range(0, len(words) - len(target) + 1):
        if normalized_words[index : index + len(target)] == target:
            matches.append(words[index : index + len(target)])
    return matches


def _normalize_token(value: str) -> str:
    return re.sub(r"\W+", "", value, flags=re.UNICODE).lower()
