from __future__ import annotations

import logging
import time
from pathlib import Path
import re

logger = logging.getLogger(__name__)

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult
from privacy_anonymizer.masking import ReplacementSpan


class ImageAdapter(FileAdapter):
    extensions = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp"}

    def read_text(self, path: Path) -> FileContent:
        Image, engine = _import_ocr()
        import numpy as np  # type: ignore[import-not-found]

        logger.info("OCR lettura: %s", path.name)
        t0 = time.perf_counter()
        image = Image.open(path).convert("RGB")
        rows = _normalize_rapidocr_result(engine(np.array(image)))
        text = "\n".join(text_value for _, text_value, _ in rows if text_value)
        logger.info("OCR completato: %d caratteri estratti in %.2fs da %s", len(text), time.perf_counter() - t0, path.name)
        ocr_warnings = []
        if not text.strip():
            ocr_warnings.append("OCR non ha estratto testo dall'immagine.")
        return FileContent(text, warnings=ocr_warnings)

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements: list[ReplacementSpan] | None = None,
        original_text: str | None = None,
        source_content=None,
    ) -> WriteResult:
        Image, ImageDraw, ImageFont = _import_pillow()
        del keep_metadata, original_text, source_content
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
    engine = _load_rapidocr()
    return Image, engine


def _load_rapidocr():
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
    except ImportError:
        try:
            from rapidocr import RapidOCR  # type: ignore[import-not-found]
        except ImportError as exc:
            raise MissingOptionalDependencyError("rapidocr", "documents") from exc
    # rapidocr/utils/log.py adds a StreamHandler and sets propagate=False at module
    # import time. Redirect before instantiating so __init__ messages go to root
    # instead of the console (silent in normal mode, file in --log mode).
    _redirect_rapidocr_logging()
    return RapidOCR()


def _redirect_rapidocr_logging() -> None:
    # Remove all handlers (including the NullHandler/FileHandler pre-added by cli.py)
    # and let messages propagate to root: silent at WARNING level, written to file
    # at DEBUG level (--log mode). This avoids duplicate log entries.
    for name in ("RapidOCR", "rapidocr"):
        logger = logging.getLogger(name)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        logger.propagate = True


def _import_pillow():
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as exc:
        raise MissingOptionalDependencyError("pillow", "documents") from exc
    Image.MAX_IMAGE_PIXELS = None
    return Image, ImageDraw, ImageFont


def _write_coordinate_redacted_image(source: Path, destination: Path, replacements: list[ReplacementSpan]) -> int:
    Image, ImageDraw, ImageFont = _import_pillow()
    _, engine = _import_ocr()
    import numpy as np  # type: ignore[import-not-found]

    image = Image.open(source).convert("RGB")
    draw = ImageDraw.Draw(image)
    rows = _normalize_rapidocr_result(engine(np.array(image)))
    words = _rapidocr_words(rows)
    redacted = 0
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    for replacement in replacements:
        for match in _find_word_matches(words, replacement.original):
            left = min(w["left"] for w in match)
            top = min(w["top"] for w in match)
            right = max(w["left"] + w["width"] for w in match)
            bottom = max(w["top"] + w["height"] for w in match)
            fill = "black" if set(replacement.replacement) == {"█"} else "white"
            draw.rectangle((left, top, right, bottom), fill=fill)
            if fill == "white":
                draw.text((left, top), replacement.replacement, fill="black", font=font)
            redacted += 1
    if redacted:
        image.save(destination)
    return redacted


def _normalize_rapidocr_result(raw) -> list[tuple]:
    """Return a list of (box, text, score) tuples from any RapidOCR API version."""
    if raw is None:
        return []
    boxes = getattr(raw, "boxes", None)
    txts = getattr(raw, "txts", None)
    scores = getattr(raw, "scores", None)
    if boxes is not None and txts is not None:
        scores = scores if scores is not None else [None] * len(txts)
        return list(zip(boxes, txts, scores))
    if isinstance(raw, tuple) and len(raw) >= 1:
        inner = raw[0]
        if not inner:
            return []
        return [tuple(item) for item in inner]
    if isinstance(raw, list):
        return [tuple(item) for item in raw]
    return []


def _rapidocr_words(rows: list[tuple]) -> list[dict]:
    """Convert normalized OCR rows (box, text, score) into per-token word dicts.

    Box is a 4-point polygon; we proportionally allocate width to each whitespace-split token.
    """
    words: list[dict] = []
    for item in rows:
        if len(item) < 2:
            continue
        box, text = item[0], item[1]
        if not text or box is None:
            continue
        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        left, right = min(xs), max(xs)
        top, bottom = min(ys), max(ys)
        line_width = right - left
        line_height = bottom - top
        tokens = text.split()
        if not tokens:
            continue
        total_chars = sum(len(t) for t in tokens) + max(len(tokens) - 1, 0)
        if total_chars <= 0:
            continue
        cursor = left
        for index, token in enumerate(tokens):
            token_chars = len(token) + (1 if index < len(tokens) - 1 else 0)
            token_width = line_width * (token_chars / total_chars)
            words.append(
                {
                    "text": token,
                    "left": cursor,
                    "top": top,
                    "width": token_width,
                    "height": line_height,
                }
            )
            cursor += token_width
    return words


def _find_word_matches(words: list[dict], original: str) -> list[list[dict]]:
    target = [_normalize_token(token) for token in original.split()]
    target = [token for token in target if token]
    if not target:
        return []
    normalized_words = [_normalize_token(word["text"]) for word in words]
    matches: list[list[dict]] = []
    for index in range(0, len(words) - len(target) + 1):
        if normalized_words[index : index + len(target)] == target:
            matches.append(words[index : index + len(target)])
    return matches


def _normalize_token(value: str) -> str:
    return re.sub(r"\W+", "", value, flags=re.UNICODE).lower()
