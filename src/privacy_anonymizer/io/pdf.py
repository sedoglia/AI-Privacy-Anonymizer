from __future__ import annotations

import re
from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult
from privacy_anonymizer.masking import ReplacementSpan


OCR_RENDER_DPI = 300


class PdfAdapter(FileAdapter):
    extensions = {".pdf"}

    def read_text(self, path: Path) -> FileContent:
        PdfReader, _ = _import_pypdf()
        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        warnings: list[str] = []
        if not any(page.strip() for page in pages):
            ocr_text, ocr_warnings = _ocr_pdf_text(path)
            warnings.extend(ocr_warnings)
            if ocr_text.strip():
                return FileContent(ocr_text, warnings=warnings)
            warnings.append(
                "PDF senza testo selezionabile e OCR non disponibile/efficace: "
                "installa l'extra [documents] o [recommended] per abilitare RapidOCR."
            )
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
        del original_text, anonymized_text
        is_scanned = _pdf_is_scanned(source)

        if not is_scanned:
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
            return _passthrough_pdf(
                source,
                destination,
                keep_metadata,
                "PDF con testo selezionabile ma nessuna occorrenza redigibile trovata: copia con metadata gestiti.",
            )

        if replacements:
            try:
                redacted_ocr = _write_ocr_redacted_pdf(source, destination, replacements, keep_metadata)
            except MissingOptionalDependencyError:
                redacted_ocr = 0
            if redacted_ocr:
                return WriteResult(
                    warnings=[f"PDF scansionato redatto via OCR (RapidOCR): {redacted_ocr} occorrenze coperte."],
                    metadata_stripped=not keep_metadata,
                )
            return _passthrough_pdf(
                source,
                destination,
                keep_metadata,
                (
                    "PDF scansionato: nessuna entità localizzata via OCR (token/bounding box non corrispondenti). "
                    "Output = copia del PDF originale con metadata gestiti. "
                    "Verifica manualmente o riesegui con un OCR migliorato."
                ),
            )

        return _passthrough_pdf(
            source,
            destination,
            keep_metadata,
            "PDF scansionato: nessuna entità rilevata. Copia del PDF originale con metadata gestiti.",
        )


def _pdf_is_scanned(path: Path) -> bool:
    """Return True if no page has a meaningful text layer."""
    try:
        PdfReader, _ = _import_pypdf()
    except MissingOptionalDependencyError:
        return False
    try:
        reader = PdfReader(str(path))
        for page in reader.pages:
            text = page.extract_text() or ""
            if text.strip():
                return False
    except Exception:
        return False
    return True


def _passthrough_pdf(
    source: Path,
    destination: Path,
    keep_metadata: bool,
    warning: str,
) -> WriteResult:
    """Copy the source PDF to destination, optionally stripping metadata via PyMuPDF."""
    try:
        fitz = _import_fitz()
        document = fitz.open(source)
        if not keep_metadata:
            document.set_metadata({})
        document.save(destination, garbage=4, deflate=True)
        document.close()
    except MissingOptionalDependencyError:
        destination.write_bytes(Path(source).read_bytes())
    return WriteResult(
        warnings=[warning],
        metadata_stripped=not keep_metadata,
    )


def _import_pypdf():
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError as exc:
        raise MissingOptionalDependencyError("pypdf", "documents") from exc
    return PdfReader, PdfWriter


def _import_fitz():
    try:
        import fitz
    except ImportError as exc:
        raise MissingOptionalDependencyError("pymupdf", "documents") from exc
    return fitz


def _import_pillow():
    try:
        from PIL import Image
    except ImportError as exc:
        raise MissingOptionalDependencyError("pillow", "documents") from exc
    Image.MAX_IMAGE_PIXELS = None
    return Image


def _ocr_pdf_text(path: Path) -> tuple[str, list[str]]:
    """Read text from a scanned PDF via RapidOCR (preferred) with Docling as last resort."""
    warnings: list[str] = []

    text = _try_rapidocr_pdf(path, warnings)
    if text and text.strip():
        return text, warnings

    text = _try_docling_extract(path, warnings)
    return text, warnings


def _try_docling_extract(path: Path, warnings: list[str]) -> str:
    try:
        from docling.document_converter import DocumentConverter
    except ImportError:
        return ""
    try:
        converter = DocumentConverter()
        result = converter.convert(str(path))
        document = result.document
        if hasattr(document, "export_to_text"):
            text = document.export_to_text()
        elif hasattr(document, "export_to_markdown"):
            text = document.export_to_markdown()
        else:
            text = str(document)
        if text and text.strip():
            warnings.append(
                "PDF letto con Docling come ultimo fallback: i confini di parola "
                "potrebbero essere imperfetti per scansioni complesse."
            )
        return text or ""
    except Exception as exc:
        warnings.append(f"Docling fallback fallito: {exc}")
        return ""


def _try_rapidocr_pdf(path: Path, warnings: list[str]) -> str:
    try:
        fitz = _import_fitz()
        Image = _import_pillow()
    except MissingOptionalDependencyError as exc:
        warnings.append(f"OCR PDF non disponibile: dipendenza mancante ({exc}).")
        return ""

    engine = _load_rapidocr(warnings)
    if engine is None:
        return ""

    import io as _io
    import numpy as np  # type: ignore[import-not-found]

    document = fitz.open(path)
    pages_text: list[str] = []
    try:
        for page in document:
            pix = page.get_pixmap(dpi=OCR_RENDER_DPI, alpha=False)
            image = Image.open(_io.BytesIO(pix.tobytes("png"))).convert("RGB")
            try:
                rows = _normalize_rapidocr_result(engine(np.array(image)))
            except Exception as exc:  # pragma: no cover - defensive
                warnings.append(f"RapidOCR pagina fallita: {exc}")
                continue
            if not rows:
                continue
            page_lines = [text for _, text, _ in rows if text]
            pages_text.append("\n".join(page_lines))
    finally:
        document.close()
    text = "\n\n".join(pages_text)
    if text.strip():
        warnings.append("PDF scansionato letto con RapidOCR.")
    return text


def _load_rapidocr(warnings: list[str] | None = None):
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
        return RapidOCR()
    except ImportError:
        pass
    try:
        from rapidocr import RapidOCR  # type: ignore[import-not-found]
        return RapidOCR()
    except ImportError:
        if warnings is not None:
            warnings.append("RapidOCR non installato: nessun fallback OCR disponibile.")
        return None
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"Inizializzazione RapidOCR fallita: {exc}")
        return None


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


def _write_ocr_redacted_pdf(
    source: Path,
    destination: Path,
    replacements: list[ReplacementSpan],
    keep_metadata: bool,
) -> int:
    """Redact a scanned PDF by locating word boxes via RapidOCR on each rendered page."""
    fitz = _import_fitz()
    Image = _import_pillow()

    engine = _load_rapidocr()
    if engine is None:
        return 0

    import io as _io
    import numpy as np  # type: ignore[import-not-found]

    document = fitz.open(source)
    redaction_count = 0
    try:
        for page in document:
            pix = page.get_pixmap(dpi=OCR_RENDER_DPI, alpha=False)
            image = Image.open(_io.BytesIO(pix.tobytes("png"))).convert("RGB")
            try:
                rows = _normalize_rapidocr_result(engine(np.array(image)))
            except Exception:
                continue
            if not rows:
                continue

            words = _rapidocr_words(rows)
            if not words:
                continue

            scale_x = page.rect.width / pix.width if pix.width else 1.0
            scale_y = page.rect.height / pix.height if pix.height else 1.0

            page_redactions = 0
            for replacement in replacements:
                original = replacement.original.strip()
                if not original:
                    continue
                for match in _find_word_matches(words, original):
                    left = min(w["left"] for w in match) * scale_x
                    top = min(w["top"] for w in match) * scale_y
                    right = max(w["left"] + w["width"] for w in match) * scale_x
                    bottom = max(w["top"] + w["height"] for w in match) * scale_y
                    rect = fitz.Rect(left, top, right, bottom)
                    fill = (0, 0, 0) if set(replacement.replacement) == {"█"} else (1, 1, 1)
                    text = "" if fill == (0, 0, 0) else replacement.replacement
                    page.add_redact_annot(rect, text=text, fill=fill)
                    page_redactions += 1
            if page_redactions:
                page.apply_redactions()
                redaction_count += page_redactions
        if not keep_metadata:
            document.set_metadata({})
        if redaction_count:
            document.save(destination, garbage=4, deflate=True)
    finally:
        document.close()
    return redaction_count


def _normalize_rapidocr_result(raw) -> list[tuple]:
    """Return a list of (box, text, score) tuples from any RapidOCR API version.

    - RapidOCR >=3.x returns a `RapidOCROutput` object exposing .boxes, .txts, .scores.
    - Older versions return a tuple (result, elapse) where result is a list of
      (box, text, score) tuples, or `None` on no detection.
    """
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
    """Find consecutive OCR word sequences that match `original`.

    Strategy:
    1. Exact token-sequence match on normalized tokens.
    2. Fallback: substring match — concatenate normalized OCR tokens into one stream
       and find spans whose joined normalized content equals the normalized target.
       Useful when OCR groups characters differently than the detector input.
    """
    target_tokens = [_normalize_token(token) for token in original.split()]
    target_tokens = [token for token in target_tokens if token]
    if not target_tokens:
        return []
    normalized_words = [_normalize_token(word["text"]) for word in words]

    matches: list[list[dict]] = []
    seen: set[tuple[int, int]] = set()

    for index in range(0, len(words) - len(target_tokens) + 1):
        if normalized_words[index : index + len(target_tokens)] == target_tokens:
            key = (index, index + len(target_tokens))
            if key not in seen:
                matches.append(words[index : index + len(target_tokens)])
                seen.add(key)
    if matches:
        return matches

    target_concat = "".join(target_tokens)
    if not target_concat:
        return matches

    # Substring fallback: also accept the case where one OCR token contains
    # the target (e.g., "sigdoglianisergio" contains "doglianisergio" because
    # OCR glued the prefix "Sig." to the name). We treat such tokens as a
    # full match on that single word's bbox — slightly over-redacts the
    # surrounding chars but avoids leaving PII visible.
    for index, normalized in enumerate(normalized_words):
        if target_concat in normalized:
            key = (index, index + 1)
            if key not in seen:
                matches.append([words[index]])
                seen.add(key)

    # Also keep the original "consecutive tokens whose join EQUALS target"
    # path for cases where OCR splits the target across multiple tokens
    # without extra prefix/suffix characters.
    for start in range(len(words)):
        joined = ""
        for end in range(start, min(start + 8, len(words))):
            joined += normalized_words[end]
            if joined == target_concat:
                key = (start, end + 1)
                if key not in seen:
                    matches.append(words[start : end + 1])
                    seen.add(key)
                break
            if len(joined) > len(target_concat):
                break
    return matches


def _normalize_token(value: str) -> str:
    return re.sub(r"\W+", "", value, flags=re.UNICODE).lower()
