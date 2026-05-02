from __future__ import annotations

import re
from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError
from privacy_anonymizer.io import _ocr
from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult
from privacy_anonymizer.masking import ReplacementSpan


# Default fallback when no Anonymizer has called _ocr.configure() yet (e.g.
# adapters used directly in tests). Runtime DPI is read from _ocr.get_settings().
OCR_RENDER_DPI = 300


class PdfAdapter(FileAdapter):
    extensions = {".pdf"}

    def read_text(self, path: Path) -> FileContent:
        PdfReader, _ = _import_pypdf()
        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        warnings: list[str] = []
        if not any(page.strip() for page in pages):
            ocr_text, ocr_words, ocr_warnings = _ocr_pdf_text(path)
            warnings.extend(ocr_warnings)
            if ocr_text.strip():
                return FileContent(ocr_text, warnings=warnings, ocr_words=ocr_words)
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
        source_content=None,
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

        cached_words = source_content.ocr_words if source_content is not None else None
        if replacements:
            try:
                redacted_ocr = _write_ocr_redacted_pdf(
                    source, destination, replacements, keep_metadata, cached_words=cached_words
                )
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


def _ocr_pdf_text(path: Path) -> tuple[str, list[list[dict]] | None, list[str]]:
    """Read text from a scanned PDF via RapidOCR.

    Returns (text, per_page_word_boxes_or_None, warnings).
    """
    warnings: list[str] = []
    text, words = _try_rapidocr_pdf(path, warnings)
    return text, words, warnings


def _try_rapidocr_pdf(path: Path, warnings: list[str]) -> tuple[str, list[list[dict]] | None]:
    try:
        fitz = _import_fitz()
        Image = _import_pillow()
    except MissingOptionalDependencyError as exc:
        warnings.append(f"OCR PDF non disponibile: dipendenza mancante ({exc}).")
        return "", None

    engine = _ocr.get_engine(warnings)
    if engine is None:
        return "", None

    settings = _ocr.get_settings()
    dpi = settings.dpi or OCR_RENDER_DPI
    document = fitz.open(path)
    page_count = document.page_count

    def _ocr_page(page_idx: int):
        # PyMuPDF page handles aren't safely shared across threads; reopen
        # the page from the same document object via index — get_pixmap is
        # what dominates the time and is safe to call serially per page.
        page = document.load_page(page_idx)
        pix = page.get_pixmap(dpi=dpi, alpha=False)
        png_bytes = pix.tobytes("png")
        pix_width, pix_height = pix.width, pix.height
        # Image decode + OCR can run off the main thread.
        return _decode_and_ocr(png_bytes, pix_width, pix_height, engine, warnings, page_idx)

    pages_results: list[tuple[list[str], list[dict], int, int]] = []
    try:
        if settings.parallel_pages and page_count > 1:
            from concurrent.futures import ThreadPoolExecutor

            workers = max(1, min(settings.max_workers, page_count))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                pages_results = list(executor.map(_ocr_page, range(page_count)))
        else:
            pages_results = [_ocr_page(i) for i in range(page_count)]
    finally:
        document.close()

    pages_text: list[str] = []
    pages_words: list[list[dict]] = []
    global_char_offset = 0
    for page_idx, (page_line_texts, page_words, pix_width, pix_height) in enumerate(pages_results):
        if page_idx > 0:
            global_char_offset += 2  # "\n\n" page separator

        if not page_line_texts:
            pages_text.append("")
            pages_words.append([])
            continue

        # Re-anchor per-token char offsets to the global text now that we know
        # this page's starting offset. Each word's char_start/char_end was
        # produced relative to the page (page-local offset).
        anchored = [
            {**w, "char_start": w["char_start"] + global_char_offset, "char_end": w["char_end"] + global_char_offset}
            for w in page_words
        ]
        page_text = "\n".join(page_line_texts)
        global_char_offset += len(page_text)

        pages_text.append(page_text)
        pages_words.append(
            [{"_pix_width": pix_width, "_pix_height": pix_height, **w} for w in anchored]
            if anchored else []
        )

    text = "\n\n".join(pages_text)
    if text.strip():
        warnings.append("PDF scansionato letto con RapidOCR.")
    return text, pages_words if text.strip() else None


def _decode_and_ocr(png_bytes: bytes, pix_width: int, pix_height: int, engine, warnings: list[str], page_idx: int):
    """Decode a rendered page PNG and run OCR. Returns (line_texts, words, w, h).

    Word offsets are page-local (0 at start of page text); the caller anchors
    them to the global text once page order is established.
    """
    import io as _io
    import numpy as np  # type: ignore[import-not-found]

    Image = _import_pillow()
    image = Image.open(_io.BytesIO(png_bytes)).convert("RGB")
    try:
        rows = _normalize_rapidocr_result(engine(np.array(image)))
    except Exception as exc:  # pragma: no cover - defensive
        warnings.append(f"RapidOCR pagina {page_idx} fallita: {exc}")
        return [], [], pix_width, pix_height

    valid_rows = [(box, txt, score) for box, txt, score in rows if txt]
    if not valid_rows:
        return [], [], pix_width, pix_height

    page_line_texts: list[str] = []
    page_words: list[dict] = []
    line_offset = 0

    for line_idx, (box, line_text, _score) in enumerate(valid_rows):
        if line_idx > 0:
            line_offset += 1  # "\n" between lines

        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        line_left, line_right = min(xs), max(xs)
        line_top, line_bottom = min(ys), max(ys)
        line_width = line_right - line_left
        line_height = line_bottom - line_top

        tokens = line_text.split()
        page_line_texts.append(line_text)
        if not tokens:
            line_offset += len(line_text)
            continue

        total_chars = sum(len(t) for t in tokens) + max(len(tokens) - 1, 0)
        cursor_x = line_left
        search_from = 0

        for tok_idx, token in enumerate(tokens):
            token_width_chars = len(token) + (1 if tok_idx < len(tokens) - 1 else 0)
            token_px_width = line_width * (token_width_chars / total_chars) if total_chars else 0

            tok_pos = line_text.find(token, search_from)
            if tok_pos < 0:
                tok_pos = search_from

            page_words.append({
                "text": token,
                "left": cursor_x,
                "top": line_top,
                "width": token_px_width,
                "height": line_height,
                "char_start": line_offset + tok_pos,
                "char_end": line_offset + tok_pos + len(token),
            })
            cursor_x += token_px_width
            search_from = tok_pos + len(token)

        line_offset += len(line_text)

    return page_line_texts, page_words, pix_width, pix_height


def _load_rapidocr(warnings: list[str] | None = None):
    """Backwards-compatible shim that returns the shared singleton engine."""
    return _ocr.get_engine(warnings)


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
    cached_words: list[list[dict]] | None = None,
    debug: bool = False,
) -> int:
    """Redact a scanned PDF by locating word boxes via RapidOCR on each rendered page.

    If cached_words is provided (from read_text), reuses that OCR output instead of
    re-running OCR, ensuring the text used for entity detection and the word coordinates
    used for redaction come from the exact same OCR pass.

    If debug=True, prints detailed matching information for each replacement span.
    """
    fitz = _import_fitz()

    document = fitz.open(source)
    redaction_count = 0
    try:
        for page_index, page in enumerate(document):
            if cached_words is not None:
                if page_index >= len(cached_words) or not cached_words[page_index]:
                    continue
                raw_words = cached_words[page_index]
                pix_width = raw_words[0].get("_pix_width", 1) if raw_words else 1
                pix_height = raw_words[0].get("_pix_height", 1) if raw_words else 1
                words = [{k: v for k, v in w.items() if not k.startswith("_")} for w in raw_words]
            else:
                Image = _import_pillow()
                engine = _ocr.get_engine()
                if engine is None:
                    break
                import io as _io
                import numpy as np  # type: ignore[import-not-found]
                pix = page.get_pixmap(dpi=_ocr.get_settings().dpi or OCR_RENDER_DPI, alpha=False)
                image = Image.open(_io.BytesIO(pix.tobytes("png"))).convert("RGB")
                try:
                    rows = _normalize_rapidocr_result(engine(np.array(image)))
                except Exception:
                    continue
                if not rows:
                    continue
                words = _rapidocr_words(rows)
                pix_width, pix_height = pix.width, pix.height

            if not words:
                continue

            scale_x = page.rect.width / pix_width if pix_width else 1.0
            scale_y = page.rect.height / pix_height if pix_height else 1.0

            page_redactions = 0
            seen_rects: set[tuple[float, float, float, float]] = set()

            # Determine whether words carry char-offset information (set during OCR
            # in _try_rapidocr_pdf). If so, try positional matching first — it is
            # immune to OCR character variants. However, when word tokens contain
            # punctuation (e.g., "PT:BoNoMoKATIA"), char-offset tracking is unreliable
            # because detected spans may be substrings of those tokens. Always fall back
            # to text-content matching for robustness.
            has_char_offsets = words and "char_start" in words[0]

            for replacement in replacements:
                fill = (0, 0, 0) if set(replacement.replacement) == {"█"} else (1, 1, 1)
                annot_text = "" if fill == (0, 0, 0) else replacement.replacement

                groups: list[list[dict]] = []
                matched_via = None  # Track which strategy matched

                if has_char_offsets:
                    # Match words that overlap the span (not just contain it).
                    # This handles cases where a span is a substring of a word,
                    # e.g., "BoNoMoKATIA" at [436-447] is part of "PT:BoNoMoKATIA" at [433-447].
                    span_words = [
                        w for w in words
                        if w.get("char_start", -1) <= replacement.end
                        and w.get("char_end", -1) >= replacement.start
                    ]
                    if span_words:
                        groups.append(span_words)
                        matched_via = "char_offset"

                # Always try text-content matching as primary/fallback. This handles:
                # 1. OCR character variants (O→0, I→1, etc.)
                # 2. Tokens with punctuation where char-offset tracking is unreliable
                # 3. Any case where positional matching failed
                if not groups or not matched_via:
                    original = replacement.original.strip()
                    if original:
                        fallback_groups = _find_word_matches(words, original)
                        if fallback_groups:
                            groups = fallback_groups
                            matched_via = "text_content"

                if debug and not groups:
                    import sys
                    print(
                        f"[DEBUG page {page_index}] NO MATCH for '{replacement.original}' "
                        f"(span {replacement.start}-{replacement.end}). "
                        f"Words in page: {len(words)}. "
                        f"Word texts: {[w['text'] for w in words[:20]]}{'...' if len(words) > 20 else ''}",
                        file=sys.stderr,
                    )
                elif debug:
                    import sys
                    print(
                        f"[DEBUG page {page_index}] MATCHED '{replacement.original}' "
                        f"via {matched_via} ({len(groups)} groups)",
                        file=sys.stderr,
                    )

                for match in groups:
                    if not match:
                        continue
                    left = min(w["left"] for w in match) * scale_x
                    top = min(w["top"] for w in match) * scale_y
                    right = max(w["left"] + w["width"] for w in match) * scale_x
                    bottom = max(w["top"] + w["height"] for w in match) * scale_y
                    rect_key = (round(left, 1), round(top, 1), round(right, 1), round(bottom, 1))
                    if rect_key in seen_rects:
                        continue
                    seen_rects.add(rect_key)
                    rect = fitz.Rect(left, top, right, bottom)
                    page.add_redact_annot(rect, text=annot_text, fill=fill)
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
    2. Substring match — concatenate normalized OCR tokens and find spans
       whose joined content equals the normalized target.
    3. Joined-token match — find word spans whose tokens, joined without
       spaces, match the target's normalized tokens joined together.
    4. Fuzzy fallback — if exact matching fails, use approximate string
       matching to find OCR text that is similar to the target (>80% similarity).
       Handles heavy OCR corruption (e.g., spacing errors, character shifts).
    """
    import difflib

    target_tokens = [_normalize_token(token) for token in original.split()]
    target_tokens = [token for token in target_tokens if token]
    if not target_tokens:
        return []
    normalized_words = [_normalize_token(word["text"]) for word in words]

    matches: list[list[dict]] = []
    seen: set[tuple[int, int]] = set()

    # Exact token-sequence match
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

    # Substring fallback
    for index, normalized in enumerate(normalized_words):
        if target_concat in normalized:
            key = (index, index + 1)
            if key not in seen:
                matches.append([words[index]])
                seen.add(key)

    # Joined-token match
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

    if matches:
        return matches

    # Fuzzy fallback: approximate string matching for heavily OCR-corrupted text.
    # Find word spans where the joined normalized text has >80% similarity
    # to the target normalized text. This catches cases like spacing errors,
    # character shifts, or token merging that exact matching misses.
    min_ratio = 0.80
    for start in range(len(words)):
        for end in range(start + 1, min(start + 8, len(words) + 1)):
            joined = "".join(normalized_words[start:end])
            ratio = difflib.SequenceMatcher(None, joined, target_concat).ratio()
            if ratio >= min_ratio:
                key = (start, end)
                if key not in seen:
                    matches.append(words[start:end])
                    seen.add(key)

    return matches


# Common OCR character confusables mapped to a canonical form.
# Applied symmetrically to BOTH target tokens and OCR word tokens so that
# a misread like "B0NOMO" matches the target "BONOMO", or "2O25" matches "2025".
_OCR_CONFUSABLE_TABLE = str.maketrans("oOiIlLsS", "00111155")


def _normalize_token(value: str) -> str:
    s = re.sub(r"\W+", "", value, flags=re.UNICODE).lower()
    return s.translate(_OCR_CONFUSABLE_TABLE)
