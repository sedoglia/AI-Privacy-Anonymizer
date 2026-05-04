from __future__ import annotations

from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import (
    _FALSE_POSITIVE_WORDS,
    _is_false_positive,
    _trim_span_punctuation,
    resolve_spans,
)


# ---------------------------------------------------------------------------
# _trim_span_punctuation
# ---------------------------------------------------------------------------

def test_trim_trailing_comma_from_opf_span() -> None:
    text = "Luca Bianchi,luca@mail.it"
    span = DetectionSpan(0, 13, "PERSONA", "opf")  # "Luca Bianchi,"
    trimmed = _trim_span_punctuation(span, text)
    assert trimmed is not None
    assert text[trimmed.start : trimmed.end] == "Luca Bianchi"


def test_trim_leading_whitespace_from_gliner_span() -> None:
    text = " Mario Rossi"
    span = DetectionSpan(0, 12, "PERSONA", "gliner")
    trimmed = _trim_span_punctuation(span, text)
    assert trimmed is not None
    assert text[trimmed.start : trimmed.end] == "Mario Rossi"


def test_trim_does_not_touch_pattern_spans() -> None:
    text = "mario.rossi@example.com,"
    span = DetectionSpan(0, 23, "EMAIL", "pattern")
    trimmed = _trim_span_punctuation(span, text)
    assert trimmed is span  # unchanged


def test_trim_span_becomes_empty_returns_none() -> None:
    text = ", ;"
    span = DetectionSpan(0, 3, "PERSONA", "opf")
    assert _trim_span_punctuation(span, text) is None


# ---------------------------------------------------------------------------
# _is_false_positive
# ---------------------------------------------------------------------------

def test_product_names_are_false_positives() -> None:
    for word in ("Mouse", "Tastiera", "Laptop", "Monitor", "Stampante"):
        assert _is_false_positive(word), f"{word!r} should be a false positive"


def test_product_names_case_insensitive() -> None:
    assert _is_false_positive("mouse")
    assert _is_false_positive("LAPTOP")
    assert _is_false_positive("tastiera")


def test_real_person_name_is_not_false_positive() -> None:
    assert not _is_false_positive("Mario")
    assert not _is_false_positive("Giulia Neri")


# ---------------------------------------------------------------------------
# resolve_spans — integration: trailing comma no longer eats separator
# ---------------------------------------------------------------------------

def test_trailing_comma_stripped_from_opf_persona() -> None:
    text = "Luca Bianchi,luca@mail.it,Mouse"
    # Simulate OPF detecting "Luca Bianchi," (with comma) as PERSONA
    # and pattern detecting the email correctly.
    spans = [
        DetectionSpan(0, 13, "PERSONA", "opf"),   # "Luca Bianchi,"
        DetectionSpan(13, 25, "EMAIL", "pattern"), # "luca@mail.it"
    ]
    resolved = resolve_spans(spans, text=text)
    labels = {text[s.start : s.end]: s.label for s in resolved}
    assert labels.get("Luca Bianchi") == "PERSONA"
    assert labels.get("luca@mail.it") == "EMAIL"


def test_product_name_not_in_resolved_spans() -> None:
    text = "Luca Bianchi,luca@mail.it,Mouse"
    spans = [
        DetectionSpan(0, 12, "PERSONA", "opf"),   # "Luca Bianchi"
        DetectionSpan(13, 25, "EMAIL", "pattern"), # "luca@mail.it"
        DetectionSpan(26, 31, "PERSONA", "opf"),   # "Mouse"
    ]
    resolved = resolve_spans(spans, text=text)
    span_texts = [text[s.start : s.end] for s in resolved]
    assert "Mouse" not in span_texts


# ---------------------------------------------------------------------------
# URL false-positive filter (via anonymizer._filter_false_positive_personas)
# ---------------------------------------------------------------------------

def test_url_filter_rejects_plain_word() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "item: Laptop"
    spans = [DetectionSpan(6, 12, "URL", "gliner")]  # "Laptop"
    result = _filter_false_positive_personas(text, spans)
    assert result == []


def test_url_filter_keeps_real_url() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "visita https://example.com per info"
    spans = [DetectionSpan(7, 26, "URL", "gliner")]  # "https://example.com"
    result = _filter_false_positive_personas(text, spans)
    assert len(result) == 1


def test_url_filter_keeps_www_url() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "vai su www.sito.it"
    spans = [DetectionSpan(6, 18, "URL", "opf")]
    result = _filter_false_positive_personas(text, spans)
    assert len(result) == 1
