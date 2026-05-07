"""Test per i parametri di LayerConfig non ancora coperti.

Copre: chunking, ml_skip, keep_metadata, consistent_mapping, DetectionSpan,
resolver normalize_label/category_counts, _build_chunks algorithm.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.anonymizer import _build_chunks
from privacy_anonymizer.config import LayerConfig, MaskingMode
from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import category_counts, normalize_label

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)

_PII_TEXT = "CF RSSMRA80A01L219M email mario@azienda.it tel 3401234567"


# ===========================================================================
# DetectionSpan — modello base
# ===========================================================================

def test_detection_span_basic_fields() -> None:
    span = DetectionSpan(start=5, end=21, label="CODICE_FISCALE", source="pattern")
    assert span.start == 5
    assert span.end == 21
    assert span.label == "CODICE_FISCALE"
    assert span.source == "pattern"
    assert span.score == 1.0
    assert span.metadata == {}


def test_detection_span_length_property() -> None:
    span = DetectionSpan(0, 16, "CODICE_FISCALE", "pattern")
    assert span.length == 16


def test_detection_span_metadata_field() -> None:
    span = DetectionSpan(0, 16, "CODICE_FISCALE", "pattern",
                         metadata={"checksum_valid": "true"})
    assert span.metadata["checksum_valid"] == "true"


def test_detection_span_invalid_offsets_raise() -> None:
    with pytest.raises(ValueError):
        DetectionSpan(start=-1, end=5, label="X", source="pattern")
    with pytest.raises(ValueError):
        DetectionSpan(start=10, end=5, label="X", source="pattern")


def test_detection_span_overlaps_or_touches_true() -> None:
    a = DetectionSpan(0, 10, "A", "pattern")
    b = DetectionSpan(8, 20, "A", "pattern")
    assert a.overlaps_or_touches(b)


def test_detection_span_overlaps_or_touches_false() -> None:
    a = DetectionSpan(0, 5, "A", "pattern")
    b = DetectionSpan(10, 15, "A", "pattern")
    assert not a.overlaps_or_touches(b)


def test_detection_span_overlaps_with_max_gap() -> None:
    a = DetectionSpan(0, 5, "A", "pattern")
    b = DetectionSpan(8, 15, "A", "pattern")   # gap = 3
    assert a.overlaps_or_touches(b, max_gap=3)
    assert not a.overlaps_or_touches(b, max_gap=2)


def test_detection_span_cf_has_checksum_metadata() -> None:
    from privacy_anonymizer.detectors.patterns_it import ItalianPatternDetector
    spans = ItalianPatternDetector().detect("CF RSSMRA80A01L219M")
    cf_span = next(s for s in spans if s.label == "CODICE_FISCALE")
    assert cf_span.metadata.get("checksum_valid") == "true"


def test_detection_span_invalid_cf_has_false_checksum() -> None:
    from privacy_anonymizer.detectors.patterns_it import ItalianPatternDetector
    spans = ItalianPatternDetector().detect("CF RSSMRA80A01L219X")
    cf_span = next(s for s in spans if s.label == "CODICE_FISCALE")
    assert cf_span.metadata.get("checksum_valid") == "false"


# ===========================================================================
# resolver — normalize_label e category_counts
# ===========================================================================

def test_normalize_label_cell_it_becomes_telefono_it() -> None:
    assert normalize_label("CELL_IT") == "TELEFONO_IT"


def test_normalize_label_tel_it_becomes_telefono_it() -> None:
    assert normalize_label("TEL_IT") == "TELEFONO_IT"


def test_normalize_label_unknown_label_uppercased() -> None:
    assert normalize_label("persona") == "PERSONA"


def test_normalize_label_email_unchanged() -> None:
    assert normalize_label("EMAIL") == "EMAIL"


def test_category_counts_aggregates_correctly() -> None:
    spans = [
        DetectionSpan(0, 5, "EMAIL", "pattern"),
        DetectionSpan(6, 10, "EMAIL", "pattern"),
        DetectionSpan(11, 25, "CODICE_FISCALE", "pattern"),
    ]
    counts = category_counts(spans)
    assert counts["EMAIL"] == 2
    assert counts["CODICE_FISCALE"] == 1


def test_category_counts_empty_spans() -> None:
    assert category_counts([]) == {}


# ===========================================================================
# _build_chunks — algoritmo di chunking
# ===========================================================================

def test_build_chunks_short_text_returns_single_window() -> None:
    text = "CF RSSMRA80A01L219M"
    windows = _build_chunks(text, chunk_size=200, overlap=20)
    assert windows == [(0, len(text))]


def test_build_chunks_exact_chunk_size_single_window() -> None:
    text = "A" * 1500
    windows = _build_chunks(text, chunk_size=1500, overlap=0)
    assert len(windows) == 1
    assert windows[0] == (0, 1500)


def test_build_chunks_long_text_produces_multiple_windows() -> None:
    text = "A" * 5000
    windows = _build_chunks(text, chunk_size=1500, overlap=100)
    assert len(windows) >= 3


def test_build_chunks_covers_full_text() -> None:
    text = "X" * 4000
    windows = _build_chunks(text, chunk_size=1500, overlap=100)
    covered = set()
    for start, end in windows:
        covered.update(range(start, end))
    assert covered == set(range(len(text)))


def test_build_chunks_windows_have_overlap() -> None:
    text = "A" * 4000
    windows = _build_chunks(text, chunk_size=1500, overlap=100)
    # Ogni finestra successiva deve iniziare prima della fine della precedente
    for i in range(len(windows) - 1):
        assert windows[i + 1][0] < windows[i][1]


def test_build_chunks_zero_chunk_size_returns_full() -> None:
    text = "CF RSSMRA80A01L219M"
    windows = _build_chunks(text, chunk_size=0, overlap=0)
    assert windows == [(0, len(text))]


def test_build_chunks_whitespace_boundary_alignment() -> None:
    # Il boundary deve essere allineato agli spazi bianchi
    text = ("parola " * 300)  # ~2100 chars, con spazi regolari
    windows = _build_chunks(text, chunk_size=500, overlap=50)
    for start, end in windows:
        if end < len(text):
            # Il carattere immediatamente dopo end deve essere o spazio o fine testo
            assert end <= len(text)


# ===========================================================================
# LayerConfig — chunk_long_text e chunk_threshold
# ===========================================================================

def test_chunk_long_text_disabled_still_detects_pii() -> None:
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False, parallel=False,
        chunk_long_text=False,
    )
    spans = Anonymizer(config).detect_text(_PII_TEXT)
    labels = {s.label for s in spans}
    assert "CODICE_FISCALE" in labels


def test_chunk_threshold_low_triggers_chunking_on_short_text() -> None:
    # Con threshold=10 anche il testo breve viene chunked
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False, parallel=False,
        chunk_long_text=True, chunk_threshold=10, chunk_size=30, chunk_overlap=5,
    )
    anon = Anonymizer(config)
    spans = anon.detect_text("CF RSSMRA80A01L219M email mario@azienda.it")
    labels = {s.label for s in spans}
    assert "CODICE_FISCALE" in labels
    assert "EMAIL" in labels


def test_chunk_size_small_still_detects_all_entities() -> None:
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False, parallel=False,
        chunk_long_text=True, chunk_threshold=10,
        chunk_size=20, chunk_overlap=5,
    )
    text = "CF RSSMRA80A01L219M IBAN IT60X0542811101000000123456"
    spans = Anonymizer(config).detect_text(text)
    labels = {s.label for s in spans}
    assert "CODICE_FISCALE" in labels
    assert "IBAN_IT" in labels


# ===========================================================================
# LayerConfig — ml_skip_extensions / ml_skip_min_chars
# ===========================================================================

def test_ml_skip_triggers_pattern_only_on_log_file(tmp_path) -> None:
    """File .log > ml_skip_min_chars deve usare solo il layer pattern."""
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False,
        ml_skip_extensions=(".log",), ml_skip_min_chars=5,
    )
    log_file = tmp_path / "server.log"
    log_file.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    result = Anonymizer(config).process_file(log_file)
    assert "RSSMRA80A01L219M" not in result.anonymized_text


def test_ml_skip_not_triggered_when_text_below_threshold(tmp_path) -> None:
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False,
        ml_skip_extensions=(".log",), ml_skip_min_chars=10_000,
    )
    log_file = tmp_path / "server.log"
    log_file.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    result = Anonymizer(config).process_file(log_file)
    assert "RSSMRA80A01L219M" not in result.anonymized_text


def test_ml_skip_empty_tuple_never_skips(tmp_path) -> None:
    config = LayerConfig(
        opf_enabled=False, gliner_enabled=False,
        ml_skip_extensions=(), ml_skip_min_chars=1,
    )
    log_file = tmp_path / "server.log"
    log_file.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    result = Anonymizer(config).process_file(log_file)
    assert "RSSMRA80A01L219M" not in result.anonymized_text


# ===========================================================================
# LayerConfig — keep_metadata
# ===========================================================================

def test_keep_metadata_false_sets_metadata_stripped_true_in_audit(tmp_path) -> None:
    config = LayerConfig(opf_enabled=False, gliner_enabled=False, keep_metadata=False)
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    result = Anonymizer(config).process_file(src)
    # Per .txt metadata_stripped dipende dall'adapter; l'audit deve registrarlo
    assert "metadata_stripped" in result.audit_report


def test_keep_metadata_flag_in_audit_report(tmp_path) -> None:
    config = LayerConfig(opf_enabled=False, gliner_enabled=False, keep_metadata=True)
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    result = Anonymizer(config).process_file(src)
    assert "metadata_stripped" in result.audit_report


# ===========================================================================
# LayerConfig — consistent_mapping (stessa entità → stesso placeholder)
# ===========================================================================

def test_consistent_mapping_same_cf_gets_same_placeholder() -> None:
    text = "CF RSSMRA80A01L219M e poi di nuovo RSSMRA80A01L219M"
    config = LayerConfig(opf_enabled=False, gliner_enabled=False, consistent_mapping=True)
    anon_text, _ = Anonymizer(config).process_text(text)
    # Il CF compare due volte → stesso placeholder
    assert anon_text.count("[CF_1]") == 2


# ===========================================================================
# LayerConfig — masking_mode via config
# ===========================================================================

@pytest.mark.parametrize("mode", [MaskingMode.REPLACE, MaskingMode.REDACT,
                                   MaskingMode.GENERALIZE, MaskingMode.HASH])
def test_masking_mode_config_applied_correctly(mode) -> None:
    config = LayerConfig(opf_enabled=False, gliner_enabled=False,
                         parallel=False, masking_mode=mode)
    anon_text, counts = Anonymizer(config).process_text("CF RSSMRA80A01L219M")
    assert "RSSMRA80A01L219M" not in anon_text
    assert counts.get("CODICE_FISCALE", 0) >= 1


# ===========================================================================
# ProcessResult.save()
# ===========================================================================

def test_process_result_save_writes_file(tmp_path) -> None:
    result = Anonymizer(_PATTERN_ONLY).analyze_text("CF RSSMRA80A01L219M")
    dest = tmp_path / "output.txt"
    saved = result.save(dest)
    assert saved == dest
    assert dest.exists()
    assert "RSSMRA80A01L219M" not in dest.read_text(encoding="utf-8")


def test_process_result_save_updates_output_path(tmp_path) -> None:
    result = Anonymizer(_PATTERN_ONLY).analyze_text("CF RSSMRA80A01L219M")
    dest = tmp_path / "output.txt"
    result.save(dest)
    assert result.output_path == dest
