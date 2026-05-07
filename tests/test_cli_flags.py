"""Test di copertura per i flag CLI non ancora testati.

Usa --pattern-only ovunque possibile per velocità; i test sulle modalità
ML (--recall-mode, --gliner-threshold) sono marcati con le cautele appropriate.
"""
from __future__ import annotations

import json

import pytest

from privacy_anonymizer.cli import main

# ---------------------------------------------------------------------------
# testo reale con PII variegate
# ---------------------------------------------------------------------------
_PII_TEXT = "CF RSSMRA80A01L219M email mario@azienda.it IBAN IT60X0542811101000000123456 tel 3401234567"


# ===========================================================================
# --text  (input diretto da riga di comando)
# ===========================================================================

def test_text_flag_prints_anonymized_output(capsys) -> None:
    rc = main(["--text", _PII_TEXT, "--pattern-only"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "RSSMRA80A01L219M" not in out
    assert "mario@azienda.it" not in out


def test_text_flag_with_json_mode(capsys) -> None:
    rc = main(["--text", _PII_TEXT, "--pattern-only", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "entities_found" in data
    assert data["entities_found"]["by_category"].get("CODICE_FISCALE", 0) >= 1


def test_text_flag_with_show_map(capsys) -> None:
    rc = main(["--text", _PII_TEXT, "--pattern-only", "--show-map"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Mappa entità" in out
    assert "CODICE_FISCALE" in out or "CF" in out


# ===========================================================================
# --mode  (tutte le modalità di mascheramento)
# ===========================================================================

@pytest.mark.parametrize("mode,expected_absent,expected_marker", [
    ("replace",    "RSSMRA80A01L219M", "[CF_"),
    ("generalize", "RSSMRA80A01L219M", "[CF]"),
    ("hash",       "RSSMRA80A01L219M", "[SHA256:"),
    ("redact",     "RSSMRA80A01L219M", "████"),
])
def test_mode_flag_masks_cf_correctly(tmp_path, mode, expected_absent, expected_marker, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text(f"CF {expected_absent}", encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--mode", mode])
    assert rc == 0
    output_file = tmp_path / "input_anonymized.txt"
    content = output_file.read_text(encoding="utf-8")
    assert expected_absent not in content
    assert expected_marker in content


# ===========================================================================
# --disable-layer
# ===========================================================================

def test_disable_pattern_layer_leaves_pii_in_output(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--disable-layer", "opf", "--disable-layer", "gliner", "--disable-layer", "pattern"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    # Con tutti i layer disabilitati il CF rimane
    assert "RSSMRA80A01L219M" in out


def test_disable_opf_and_gliner_same_as_pattern_only(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--disable-layer", "opf", "--disable-layer", "gliner"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out
    assert "[CF_1]" in out


# ===========================================================================
# --pattern-only
# ===========================================================================

def test_pattern_only_flag_detects_cf(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--pattern-only"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out


# ===========================================================================
# --dry-run
# ===========================================================================

def test_dry_run_does_not_write_output_file(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--dry-run"])
    assert rc == 0
    output = tmp_path / "input_anonymized.txt"
    assert not output.exists()
    assert "Dry-run" in capsys.readouterr().out


def test_dry_run_still_prints_summary(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M email mario@azienda.it", encoding="utf-8")
    main([str(src), "--pattern-only", "--dry-run"])
    out = capsys.readouterr().out
    assert "Span rilevati" in out or "CODICE_FISCALE" in out


# ===========================================================================
# --show-map  (su file)
# ===========================================================================

def test_show_map_prints_entity_map_on_file(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--show-map"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Mappa entità" in out
    # I placeholder devono essere presenti (no valori originali)
    assert "RSSMRA80A01L219M" not in out
    assert "mario@azienda.it" not in out


def test_show_map_no_entities_prints_nessuna(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text("Testo senza dati personali.", encoding="utf-8")
    main([str(src), "--pattern-only", "--show-map"])
    out = capsys.readouterr().out
    assert "nessuna" in out.lower() or "Mappa" in out


# ===========================================================================
# --json  (output JSON audit su file)
# ===========================================================================

def test_json_flag_prints_valid_json_audit(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "entities_found" in data
    assert "processed_at" in data
    assert "layers_used" in data


def test_json_flag_includes_category_counts(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    main([str(src), "--pattern-only", "--json"])
    data = json.loads(capsys.readouterr().out)
    by_cat = data["entities_found"]["by_category"]
    assert by_cat.get("CODICE_FISCALE", 0) >= 1
    assert by_cat.get("EMAIL", 0) >= 1
    assert by_cat.get("IBAN_IT", 0) >= 1


# ===========================================================================
# --supported-formats
# ===========================================================================

def test_supported_formats_lists_common_extensions(capsys) -> None:
    rc = main(["--supported-formats"])
    assert rc == 0
    out = capsys.readouterr().out
    for ext in (".txt", ".docx", ".xlsx", ".pdf", ".json"):
        assert ext in out


# ===========================================================================
# --setup
# ===========================================================================

def test_setup_prints_layer_status(capsys) -> None:
    rc = main(["--setup"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pattern" in out.lower() or "Layer" in out or "Setup" in out


# ===========================================================================
# --wipe-cache
# ===========================================================================

def test_wipe_cache_returns_zero(capsys) -> None:
    rc = main(["--wipe-cache"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cache" in out.lower() or "cancellat" in out.lower()


# ===========================================================================
# --no-parallel  (sequenziale)
# ===========================================================================

def test_no_parallel_flag_produces_same_result(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    main([str(src), "--pattern-only", "--no-parallel"])
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out
    assert "mario@azienda.it" not in out


# ===========================================================================
# --no-chunk-long-text
# ===========================================================================

def test_no_chunk_long_text_flag_still_anonymizes(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--no-chunk-long-text"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out


# ===========================================================================
# --chunk-threshold / --chunk-size / --chunk-overlap / --chunk-max-workers
# ===========================================================================

def test_chunk_threshold_param_accepted(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--chunk-threshold", "500"])
    assert rc == 0


def test_chunk_size_and_overlap_params_accepted(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT * 10, encoding="utf-8")  # testo abbastanza lungo
    rc = main([str(src), "--pattern-only", "--chunk-size", "200", "--chunk-overlap", "20"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.txt").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out


def test_chunk_max_workers_param_accepted(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text(_PII_TEXT, encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--chunk-max-workers", "2"])
    assert rc == 0


# ===========================================================================
# --ml-skip-extensions / --ml-skip-min-chars
# ===========================================================================

def test_ml_skip_extensions_accepted(tmp_path) -> None:
    src = tmp_path / "input.log"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--ml-skip-extensions", ".log", "--ml-skip-min-chars", "10"])
    assert rc == 0
    out = (tmp_path / "input_anonymized.log").read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out


def test_ml_skip_extensions_empty_disables_skip(tmp_path) -> None:
    src = tmp_path / "input.log"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--ml-skip-extensions", ""])
    assert rc == 0


# ===========================================================================
# --log  (file di log)
# ===========================================================================

def test_log_flag_creates_log_file(tmp_path, capsys) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    log_file = tmp_path / "run.log"
    rc = main([str(src), "--pattern-only", "--log", str(log_file)])
    assert rc == 0
    assert log_file.exists()
    assert log_file.stat().st_size > 0


# ===========================================================================
# --recall-mode  (funziona con pattern-only, il param è accettato)
# ===========================================================================

@pytest.mark.parametrize("mode", ["conservative", "balanced", "aggressive"])
def test_recall_mode_accepted_with_pattern_only(tmp_path, mode) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    rc = main([str(src), "--pattern-only", "--recall-mode", mode])
    assert rc == 0


# ===========================================================================
# --output  (file o directory di output espliciti)
# ===========================================================================

def test_output_explicit_file(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    out_file = tmp_path / "output" / "clean.txt"
    rc = main([str(src), "--pattern-only", "--output", str(out_file)])
    assert rc == 0
    assert out_file.exists()
    assert "RSSMRA80A01L219M" not in out_file.read_text(encoding="utf-8")


def test_output_explicit_directory(tmp_path) -> None:
    src = tmp_path / "input.txt"
    src.write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    out_dir = tmp_path / "outputs"
    out_dir.mkdir()
    rc = main([str(src), "--pattern-only", "--output", str(out_dir)])
    assert rc == 0
    outputs = list(out_dir.glob("*.txt"))
    assert len(outputs) == 1


# ===========================================================================
# --recursive / --no-recursive  (cartella)
# ===========================================================================

def test_recursive_processes_nested_files(tmp_path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.txt").write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(tmp_path), "--pattern-only", "--output", str(out_dir)])
    assert rc == 0
    nested = out_dir / "sub" / "deep_anonymized.txt"
    assert nested.exists()


def test_no_recursive_skips_nested_files(tmp_path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.txt").write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    (tmp_path / "top.txt").write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(tmp_path), "--pattern-only", "--no-recursive", "--output", str(out_dir)])
    assert rc == 0
    nested = out_dir / "sub" / "deep_anonymized.txt"
    assert not nested.exists()


# ===========================================================================
# --json su cartella (batch audit)
# ===========================================================================

def test_json_flag_on_folder_prints_batch_audit(tmp_path, capsys) -> None:
    (tmp_path / "a.txt").write_text("CF RSSMRA80A01L219M", encoding="utf-8")
    (tmp_path / "b.txt").write_text("IBAN IT60X0542811101000000123456", encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main([str(tmp_path), "--pattern-only", "--output", str(out_dir), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["processed_count"] == 2
    assert "files" in data
