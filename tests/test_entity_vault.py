"""Test Entity Vault (de-anonymization) with real Italian PII data."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.cli import _restore_from_vault
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.masking import build_masking_plan

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)

# ---------------------------------------------------------------------------
# Real Italian PII fixtures
# ---------------------------------------------------------------------------
CF = "RSSMRA80A01L219M"
CF2 = "BNCGPP75T18H501Q"
EMAIL = "mario.rossi@azienda.it"
EMAIL2 = "giuseppe.bianchi@comune.roma.it"
IBAN = "IT60X0542811101000000123456"
TELEFONO = "3401234567"
TARGA = "AB123CD"

FULL_TEXT = (
    f"Contribuente: Mario Rossi, CF {CF}, "
    f"email {EMAIL}, tel {TELEFONO}, "
    f"IBAN {IBAN}. "
    f"Secondo contribuente: Giuseppe Bianchi, CF {CF2}, "
    f"email {EMAIL2}."
)


# ---------------------------------------------------------------------------
# 1. Vault structure
# ---------------------------------------------------------------------------

def test_vault_keys_are_placeholders_and_contain_label_and_original() -> None:
    text = f"CF {CF} email {EMAIL}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    vault = plan.entity_vault()

    assert len(vault) >= 2
    for placeholder, entry in vault.items():
        assert "label" in entry, f"Missing 'label' for {placeholder}"
        assert "original" in entry, f"Missing 'original' for {placeholder}"
        assert isinstance(entry["label"], str)
        assert isinstance(entry["original"], str)
        # Placeholder must appear in the anonymized text
        assert placeholder in plan.text, f"{placeholder} not in anonymized text"


def test_vault_original_values_match_source_text() -> None:
    text = f"CF {CF} tel {TELEFONO} IBAN {IBAN}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    originals = {e["original"] for e in plan.entity_vault().values()}

    assert CF in originals
    assert TELEFONO in originals
    assert IBAN in originals


def test_vault_labels_match_entity_types() -> None:
    text = f"CF {CF} email {EMAIL} tel {TELEFONO}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    vault = plan.entity_vault()
    labels = {e["label"] for e in vault.values()}

    assert "CODICE_FISCALE" in labels
    assert "EMAIL" in labels
    assert any(lbl in labels for lbl in ("TELEFONO_IT", "CELL_IT", "TEL_IT"))


# ---------------------------------------------------------------------------
# 2. Consistent placeholder for repeated entity
# ---------------------------------------------------------------------------

def test_same_entity_appearing_twice_gets_single_vault_entry() -> None:
    text = f"CF {CF} e poi ancora CF {CF}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    vault = plan.entity_vault()
    cf_entries = [e for e in vault.values() if e["original"] == CF]

    assert len(cf_entries) == 1, "Repeated entity must map to exactly one vault entry"


def test_same_entity_uses_same_placeholder_in_anonymized_text() -> None:
    text = f"CF {CF} e poi ancora CF {CF}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    # Find the placeholder for CF
    vault = plan.entity_vault()
    placeholder = next(k for k, v in vault.items() if v["original"] == CF)

    assert plan.text.count(placeholder) == 2, "Same entity must use same placeholder both times"


# ---------------------------------------------------------------------------
# 3. All masking modes produce a vault
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["replace", "generalize", "redact", "hash"])
def test_vault_non_empty_for_all_modes(mode: str) -> None:
    text = f"CF {CF} email {EMAIL}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode=mode)

    vault = plan.entity_vault()
    assert len(vault) >= 2


@pytest.mark.parametrize("mode", ["replace", "generalize", "redact", "hash"])
def test_vault_originals_preserved_in_all_modes(mode: str) -> None:
    text = f"CF {CF} IBAN {IBAN}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode=mode)

    originals = {e["original"] for e in plan.entity_vault().values()}
    assert CF in originals
    assert IBAN in originals


# ---------------------------------------------------------------------------
# 4. Full round-trip: anonymize → export vault → restore
# ---------------------------------------------------------------------------

def test_roundtrip_hash_mode_restores_exact_original(tmp_path: Path) -> None:
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(FULL_TEXT, anon.detect_text(FULL_TEXT), mode="hash")

    vault_path = tmp_path / "vault.json"
    vault_path.write_text(json.dumps(plan.entity_vault(), ensure_ascii=False), encoding="utf-8")
    anon_path = tmp_path / "anon.txt"
    anon_path.write_text(plan.text, encoding="utf-8")
    restored_path = tmp_path / "restored.txt"

    rc = _restore_from_vault(str(vault_path), str(anon_path), str(restored_path))

    assert rc == 0
    assert restored_path.read_text(encoding="utf-8") == FULL_TEXT


def test_roundtrip_replace_mode_restores_exact_original(tmp_path: Path) -> None:
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(FULL_TEXT, anon.detect_text(FULL_TEXT), mode="replace")

    vault_path = tmp_path / "vault.json"
    vault_path.write_text(json.dumps(plan.entity_vault(), ensure_ascii=False), encoding="utf-8")
    anon_path = tmp_path / "anon.txt"
    anon_path.write_text(plan.text, encoding="utf-8")
    restored_path = tmp_path / "restored.txt"

    rc = _restore_from_vault(str(vault_path), str(anon_path), str(restored_path))

    assert rc == 0
    assert restored_path.read_text(encoding="utf-8") == FULL_TEXT


def test_roundtrip_no_output_path_uses_default_name(tmp_path: Path) -> None:
    text = f"email {EMAIL}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    vault_path = tmp_path / "vault.json"
    vault_path.write_text(json.dumps(plan.entity_vault(), ensure_ascii=False), encoding="utf-8")
    anon_path = tmp_path / "anon.txt"
    anon_path.write_text(plan.text, encoding="utf-8")

    rc = _restore_from_vault(str(vault_path), str(anon_path), None)

    assert rc == 0
    default_out = tmp_path / "anon_restored.txt"
    assert default_out.exists()
    assert default_out.read_text(encoding="utf-8") == text


# ---------------------------------------------------------------------------
# 5. Multiple distinct entities — vault has one entry per unique PII value
# ---------------------------------------------------------------------------

def test_vault_has_one_entry_per_distinct_entity() -> None:
    text = f"CF {CF} CF {CF2} email {EMAIL} email {EMAIL2}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    vault = plan.entity_vault()
    originals = [e["original"] for e in vault.values()]

    # All four distinct entities must appear exactly once
    assert originals.count(CF) == 1
    assert originals.count(CF2) == 1
    assert originals.count(EMAIL) == 1
    assert originals.count(EMAIL2) == 1


# ---------------------------------------------------------------------------
# 6. Empty vault when no PII present
# ---------------------------------------------------------------------------

def test_vault_empty_when_no_pii_detected() -> None:
    text = "Questo testo non contiene dati personali."
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    assert plan.entity_vault() == {}
    assert plan.text == text


# ---------------------------------------------------------------------------
# 7. analyze_text integration — replacements field feeds the vault
# ---------------------------------------------------------------------------

def test_analyze_text_replacements_build_valid_vault() -> None:
    text = f"CF {CF} tel {TELEFONO}"
    result = Anonymizer(_PATTERN_ONLY).analyze_text(text)

    assert result.replacements is not None
    vault = {r.replacement: {"label": r.label, "original": r.original} for r in result.replacements}

    originals = {v["original"] for v in vault.values()}
    assert CF in originals
    assert TELEFONO in originals


# ---------------------------------------------------------------------------
# 8. Restore error handling — missing input path
# ---------------------------------------------------------------------------

def test_restore_returns_error_when_input_path_is_none(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault.json"
    vault_path.write_text("{}", encoding="utf-8")

    rc = _restore_from_vault(str(vault_path), None, None)

    assert rc == 1


# ---------------------------------------------------------------------------
# 9. Hash mode placeholders have expected SHA256 format
# ---------------------------------------------------------------------------

def test_hash_mode_placeholders_have_sha256_prefix() -> None:
    text = f"CF {CF} email {EMAIL}"
    anon = Anonymizer(_PATTERN_ONLY)
    plan = build_masking_plan(text, anon.detect_text(text), mode="hash")

    for placeholder in plan.entity_vault():
        assert placeholder.startswith("[SHA256:"), f"Unexpected placeholder format: {placeholder}"
        assert placeholder.endswith("]")
        hex_part = placeholder[8:-1]
        assert len(hex_part) == 12
        assert all(c in "0123456789abcdef" for c in hex_part)
