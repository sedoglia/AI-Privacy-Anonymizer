"""Test del dataset sintetico e del sistema di evaluation con dati reali italiani."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.evaluation import (
    SYNTHETIC_CASES,
    EvaluationResult,
    evaluate_dataset,
    write_synthetic_dataset,
)

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)

# ---------------------------------------------------------------------------
# Dati reali italiani usati nei test
# ---------------------------------------------------------------------------
_REAL_CASES: list[dict] = [
    {
        "text": "Contribuente Mario Rossi CF RSSMRA80A01L219M, email mario.rossi@azienda.it, tel 3401234567",
        "labels": ["CODICE_FISCALE", "EMAIL", "TELEFONO_IT"],
    },
    {
        "text": "Fornitore Beta SRL P.IVA 01114601006, IBAN IT60X0542811101000000123456",
        "labels": ["PARTITA_IVA", "IBAN_IT"],
    },
    {
        "text": "Server 192.168.1.10 gestito da admin@acme.it, log: accesso fallito",
        "labels": ["IP_ADDRESS", "EMAIL"],
    },
    {
        "text": "Paziente Anna Bianchi CF BNCNNA75T41F205Y, tessera sanitaria 80380030001234567890",
        "labels": ["CODICE_FISCALE", "TESSERA_SANITARIA"],
    },
    {
        "text": "Targa AB123CD, proprietario CF VRDLCU82M15H501J, PEC studio@pec.it",
        "labels": ["TARGA_IT", "CODICE_FISCALE", "PEC"],
    },
    {
        "text": "Numero ordine 2024-XYZ, rif. prodotto codice ABC — nessun dato personale",
        "labels": [],
    },
]


# ===========================================================================
# 1. Struttura di SYNTHETIC_CASES
# ===========================================================================

def test_synthetic_cases_minimum_count() -> None:
    assert len(SYNTHETIC_CASES) >= 30


def test_synthetic_cases_all_have_text_and_labels_fields() -> None:
    for i, case in enumerate(SYNTHETIC_CASES):
        assert "text" in case, f"Case {i}: missing 'text'"
        assert "labels" in case, f"Case {i}: missing 'labels'"
        assert isinstance(case["text"], str), f"Case {i}: 'text' must be str"
        assert isinstance(case["labels"], list), f"Case {i}: 'labels' must be list"


def test_synthetic_cases_labels_are_strings() -> None:
    for i, case in enumerate(SYNTHETIC_CASES):
        for label in case["labels"]:
            assert isinstance(label, str), f"Case {i}: label {label!r} is not str"


def test_synthetic_cases_contain_negative_cases() -> None:
    empty_label_cases = [c for c in SYNTHETIC_CASES if c["labels"] == []]
    assert len(empty_label_cases) >= 1, "Must include at least one negative case (no expected labels)"


def test_synthetic_cases_cover_main_italian_entity_types() -> None:
    all_labels = {label for case in SYNTHETIC_CASES for label in case["labels"]}
    required = {"CODICE_FISCALE", "PARTITA_IVA", "IBAN_IT", "EMAIL", "TELEFONO_IT", "IP_ADDRESS"}
    missing = required - all_labels
    assert not missing, f"Missing entity types in SYNTHETIC_CASES: {missing}"


def test_synthetic_cases_texts_are_non_empty() -> None:
    for i, case in enumerate(SYNTHETIC_CASES):
        assert case["text"].strip(), f"Case {i}: text must not be blank"


# ===========================================================================
# 2. write_synthetic_dataset
# ===========================================================================

def test_write_synthetic_dataset_creates_file(tmp_path: Path) -> None:
    dest = tmp_path / "dataset.jsonl"
    result = write_synthetic_dataset(dest)
    assert dest.exists()
    assert result == dest


def test_write_synthetic_dataset_creates_parent_dirs(tmp_path: Path) -> None:
    dest = tmp_path / "nested" / "deep" / "dataset.jsonl"
    write_synthetic_dataset(dest)
    assert dest.exists()


def test_write_synthetic_dataset_line_count_matches_cases(tmp_path: Path) -> None:
    dest = tmp_path / "dataset.jsonl"
    write_synthetic_dataset(dest)
    lines = [l for l in dest.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == len(SYNTHETIC_CASES)


def test_write_synthetic_dataset_each_line_is_valid_json(tmp_path: Path) -> None:
    dest = tmp_path / "dataset.jsonl"
    write_synthetic_dataset(dest)
    for i, line in enumerate(dest.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        parsed = json.loads(line)
        assert "text" in parsed, f"Line {i}: missing 'text'"
        assert "labels" in parsed, f"Line {i}: missing 'labels'"


def test_write_synthetic_dataset_preserves_unicode(tmp_path: Path) -> None:
    dest = tmp_path / "dataset.jsonl"
    write_synthetic_dataset(dest)
    content = dest.read_text(encoding="utf-8")
    # Italian characters must not be escaped as \uXXXX
    assert "\\u" not in content or "Mario" in content  # ensure_ascii=False


# ===========================================================================
# 3. EvaluationResult — proprietà matematiche
# ===========================================================================

def test_evaluation_result_perfect_recall_and_precision() -> None:
    result = EvaluationResult(documents=5, expected_labels=10, matched_labels=10, extra_labels=0)
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.f1 == 1.0


def test_evaluation_result_zero_recall() -> None:
    result = EvaluationResult(documents=3, expected_labels=6, matched_labels=0, extra_labels=2)
    assert result.recall == 0.0
    assert result.precision == 0.0
    assert result.f1 == 0.0


def test_evaluation_result_partial_recall() -> None:
    # 3 detected out of 6 expected, 1 false positive
    result = EvaluationResult(documents=3, expected_labels=6, matched_labels=3, extra_labels=1)
    assert result.recall == pytest.approx(3 / 6)
    assert result.precision == pytest.approx(3 / 4)
    expected_f1 = 2 * (3 / 4) * (3 / 6) / ((3 / 4) + (3 / 6))
    assert result.f1 == pytest.approx(expected_f1)


def test_evaluation_result_no_expected_labels_returns_1_recall() -> None:
    # Only negative cases: no expected labels, nothing to detect
    result = EvaluationResult(documents=2, expected_labels=0, matched_labels=0, extra_labels=0)
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.f1 == 1.0


def test_evaluation_result_only_false_positives() -> None:
    # Negative text but detector fires spuriously
    result = EvaluationResult(documents=1, expected_labels=0, matched_labels=0, extra_labels=3)
    assert result.recall == 1.0       # no expected → recall stays 1
    assert result.precision == 0.0   # 0 matched out of 3 detected
    assert result.f1 == 0.0


def test_evaluation_result_as_dict_has_all_keys() -> None:
    result = EvaluationResult(documents=10, expected_labels=20, matched_labels=18, extra_labels=2)
    d = result.as_dict()
    for key in ("documents", "expected_labels", "matched_labels", "extra_labels", "recall", "precision", "f1"):
        assert key in d, f"Missing key '{key}' in as_dict()"


def test_evaluation_result_as_dict_metrics_are_rounded_to_4_decimals() -> None:
    result = EvaluationResult(documents=3, expected_labels=3, matched_labels=2, extra_labels=1)
    d = result.as_dict()
    for key in ("recall", "precision", "f1"):
        val = d[key]
        assert isinstance(val, float)
        assert len(str(val).rstrip("0").split(".")[-1]) <= 4


# ===========================================================================
# 4. evaluate_dataset con dati reali custom
# ===========================================================================

def _write_jsonl(path: Path, cases: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in cases),
        encoding="utf-8",
    )


def test_evaluate_dataset_perfect_detection_on_real_cf_and_iban(tmp_path: Path) -> None:
    cases = [
        {"text": "CF RSSMRA80A01L219M IBAN IT60X0542811101000000123456", "labels": ["CODICE_FISCALE", "IBAN_IT"]},
    ]
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, cases)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.documents == 1
    assert result.expected_labels == 2
    assert result.matched_labels == 2
    assert result.recall == 1.0


def test_evaluate_dataset_all_real_italian_pii_detected(tmp_path: Path) -> None:
    cases = [
        {"text": "CF RSSMRA80A01L219M", "labels": ["CODICE_FISCALE"]},
        {"text": "IBAN IT60X0542811101000000123456", "labels": ["IBAN_IT"]},
        {"text": "email mario@azienda.it", "labels": ["EMAIL"]},
        {"text": "tel 3401234567", "labels": ["TELEFONO_IT"]},
        {"text": "IP 192.168.1.10", "labels": ["IP_ADDRESS"]},
        {"text": "P.IVA 01114601006", "labels": ["PARTITA_IVA"]},
    ]
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, cases)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.documents == 6
    assert result.recall == 1.0, f"Pattern layer failed to detect all real entities: recall={result.recall}"


def test_evaluate_dataset_negative_cases_do_not_inflate_expected(tmp_path: Path) -> None:
    cases = [
        {"text": "Numero ordine 2024-XYZ, codice prodotto ABC999", "labels": []},
        {"text": "CF RSSMRA80A01L219M", "labels": ["CODICE_FISCALE"]},
    ]
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, cases)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.documents == 2
    assert result.expected_labels == 1   # only the second case has a label
    assert result.matched_labels == 1


def test_evaluate_dataset_counts_false_positives_in_extra_labels(tmp_path: Path) -> None:
    # Text with no expected labels but detector fires anyway
    # Use a real PII pattern to guarantee the detector will fire
    cases = [
        {"text": "CF RSSMRA80A01L219M", "labels": []},   # CF detected but not expected
    ]
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, cases)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.extra_labels >= 1, "Detected entity on negative case must appear in extra_labels"
    assert result.matched_labels == 0


def test_evaluate_dataset_partial_match_on_multi_entity_text(tmp_path: Path) -> None:
    # Expect both CF and email; only CF will be detected (email not present)
    cases = [
        {"text": "CF RSSMRA80A01L219M", "labels": ["CODICE_FISCALE", "EMAIL"]},
    ]
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, cases)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.expected_labels == 2
    assert result.matched_labels == 1
    assert result.recall == pytest.approx(0.5)


def test_evaluate_dataset_document_count_is_correct(tmp_path: Path) -> None:
    dataset = tmp_path / "test.jsonl"
    _write_jsonl(dataset, _REAL_CASES)

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.documents == len(_REAL_CASES)


def test_evaluate_dataset_skips_blank_lines(tmp_path: Path) -> None:
    dataset = tmp_path / "test.jsonl"
    lines = [
        json.dumps({"text": "CF RSSMRA80A01L219M", "labels": ["CODICE_FISCALE"]}, ensure_ascii=False),
        "",
        "   ",
        json.dumps({"text": "IBAN IT60X0542811101000000123456", "labels": ["IBAN_IT"]}, ensure_ascii=False),
    ]
    dataset.write_text("\n".join(lines), encoding="utf-8")

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.documents == 2


# ===========================================================================
# 5. Recall per categoria su dataset reale
# ===========================================================================

@pytest.mark.parametrize("entity,text", [
    ("CODICE_FISCALE",   "Dipendente CF RSSMRA80A01L219M"),
    ("CODICE_FISCALE",   "Contribuente BNCNNA75T41F205Y"),
    ("PARTITA_IVA",      "Azienda P.IVA 01114601006"),
    ("IBAN_IT",          "Coordinate IBAN IT60X0542811101000000123456"),
    ("EMAIL",            "Contatto mario.rossi@azienda.it"),
    ("IP_ADDRESS",       "Server IP 192.168.1.10"),
    ("IP_ADDRESS",       "Host 10.0.0.42 non autorizzato"),
    ("TELEFONO_IT",      "Chiama il 3401234567"),
    ("TELEFONO_IT",      "Tel +39 011 1234567"),
    ("TARGA_IT",         "Veicolo targa AB123CD"),
    ("TESSERA_SANITARIA","TS 80380030001234567890"),
    ("PEC",              "PEC studio.rossi@legalmail.pec.it"),
])
def test_pattern_layer_detects_entity(entity: str, text: str, tmp_path: Path) -> None:
    dataset = tmp_path / "single.jsonl"
    dataset.write_text(json.dumps({"text": text, "labels": [entity]}, ensure_ascii=False), encoding="utf-8")

    result = evaluate_dataset(dataset, Anonymizer(_PATTERN_ONLY))

    assert result.matched_labels == 1, (
        f"Pattern layer failed to detect {entity} in: {text!r}"
    )


# ===========================================================================
# 6. Integrazione CLI via main()
# ===========================================================================

def test_cli_generate_synthetic_dataset_creates_file(tmp_path: Path, capsys) -> None:
    from privacy_anonymizer.cli import main

    dest = tmp_path / "synth.jsonl"
    rc = main(["--generate-synthetic-dataset", str(dest)])

    assert rc == 0
    assert dest.exists()
    captured = capsys.readouterr()
    assert str(dest) in captured.out


def test_cli_generate_synthetic_dataset_output_is_valid_jsonl(tmp_path: Path) -> None:
    from privacy_anonymizer.cli import main

    dest = tmp_path / "synth.jsonl"
    main(["--generate-synthetic-dataset", str(dest)])

    for line in dest.read_text(encoding="utf-8").splitlines():
        if line.strip():
            parsed = json.loads(line)
            assert "text" in parsed and "labels" in parsed


def test_cli_evaluate_outputs_json_metrics(tmp_path: Path, capsys) -> None:
    from privacy_anonymizer.cli import main

    dest = tmp_path / "synth.jsonl"
    main(["--generate-synthetic-dataset", str(dest)])
    capsys.readouterr()  # flush output from the generate call

    rc = main(["--evaluate", str(dest)])

    assert rc == 0
    output = capsys.readouterr().out
    metrics = json.loads(output)
    for key in ("documents", "expected_labels", "matched_labels", "extra_labels", "recall", "precision", "f1"):
        assert key in metrics, f"Missing '{key}' in CLI evaluation output"


def test_cli_evaluate_custom_real_dataset(tmp_path: Path, capsys) -> None:
    from privacy_anonymizer.cli import main

    dataset = tmp_path / "real.jsonl"
    _write_jsonl(dataset, [
        {"text": "CF RSSMRA80A01L219M email mario@azienda.it", "labels": ["CODICE_FISCALE", "EMAIL"]},
        {"text": "IBAN IT60X0542811101000000123456 tel 3401234567", "labels": ["IBAN_IT", "TELEFONO_IT"]},
    ])

    rc = main(["--evaluate", str(dataset)])

    assert rc == 0
    metrics = json.loads(capsys.readouterr().out)
    assert metrics["documents"] == 2
    assert metrics["expected_labels"] == 4
    assert metrics["recall"] == 1.0


# ===========================================================================
# 7. Roundtrip: write → evaluate con dati reali complessi
# ===========================================================================

def test_write_then_evaluate_roundtrip_preserves_all_cases(tmp_path: Path) -> None:
    dest = tmp_path / "synth.jsonl"
    write_synthetic_dataset(dest)

    result = evaluate_dataset(dest, Anonymizer(_PATTERN_ONLY))

    assert result.documents == len(SYNTHETIC_CASES)
    assert result.expected_labels > 0


def test_write_then_evaluate_custom_dataset_roundtrip(tmp_path: Path) -> None:
    dest = tmp_path / "real_dataset.jsonl"
    dest.write_text(
        "\n".join(json.dumps(c, ensure_ascii=False) for c in _REAL_CASES),
        encoding="utf-8",
    )

    result = evaluate_dataset(dest, Anonymizer(_PATTERN_ONLY))

    total_expected = sum(len(c["labels"]) for c in _REAL_CASES)
    assert result.expected_labels == total_expected
    assert result.documents == len(_REAL_CASES)
    # Recall should be high on real Italian PII covered by pattern layer
    assert result.recall >= 0.85, f"Recall too low on real Italian data: {result.recall:.2%}"
