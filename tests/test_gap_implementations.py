from __future__ import annotations

import json
from pathlib import Path

from privacy_anonymizer import Anonymizer, LayerConfig
from privacy_anonymizer.cli import _restore_from_vault
from privacy_anonymizer.evaluation import SYNTHETIC_CASES, evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer.masking import build_masking_plan
from privacy_anonymizer.webui import render_highlighted_html


def test_synthetic_dataset_has_at_least_30_cases() -> None:
    assert len(SYNTHETIC_CASES) >= 30


def test_synthetic_dataset_evaluation_recall_strong(tmp_path: Path) -> None:
    dataset = tmp_path / "synthetic.jsonl"
    write_synthetic_dataset(dataset)
    metrics = evaluate_dataset(dataset)
    assert metrics.recall >= 0.9
    assert metrics.f1 >= 0.85


def test_low_memory_releases_models() -> None:
    anonymizer = Anonymizer(LayerConfig(low_memory=True, pattern_enabled=True))
    spans = anonymizer.detect_text("Mario Rossi, CF RSSMRA80A01L219M, IBAN IT60X0542811101000000123456")
    assert any(span.label == "CODICE_FISCALE" for span in spans)
    assert any(span.label == "IBAN_IT" for span in spans)


def test_parallel_layers_consistent_with_sequential() -> None:
    text = "Mario Rossi CF RSSMRA80A01L219M tel 3401234567 IBAN IT60X0542811101000000123456"
    serial = Anonymizer(LayerConfig(parallel=False)).detect_text(text)
    parallel = Anonymizer(LayerConfig(parallel=True)).detect_text(text)
    assert {span.label for span in serial} == {span.label for span in parallel}


def test_restore_from_vault(tmp_path: Path) -> None:
    text = "Mario Rossi, CF RSSMRA80A01L219M"
    anonymizer = Anonymizer(LayerConfig(masking_mode="hash"))
    plan = build_masking_plan(text, anonymizer.detect_text(text), mode="hash")
    vault_path = tmp_path / "vault.json"
    vault_path.write_text(
        json.dumps(plan.entity_vault(), ensure_ascii=False),
        encoding="utf-8",
    )
    anon_path = tmp_path / "anon.txt"
    anon_path.write_text(plan.text, encoding="utf-8")
    restored_path = tmp_path / "restored.txt"
    _restore_from_vault(str(vault_path), str(anon_path), str(restored_path))
    assert restored_path.read_text(encoding="utf-8") == text


def test_render_highlighted_html_marks_layer_colors() -> None:
    text = "Mario Rossi, CF RSSMRA80A01L219M"
    anonymizer = Anonymizer(LayerConfig(pattern_enabled=True))
    spans = anonymizer.detect_text(text)
    html = render_highlighted_html(text, spans)
    assert "background:#ffd54f" in html
    assert "RSSMRA80A01L219M" in html


def test_fatturapa_warning_recognized(tmp_path: Path) -> None:
    from privacy_anonymizer.io.xml_files import XmlAdapter

    fattura = tmp_path / "fattura.xml"
    fattura.write_text(
        '<?xml version="1.0"?>'
        '<p:FatturaElettronica xmlns:p="http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2">'
        "<CedentePrestatore><DatiAnagrafici><CodiceFiscale>RSSMRA80A01L219M</CodiceFiscale></DatiAnagrafici></CedentePrestatore>"
        "</p:FatturaElettronica>",
        encoding="utf-8",
    )
    content = XmlAdapter().read_text(fattura)
    assert any("FatturaPA" in warning for warning in content.warnings)
    assert "RSSMRA80A01L219M" in content.text
