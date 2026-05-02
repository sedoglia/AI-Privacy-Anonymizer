from __future__ import annotations

import json
from pathlib import Path

from privacy_anonymizer import Anonymizer, LayerConfig
from privacy_anonymizer.cli import _restore_from_vault
from privacy_anonymizer.compliance import write_compliance_report
from privacy_anonymizer.evaluation import SYNTHETIC_CASES, evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer.masking import build_masking_plan
from privacy_anonymizer.mcp_server import handle_request
from privacy_anonymizer.webui import render_highlighted_html


def test_synthetic_dataset_has_at_least_30_cases() -> None:
    assert len(SYNTHETIC_CASES) >= 30


def test_synthetic_dataset_evaluation_recall_strong(tmp_path: Path) -> None:
    dataset = tmp_path / "synthetic.jsonl"
    write_synthetic_dataset(dataset)
    metrics = evaluate_dataset(dataset, anonymizer=Anonymizer(LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)))
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


def test_xml_adapter_masks_text_and_attributes(tmp_path: Path) -> None:
    source = tmp_path / "fattura.xml"
    source.write_text(
        '<Fattura><Cedente email="mario.rossi@example.com"><CodiceFiscale>RSSMRA80A01L219X</CodiceFiscale></Cedente></Fattura>',
        encoding="utf-8",
    )

    result = Anonymizer().process_file(source)
    output = result.output_path.read_text(encoding="utf-8")

    assert "mario.rossi@example.com" not in output
    assert "RSSMRA80A01L219X" not in output


def test_legacy_doc_outputs_txt(tmp_path: Path) -> None:
    source = tmp_path / "legacy.doc"
    source.write_bytes(b"CF RSSMRA80A01L219X")

    result = Anonymizer().process_file(source)

    assert result.output_path.suffix == ".txt"
    assert "RSSMRA80A01L219X" not in result.output_path.read_text(encoding="utf-8")


def test_compliance_report_writes_pdf(tmp_path: Path) -> None:
    result = Anonymizer().analyze_text("CF RSSMRA80A01L219X")
    destination = tmp_path / "report.pdf"

    write_compliance_report(result.audit_report, destination)

    assert destination.exists()
    assert destination.read_bytes().startswith(b"%PDF")


def test_mcp_anonymize_text_tool() -> None:
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "anonymize_text", "arguments": {"text": "CF RSSMRA80A01L219X"}},
        }
    )

    assert response["result"]["content"][0]["text"] == "CF [CF_1]"
    assert response["result"]["structuredContent"]["counts"]["CODICE_FISCALE"] == 1


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
