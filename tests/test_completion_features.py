import json
from pathlib import Path

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.compliance import write_compliance_report
from privacy_anonymizer.evaluation import evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer.mcp_server import handle_request


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


def test_synthetic_dataset_evaluation(tmp_path: Path) -> None:
    dataset = write_synthetic_dataset(tmp_path / "synthetic.jsonl")
    result = evaluate_dataset(dataset)

    assert result.documents == 3
    assert result.recall >= 0.9
    assert result.f1 >= 0.8


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
