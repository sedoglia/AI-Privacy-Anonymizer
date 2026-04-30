from privacy_anonymizer import Anonymizer


def test_process_text_masks_values_and_counts_categories() -> None:
    anonymized, counts = Anonymizer().process_text(
        "CF RSSMRA80A01L219X email mario.rossi@example.com tel 3401234567"
    )

    assert "RSSMRA80A01L219X" not in anonymized
    assert "mario.rossi@example.com" not in anonymized
    assert "3401234567" not in anonymized
    assert "[CF_1]" in anonymized
    assert counts["CODICE_FISCALE"] == 1
    assert counts["EMAIL"] == 1
    assert counts["TELEFONO_IT"] == 1


def test_process_file_writes_output_and_audit(tmp_path) -> None:
    source = tmp_path / "input.txt"
    output = tmp_path / "clean.txt"
    source.write_text("CF RSSMRA80A01L219X", encoding="utf-8")

    result = Anonymizer().process_file(source, output_path=output)

    assert result.output_path == output
    assert output.read_text(encoding="utf-8") == "CF [CF_1]"
    assert output.with_suffix(".txt.audit.json").exists()
