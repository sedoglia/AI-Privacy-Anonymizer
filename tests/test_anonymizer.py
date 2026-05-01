from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.io import supported_extensions

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)


def test_process_text_masks_values_and_counts_categories() -> None:
    anonymized, counts = Anonymizer().process_text(
        "CF RSSMRA80A01L219X email mario.rossi@example.com tel 3401234567"
    )

    assert "RSSMRA80A01L219X" not in anonymized
    assert "mario.rossi@example.com" not in anonymized
    assert "3401234567" not in anonymized
    assert "[CF_1]" in anonymized


def test_process_file_writes_output_and_audit(tmp_path) -> None:
    source = tmp_path / "input.txt"
    output = tmp_path / "clean.txt"
    source.write_text("CF RSSMRA80A01L219X", encoding="utf-8")

    result = Anonymizer(_PATTERN_ONLY).process_file(source, output_path=output)

    assert result.output_path == output
    assert output.read_text(encoding="utf-8") == "CF [CF_1]"
    assert output.with_suffix(".txt.audit.json").exists()


def test_process_folder_preserves_relative_paths_and_skips_unknown(tmp_path) -> None:
    source_dir = tmp_path / "input"
    nested = source_dir / "nested"
    output_dir = tmp_path / "output"
    nested.mkdir(parents=True)
    (source_dir / "a.txt").write_text("email mario.rossi@example.com", encoding="utf-8")
    (nested / "b.log").write_text("tel 3401234567", encoding="utf-8")
    (source_dir / "raw.bin").write_bytes(b"raw")

    result = Anonymizer(_PATTERN_ONLY).process_folder(source_dir, output_dir)

    assert result.processed_count == 2
    assert result.skipped_count == 1
    assert (output_dir / "a_anonymized.txt").read_text(encoding="utf-8") == "email [EMAIL_1]"
    assert (output_dir / "nested" / "b_anonymized.log").read_text(encoding="utf-8") == "tel [TEL_1]"


def test_supported_formats_include_text_and_office_extensions() -> None:
    assert {".txt", ".docx", ".xlsx", ".pptx"} <= set(supported_extensions())
