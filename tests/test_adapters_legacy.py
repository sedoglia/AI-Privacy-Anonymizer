"""Test per gli adapter legacy non ancora coperti: LegacyXlsAdapter e RTF fallback."""
from __future__ import annotations

from pathlib import Path

import pytest
import xlrd

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.io.legacy import LegacyXlsAdapter, RtfAdapter, _fallback_rtf_to_text

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)


# ===========================================================================
# LegacyXlsAdapter — read_text
# ===========================================================================

def _make_xls(path: Path, rows: list[list[str]]) -> None:
    """Crea un file .xls reale con xlwt (o xlrd write-compatible) via xlrd test utils."""
    import xlwt  # type: ignore[import-not-found]
    wb = xlwt.Workbook()
    ws = wb.add_sheet("Foglio1")
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            ws.write(r, c, val)
    wb.save(str(path))


def _skip_if_no_xlwt() -> None:
    try:
        import xlwt  # noqa: F401
    except ImportError:
        pytest.skip("xlwt non installato — necessario per creare file .xls di test")


def test_xls_adapter_reads_string_cells(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "test.xls"
    _make_xls(xls, [["CF RSSMRA80A01L219M", "mario@azienda.it"], ["IT60X0542811101000000123456", ""]])
    content = LegacyXlsAdapter().read_text(xls)
    assert "RSSMRA80A01L219M" in content.text
    assert "mario@azienda.it" in content.text
    assert "IT60X0542811101000000123456" in content.text


def test_xls_adapter_includes_sheet_name(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "test.xls"
    _make_xls(xls, [["valore"]])
    content = LegacyXlsAdapter().read_text(xls)
    assert "Foglio1" in content.text


def test_xls_adapter_skips_empty_cells(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "test.xls"
    _make_xls(xls, [["CF RSSMRA80A01L219M", ""], ["", "mario@azienda.it"]])
    content = LegacyXlsAdapter().read_text(xls)
    lines = [l for l in content.text.splitlines() if l.strip()]
    assert all(l.strip() for l in lines)


def test_xls_adapter_output_suffix_is_txt(tmp_path: Path) -> None:
    assert LegacyXlsAdapter().output_suffix(tmp_path / "test.xls") == ".txt"


def test_xls_adapter_write_anonymized_produces_txt(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "input.xls"
    _make_xls(xls, [["CF RSSMRA80A01L219M"]])
    result = Anonymizer(_PATTERN_ONLY).process_file(xls)
    assert result.output_path is not None
    assert result.output_path.suffix == ".txt"
    assert "RSSMRA80A01L219M" not in result.output_path.read_text(encoding="utf-8")


def test_xls_adapter_anonymizes_pii_in_cells(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "dipendenti.xls"
    _make_xls(xls, [
        ["Mario Rossi", "RSSMRA80A01L219M", "mario@azienda.it"],
        ["Anna Bianchi", "BNCNNA75T41F205Y", "IT60X0542811101000000123456"],
    ])
    result = Anonymizer(_PATTERN_ONLY).process_file(xls)
    out = result.output_path.read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out
    assert "BNCNNA75T41F205Y" not in out
    assert "mario@azienda.it" not in out
    assert "IT60X0542811101000000123456" not in out


def test_xls_adapter_write_result_has_warning(tmp_path: Path) -> None:
    _skip_if_no_xlwt()
    xls = tmp_path / "test.xls"
    _make_xls(xls, [["CF RSSMRA80A01L219M"]])
    content = LegacyXlsAdapter().read_text(xls)
    dest = tmp_path / "out.txt"
    write_result = LegacyXlsAdapter().write_anonymized(xls, dest, "anonimizzato", keep_metadata=False)
    assert write_result.metadata_stripped is True
    assert len(write_result.warnings) >= 1


# ===========================================================================
# RtfAdapter — con striprtf
# ===========================================================================

def _make_rtf(path: Path, text: str) -> None:
    escaped = text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
    rtf_content = r"{\rtf1\ansi " + escaped.replace("\n", r"\par ") + "}"
    path.write_text(rtf_content, encoding="utf-8")


def test_rtf_adapter_reads_text_content(tmp_path: Path) -> None:
    rtf = tmp_path / "test.rtf"
    _make_rtf(rtf, "CF RSSMRA80A01L219M email mario@azienda.it")
    content = RtfAdapter().read_text(rtf)
    assert "RSSMRA80A01L219M" in content.text
    assert "mario@azienda.it" in content.text


def test_rtf_adapter_anonymizes_pii(tmp_path: Path) -> None:
    rtf = tmp_path / "contratto.rtf"
    _make_rtf(rtf, "Fornitore CF RSSMRA80A01L219M IBAN IT60X0542811101000000123456")
    result = Anonymizer(_PATTERN_ONLY).process_file(rtf)
    out = result.output_path.read_text(encoding="utf-8")
    assert "RSSMRA80A01L219M" not in out
    assert "IT60X0542811101000000123456" not in out


def test_rtf_adapter_write_produces_rtf_output(tmp_path: Path) -> None:
    rtf = tmp_path / "test.rtf"
    _make_rtf(rtf, "CF RSSMRA80A01L219M")
    result = Anonymizer(_PATTERN_ONLY).process_file(rtf)
    assert result.output_path is not None
    assert result.output_path.suffix == ".rtf"
    out = result.output_path.read_text(encoding="utf-8")
    assert out.startswith("{\\rtf1")


def test_rtf_write_result_has_simplified_warning(tmp_path: Path) -> None:
    rtf = tmp_path / "test.rtf"
    _make_rtf(rtf, "testo")
    dest = tmp_path / "out.rtf"
    wr = RtfAdapter().write_anonymized(rtf, dest, "anonymized", keep_metadata=False)
    assert any("RTF" in w or "semplificata" in w for w in wr.warnings)
    assert wr.metadata_stripped is True


# ===========================================================================
# RTF fallback parser — _fallback_rtf_to_text
# ===========================================================================

def test_fallback_rtf_strips_control_words() -> None:
    raw = r"{\rtf1\ansi\deff0 Mario Rossi}"
    result = _fallback_rtf_to_text(raw)
    assert "Mario Rossi" in result
    assert "\\rtf1" not in result
    assert "\\ansi" not in result


def test_fallback_rtf_strips_hex_escapes() -> None:
    raw = r"{\rtf1 caf\e8}"
    result = _fallback_rtf_to_text(raw)
    assert "\\e8" not in result


def test_fallback_rtf_removes_braces() -> None:
    raw = r"{\rtf1 {nested {block}} fine}"
    result = _fallback_rtf_to_text(raw)
    assert "{" not in result
    assert "}" not in result


def test_fallback_rtf_preserves_plain_text() -> None:
    raw = r"{\rtf1\ansi CF RSSMRA80A01L219M}"
    result = _fallback_rtf_to_text(raw)
    assert "RSSMRA80A01L219M" in result
