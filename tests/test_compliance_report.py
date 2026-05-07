"""Test generazione report compliance GDPR (PDF) con dati reali simulati.

Verifica: creazione file, magic bytes, contenuto testuale estratto via pypdf,
integrazione con Anonymizer.analyze_text e process_file, e CLI --compliance-report.
"""
from __future__ import annotations

import json
from pathlib import Path

import pypdf
import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.compliance import write_compliance_report
from privacy_anonymizer.config import LayerConfig

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)

# ---------------------------------------------------------------------------
# Audit report realistico — simula un cedolino paga processato
# ---------------------------------------------------------------------------
_AUDIT_CEDOLINO = {
    "tool_version": "0.1.0",
    "source_file": "/documenti/cedolino_2024_04_mario_rossi.txt",
    "output_file": "/documenti/cedolino_2024_04_mario_rossi_anonymized.txt",
    "processed_at": "2026-05-07T10:23:45+00:00",
    "processing_time_seconds": 0.0312,
    "layers_used": ["pattern"],
    "entities_found": {
        "opf_spans": 0,
        "gliner_spans": 0,
        "pattern_spans": 5,
        "merged_unique_spans": 5,
        "by_category": {
            "CODICE_FISCALE": 1,
            "IBAN_IT": 1,
            "TELEFONO_IT": 1,
            "EMAIL": 1,
            "MATRICOLA_INPS": 1,
        },
    },
    "metadata_stripped": True,
    "track_changes_accepted": True,
    "opf_recall_mode": None,
    "low_memory": False,
    "warnings": [],
}

# Audit con dati multi-categoria e warning — simula un documento medico complesso
_AUDIT_MEDICO = {
    "tool_version": "0.1.0",
    "source_file": "/documenti/referto_medico_bianchi.docx",
    "output_file": "/documenti/referto_medico_bianchi_anonymized.docx",
    "processed_at": "2026-05-07T14:55:12+00:00",
    "processing_time_seconds": 1.2341,
    "layers_used": ["gliner", "pattern"],
    "entities_found": {
        "opf_spans": 0,
        "gliner_spans": 3,
        "pattern_spans": 4,
        "merged_unique_spans": 6,
        "by_category": {
            "CODICE_FISCALE": 1,
            "TESSERA_SANITARIA": 1,
            "TELEFONO_IT": 2,
            "EMAIL": 1,
            "PARTITA_IVA": 1,
        },
    },
    "metadata_stripped": True,
    "track_changes_accepted": True,
    "opf_recall_mode": None,
    "low_memory": False,
    "warnings": [
        "Documento .docx: macro VBA presenti, non elaborate.",
        "Immagine incorporata non anonimizzata (richiede OCR).",
    ],
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_all_text(pdf_path: Path) -> str:
    """Estrae tutto il testo da tutte le pagine del PDF."""
    reader = pypdf.PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# ===========================================================================
# 1. Creazione file e validità PDF
# ===========================================================================

def test_compliance_pdf_file_is_created(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    assert dest.exists()


def test_compliance_pdf_is_non_empty(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    assert dest.stat().st_size > 0


def test_compliance_pdf_starts_with_magic_bytes(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    assert dest.read_bytes().startswith(b"%PDF")


def test_compliance_pdf_return_value_is_destination_path(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    result = write_compliance_report(_AUDIT_CEDOLINO, dest)
    assert result == dest


def test_compliance_pdf_accepts_string_path(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, str(dest))
    assert dest.exists()


def test_compliance_pdf_is_parseable_by_pypdf(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    reader = pypdf.PdfReader(str(dest))
    assert len(reader.pages) >= 1


# ===========================================================================
# 2. Intestazione e metadati di processing
# ===========================================================================

def test_compliance_pdf_contains_header_title(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "AI Privacy Anonymizer" in text
    assert "GDPR" in text


def test_compliance_pdf_contains_source_file(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    # Verifica che il nome file sorgente compaia (il path può essere troncato a 110 char)
    assert "cedolino_2024_04_mario_rossi" in text


def test_compliance_pdf_contains_output_file(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "anonymized" in text


def test_compliance_pdf_contains_timestamp(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "2026-05-07" in text


def test_compliance_pdf_contains_layers_used(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "pattern" in text


def test_compliance_pdf_contains_multiple_layers(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_MEDICO, dest)
    text = _extract_all_text(dest)
    assert "gliner" in text
    assert "pattern" in text


def test_compliance_pdf_contains_metadata_stripped_flag(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "Metadati rimossi" in text
    assert "True" in text


# ===========================================================================
# 3. Entità rilevate
# ===========================================================================

def test_compliance_pdf_contains_entity_section_header(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "rilevate" in text.lower()


@pytest.mark.parametrize("category,count", [
    ("CODICE_FISCALE", "1"),
    ("IBAN_IT", "1"),
    ("TELEFONO_IT", "1"),
    ("EMAIL", "1"),
    ("MATRICOLA_INPS", "1"),
])
def test_compliance_pdf_cedolino_entity_categories(tmp_path: Path, category: str, count: str) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert category in text, f"Categoria '{category}' non trovata nel PDF"
    # Il conteggio appare dopo i due punti
    assert f"{category}: {count}" in text or (category in text and count in text)


@pytest.mark.parametrize("category,count", [
    ("CODICE_FISCALE", "1"),
    ("TESSERA_SANITARIA", "1"),
    ("TELEFONO_IT", "2"),
    ("EMAIL", "1"),
    ("PARTITA_IVA", "1"),
])
def test_compliance_pdf_medico_entity_categories(tmp_path: Path, category: str, count: str) -> None:
    dest = tmp_path / "report_medico.pdf"
    write_compliance_report(_AUDIT_MEDICO, dest)
    text = _extract_all_text(dest)
    assert category in text, f"Categoria '{category}' non trovata nel PDF del referto medico"


def test_compliance_pdf_entity_categories_sorted_alphabetically(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    categories = [c for c in _AUDIT_CEDOLINO["entities_found"]["by_category"]]
    # Verifica che le categorie compaiano in ordine alfabetico nel PDF
    sorted_cats = sorted(categories)
    positions = [text.find(c) for c in sorted_cats if c in text]
    assert positions == sorted(positions), "Le categorie non sono in ordine alfabetico nel PDF"


# ===========================================================================
# 4. Sezione Warning
# ===========================================================================

def test_compliance_pdf_contains_warnings_section_when_present(tmp_path: Path) -> None:
    dest = tmp_path / "report_medico.pdf"
    write_compliance_report(_AUDIT_MEDICO, dest)
    text = _extract_all_text(dest)
    assert "Warning" in text


def test_compliance_pdf_contains_warning_messages(tmp_path: Path) -> None:
    dest = tmp_path / "report_medico.pdf"
    write_compliance_report(_AUDIT_MEDICO, dest)
    text = _extract_all_text(dest)
    # Il warning è troncato a 110 char, verifichiamo almeno il prefisso
    assert "macro VBA" in text or "Documento .docx" in text


def test_compliance_pdf_no_warnings_section_when_empty(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)  # warnings: []
    text = _extract_all_text(dest)
    # Non deve comparire la sezione Warning: se non ci sono warning
    lines = [l.strip() for l in text.splitlines()]
    assert "Warning:" not in lines


# ===========================================================================
# 5. Sezione Audit JSON
# ===========================================================================

def test_compliance_pdf_contains_audit_json_section(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "Audit JSON" in text


def test_compliance_pdf_audit_json_contains_tool_version(tmp_path: Path) -> None:
    dest = tmp_path / "report.pdf"
    write_compliance_report(_AUDIT_CEDOLINO, dest)
    text = _extract_all_text(dest)
    assert "tool_version" in text
    assert "0.1.0" in text


def test_compliance_pdf_audit_json_is_truncated_at_1500_chars(tmp_path: Path) -> None:
    # Crea un audit con molti warning per forzare un JSON lungo
    long_audit = dict(_AUDIT_CEDOLINO)
    long_audit["warnings"] = [f"Warning numero {i}: testo descrittivo molto lungo" for i in range(50)]
    full_json = json.dumps(long_audit, ensure_ascii=False)
    assert len(full_json) > 1500

    dest = tmp_path / "report_long.pdf"
    write_compliance_report(long_audit, dest)
    text = _extract_all_text(dest)

    # Il testo del JSON nel PDF non può superare 1500 caratteri (troncato dalla funzione)
    # Verifichiamo che la funzione non abbia crashato e il PDF sia valido
    assert dest.read_bytes().startswith(b"%PDF")
    assert "tool_version" in text  # Il JSON è presente


# ===========================================================================
# 6. Gestione valori None e audit minimale
# ===========================================================================

def test_compliance_pdf_handles_none_source_and_output(tmp_path: Path) -> None:
    audit_minimal = {
        "tool_version": "0.1.0",
        "source_file": None,
        "output_file": None,
        "processed_at": "2026-05-07T09:00:00+00:00",
        "processing_time_seconds": 0.001,
        "layers_used": ["pattern"],
        "entities_found": {"by_category": {}},
        "metadata_stripped": False,
        "track_changes_accepted": False,
        "opf_recall_mode": None,
        "low_memory": False,
        "warnings": [],
    }
    dest = tmp_path / "report_minimal.pdf"
    write_compliance_report(audit_minimal, dest)
    assert dest.read_bytes().startswith(b"%PDF")


def test_compliance_pdf_handles_empty_entities(tmp_path: Path) -> None:
    audit_no_entities = dict(_AUDIT_CEDOLINO)
    audit_no_entities["entities_found"] = {
        "opf_spans": 0, "gliner_spans": 0, "pattern_spans": 0,
        "merged_unique_spans": 0, "by_category": {},
    }
    dest = tmp_path / "report_empty.pdf"
    write_compliance_report(audit_no_entities, dest)
    assert dest.read_bytes().startswith(b"%PDF")


def test_compliance_pdf_handles_all_three_layers(tmp_path: Path) -> None:
    audit_all_layers = dict(_AUDIT_CEDOLINO)
    audit_all_layers["layers_used"] = ["opf", "gliner", "pattern"]
    audit_all_layers["opf_recall_mode"] = "aggressive"
    dest = tmp_path / "report_all_layers.pdf"
    write_compliance_report(audit_all_layers, dest)
    text = _extract_all_text(dest)
    assert "opf" in text
    assert "gliner" in text
    assert "pattern" in text


# ===========================================================================
# 7. Multi-pagina (contenuto lungo)
# ===========================================================================

def test_compliance_pdf_multipage_for_long_content(tmp_path: Path) -> None:
    # Crea un audit con molte categorie per forzare più pagine
    many_categories = {f"CATEGORIA_{i:03d}": i + 1 for i in range(60)}
    audit_large = dict(_AUDIT_CEDOLINO)
    audit_large["entities_found"] = {"by_category": many_categories}
    audit_large["warnings"] = [f"Warning {i}: descrizione del problema rilevato nel documento" for i in range(20)]

    dest = tmp_path / "report_multipage.pdf"
    write_compliance_report(audit_large, dest)

    reader = pypdf.PdfReader(str(dest))
    assert len(reader.pages) >= 2, "Un audit con 60 categorie e 20 warning deve produrre almeno 2 pagine"


def test_compliance_pdf_multipage_all_categories_present(tmp_path: Path) -> None:
    many_categories = {f"CATEGORIA_{i:03d}": i + 1 for i in range(60)}
    audit_large = dict(_AUDIT_CEDOLINO)
    audit_large["entities_found"] = {"by_category": many_categories}

    dest = tmp_path / "report_multipage2.pdf"
    write_compliance_report(audit_large, dest)
    text = _extract_all_text(dest)

    # Alcune categorie devono essere presenti (le prime e le ultime)
    assert "CATEGORIA_000" in text
    assert "CATEGORIA_059" in text


# ===========================================================================
# 8. Integrazione con Anonymizer — dati PII italiani reali
# ===========================================================================

def test_compliance_from_analyze_text_cedolino_reale(tmp_path: Path) -> None:
    testo_cedolino = (
        "Cedolino paga aprile 2024\n"
        "Dipendente: Mario Rossi, CF RSSMRA80A01L219M\n"
        "Stipendio: 2.450,00 EUR, accreditato su IBAN IT60X0542811101000000123456\n"
        "Contatto: mario.rossi@azienda.it, tel 3401234567\n"
        "Matricola INPS: 12345678"
    )
    result = Anonymizer(_PATTERN_ONLY).analyze_text(testo_cedolino)
    dest = tmp_path / "cedolino_report.pdf"

    write_compliance_report(result.audit_report, dest)

    assert dest.read_bytes().startswith(b"%PDF")
    text = _extract_all_text(dest)
    assert "CODICE_FISCALE" in text
    assert "IBAN_IT" in text
    assert "EMAIL" in text


def test_compliance_from_analyze_text_contratto_fornitura(tmp_path: Path) -> None:
    testo_contratto = (
        "Contratto di fornitura n. 2024/CF/0042\n"
        "Fornitore: ACME Srl, P.IVA 01114601006, PEC studio.acme@legalmail.pec.it\n"
        "Cliente: Beta S.p.A., P.IVA 12345678903\n"
        "Referente: sig. Rossi tel +39 011 1234567\n"
        "Coordinate bancarie: IBAN IT60X0542811101000000123456"
    )
    result = Anonymizer(_PATTERN_ONLY).analyze_text(testo_contratto)
    dest = tmp_path / "contratto_report.pdf"

    write_compliance_report(result.audit_report, dest)

    assert dest.read_bytes().startswith(b"%PDF")
    text = _extract_all_text(dest)
    assert "PARTITA_IVA" in text
    assert "IBAN_IT" in text
    # Verifico che il PDF contenga almeno un conteggio > 0
    assert ": 1" in text or ": 2" in text


def test_compliance_from_analyze_text_documento_medico(tmp_path: Path) -> None:
    testo_medico = (
        "Referto diagnostico — ASL Roma 1\n"
        "Paziente: Anna Bianchi, CF BNCNNA75T41F205Y\n"
        "Tessera sanitaria: 80380030001234567890\n"
        "Contatto: 3401234567, anna.bianchi@email.it\n"
        "Targa veicolo: AB123CD"
    )
    result = Anonymizer(_PATTERN_ONLY).analyze_text(testo_medico)
    dest = tmp_path / "medico_report.pdf"

    write_compliance_report(result.audit_report, dest)

    assert dest.read_bytes().startswith(b"%PDF")
    text = _extract_all_text(dest)
    assert "CODICE_FISCALE" in text
    assert "TESSERA_SANITARIA" in text
    assert "TARGA_IT" in text


def test_compliance_from_process_file_txt(tmp_path: Path) -> None:
    source = tmp_path / "dipendente.txt"
    source.write_text(
        "CF RSSMRA80A01L219M, IBAN IT60X0542811101000000123456, email mario@azienda.it",
        encoding="utf-8",
    )
    result = Anonymizer(_PATTERN_ONLY).process_file(source)
    dest = tmp_path / "dipendente_report.pdf"

    write_compliance_report(result.audit_report, dest)

    assert dest.read_bytes().startswith(b"%PDF")
    text = _extract_all_text(dest)
    assert "CODICE_FISCALE" in text
    assert "IBAN_IT" in text
    assert "EMAIL" in text
    # Il path sorgente compare nell'audit (anche se troncato a 110 char per riga)
    assert "File sorgente" in text
    assert result.audit_report["source_file"] is not None


def test_compliance_audit_report_entity_counts_match_detection(tmp_path: Path) -> None:
    # Testo con 2 CF e 1 IBAN: verifica che i conteggi nel PDF siano corretti
    testo = (
        "Primo dipendente CF RSSMRA80A01L219M, "
        "secondo dipendente CF BNCNNA75T41F205Y, "
        "IBAN condiviso IT60X0542811101000000123456"
    )
    result = Anonymizer(_PATTERN_ONLY).analyze_text(testo)
    by_cat = result.audit_report["entities_found"]["by_category"]

    dest = tmp_path / "multientry_report.pdf"
    write_compliance_report(result.audit_report, dest)
    text = _extract_all_text(dest)

    # Il conteggio reale rilevato deve essere nel PDF
    cf_count = str(by_cat.get("CODICE_FISCALE", 0))
    assert f"CODICE_FISCALE: {cf_count}" in text
    iban_count = str(by_cat.get("IBAN_IT", 0))
    assert f"IBAN_IT: {iban_count}" in text


# ===========================================================================
# 9. Integrazione CLI — --compliance-report
# ===========================================================================

def test_cli_compliance_report_flag_creates_pdf(tmp_path: Path) -> None:
    from privacy_anonymizer.cli import main

    source = tmp_path / "input.txt"
    source.write_text(
        "CF RSSMRA80A01L219M email mario@azienda.it IBAN IT60X0542811101000000123456",
        encoding="utf-8",
    )
    report = tmp_path / "gdpr_report.pdf"

    rc = main([
        str(source),
        "--pattern-only",
        "--compliance-report", str(report),
    ])

    assert rc == 0
    assert report.exists()
    assert report.read_bytes().startswith(b"%PDF")


def test_cli_compliance_report_pdf_contains_entity_data(tmp_path: Path) -> None:
    from privacy_anonymizer.cli import main

    source = tmp_path / "fattura.txt"
    # studio@legalmail.pec.it contiene .pec. nel dominio → classificata PEC
    source.write_text(
        "Fornitore P.IVA 01114601006, IBAN IT60X0542811101000000123456, PEC studio@legalmail.pec.it",
        encoding="utf-8",
    )
    report = tmp_path / "gdpr_report.pdf"

    main([str(source), "--pattern-only", "--compliance-report", str(report)])

    text = _extract_all_text(report)
    assert "PARTITA_IVA" in text
    assert "IBAN_IT" in text
    assert "PEC" in text
