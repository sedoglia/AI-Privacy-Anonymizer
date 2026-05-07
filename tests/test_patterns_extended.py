"""Test estesi per il layer pattern — ogni regex individualmente.

Copre: INDIRIZZO_IT, DOCUMENTO_ID, CARTA_IDENTITA formati multipli,
PEC vs EMAIL, TEL_IT vs CELL_IT, IPv4 ottetti invalidi, checksum rejection,
falsi positivi del resolver, filtro PATENTE/PERSONA/ACCOUNT_NUMBER.
"""
from __future__ import annotations

import pytest

from privacy_anonymizer.detectors.patterns_it import (
    ItalianPatternDetector,
    validate_codice_fiscale,
    validate_iban,
    validate_partita_iva,
)
from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import _is_false_positive, resolve_spans

_D = ItalianPatternDetector()


def _labels(text: str) -> set[str]:
    return {span.label for span in _D.detect(text)}


def _spans(text: str) -> list[DetectionSpan]:
    return _D.detect(text)


# ===========================================================================
# INDIRIZZO_IT
# ===========================================================================

@pytest.mark.parametrize("text", [
    "Via Roma 12",
    "Corso Vittorio Emanuele 45",
    "Piazza Navona 3",
    "Viale della Repubblica 100",
    "Vicolo Corto 7",
    "Largo dei Lombardi 2",
])
def test_indirizzo_it_detected(text: str) -> None:
    assert "INDIRIZZO" in _labels(text), f"INDIRIZZO non rilevato in: {text!r}"


def test_indirizzo_it_with_interno() -> None:
    assert "INDIRIZZO" in _labels("Via Garibaldi 10 int. 3")


def test_indirizzo_it_with_scala() -> None:
    assert "INDIRIZZO" in _labels("Corso Italia 15 scala B")


# ===========================================================================
# DOCUMENTO_ID
# ===========================================================================

@pytest.mark.parametrize("text,expected_in", [
    ("ID-ABC123", True),
    ("ID-XYZ9876543", True),
    ("codice ID-DOC001", True),
    ("ID-X", False),  # troppo corto
])
def test_documento_id_detection(text: str, expected_in: bool) -> None:
    found = "DOCUMENTO_ID" in _labels(text)
    assert found == expected_in, f"DOCUMENTO_ID detected={found} per {text!r}"


# ===========================================================================
# CARTA_IDENTITA — formati multipli
# ===========================================================================

@pytest.mark.parametrize("ci", [
    "AX1234567",    # formato classico: 2 lettere + 7 cifre
    "CA1234567AB",  # formato elettronico: CA + 7 cifre + 2 lettere
])
def test_carta_identita_formats(ci: str) -> None:
    assert "CARTA_IDENTITA" in _labels(ci), f"CARTA_IDENTITA non rilevata per {ci!r}"


def test_carta_identita_in_sentence() -> None:
    assert "CARTA_IDENTITA" in _labels("Documento d'identità AX1234567 di Anna Bianchi")


# ===========================================================================
# PEC vs EMAIL
# ===========================================================================

@pytest.mark.parametrize("email,expected_label", [
    ("studio.rossi@legalmail.pec.it", "PEC"),
    ("admin@comune.pec.it", "PEC"),
    ("mario.rossi@azienda.it", "EMAIL"),
    ("info@example.com", "EMAIL"),
    ("user@subdomain.pec.example.com", "PEC"),  # .pec. nel dominio
])
def test_pec_vs_email_classification(email: str, expected_label: str) -> None:
    labels = _labels(email)
    assert expected_label in labels, f"Atteso {expected_label} per {email!r}, trovato {labels}"


# ===========================================================================
# TEL_IT vs CELL_IT
# ===========================================================================

@pytest.mark.parametrize("tel,expected_label", [
    ("3401234567", "CELL_IT"),       # mobile: inizia con 3
    ("+39 340 1234567", "CELL_IT"),
    ("011 1234567", "TEL_IT"),        # fisso: inizia con 0
    ("+39 011 1234567", "TEL_IT"),
    ("06 12345678", "TEL_IT"),
])
def test_tel_vs_cell_classification(tel: str, expected_label: str) -> None:
    found_labels = _labels(tel)
    assert expected_label in found_labels, f"Atteso {expected_label} per {tel!r}, trovato {found_labels}"


# ===========================================================================
# IPv4 — ottetti invalidi rifiutati
# ===========================================================================

def test_ipv4_valid_detected() -> None:
    assert "IP_ADDRESS" in _labels("server 192.168.1.10 down")
    assert "IP_ADDRESS" in _labels("host 10.0.0.42")
    assert "IP_ADDRESS" in _labels("gateway 172.16.0.1")
    assert "IP_ADDRESS" in _labels("DNS 8.8.8.8")


def test_ipv4_invalid_octets_not_detected() -> None:
    # 999.1.1.1 — ottetto > 255 → non valido
    assert "IP_ADDRESS" not in _labels("addr 999.1.1.1 invalid")
    assert "IP_ADDRESS" not in _labels("addr 256.0.0.1 invalid")


def test_ipv4_broadcast_detected() -> None:
    assert "IP_ADDRESS" in _labels("broadcast 255.255.255.0")


# ===========================================================================
# TESSERA SANITARIA
# ===========================================================================

def test_tessera_sanitaria_detected() -> None:
    assert "TESSERA_SANITARIA" in _labels("TS 80380030001234567890")


def test_tessera_sanitaria_requires_correct_prefix() -> None:
    # Non inizia con 80 → non deve matchare
    assert "TESSERA_SANITARIA" not in _labels("12345678901234567890")


# ===========================================================================
# MATRICOLA INPS — pattern con keyword
# ===========================================================================

@pytest.mark.parametrize("text", [
    "matricola 12345678",
    "matricola INPS 87654321",
    "INPS: 11223344",
    "INPS #99887766",
])
def test_matricola_inps_detected(text: str) -> None:
    assert "MATRICOLA_INPS" in _labels(text), f"MATRICOLA_INPS non rilevata in: {text!r}"


# ===========================================================================
# Checksum validation — rifiuto valori non validi
# ===========================================================================

def test_invalid_cf_checksum_still_detected_but_flagged() -> None:
    # Il CF invalido viene rilevato ma con checksum_valid=false
    spans = _spans("CF RSSMRA80A01L219X")
    cf = next((s for s in spans if s.label == "CODICE_FISCALE"), None)
    assert cf is not None
    assert cf.metadata.get("checksum_valid") == "false"


def test_valid_cf_checksum_flagged_true() -> None:
    spans = _spans("CF RSSMRA80A01L219M")
    cf = next((s for s in spans if s.label == "CODICE_FISCALE"), None)
    assert cf is not None
    assert cf.metadata.get("checksum_valid") == "true"


def test_invalid_piva_checksum_not_detected() -> None:
    # P.IVA con checksum errato NON viene rilevata (filtrata da validate_partita_iva)
    assert "PARTITA_IVA" not in _labels("P.IVA 01114601007")


def test_invalid_iban_checksum_not_detected() -> None:
    assert "IBAN_IT" not in _labels("IBAN IT61X0542811101000000123456")


# ===========================================================================
# Falsi positivi del resolver
# ===========================================================================

@pytest.mark.parametrize("word", [
    "Roma", "Milano", "Napoli", "Torino", "Firenze",
    "Mouse", "Tastiera", "Laptop", "Monitor",
    "Prodotto", "Fattura", "Ordine",
    "Analista", "Responsabile", "Direttore",
    "Email", "Telefono", "Indirizzo",
])
def test_false_positive_words_rejected(word: str) -> None:
    assert _is_false_positive(word), f"{word!r} dovrebbe essere falso positivo"


@pytest.mark.parametrize("word", [
    "Mario Rossi", "Anna Bianchi", "Giuseppe Verdi",
    "RSSMRA80A01L219M", "mario@azienda.it",
])
def test_real_entities_not_rejected(word: str) -> None:
    assert not _is_false_positive(word), f"{word!r} non dovrebbe essere falso positivo"


# ===========================================================================
# Filtro PATENTE tipo veicolo (da anonymizer._filter_false_positive_personas)
# ===========================================================================

@pytest.mark.parametrize("vehicle_word", [
    "autoveicolo", "motoveicolo", "ciclomotore", "rimorchio",
    "autovettura", "motociclo", "veicolo",
])
def test_patente_vehicle_type_filtered(vehicle_word: str) -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = f"tipo: {vehicle_word}"
    start = text.index(vehicle_word)
    span = DetectionSpan(start, start + len(vehicle_word), "PATENTE", "gliner")
    result = _filter_false_positive_personas(text, [span])
    assert result == [], f"PATENTE vehicolo {vehicle_word!r} non filtrato"


def test_patente_real_license_not_filtered() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "Patente B 1234567"
    span = DetectionSpan(0, len(text), "PATENTE", "gliner")
    result = _filter_false_positive_personas(text, [span])
    assert len(result) == 1


# ===========================================================================
# Filtro PERSONA con cifre
# ===========================================================================

def test_persona_with_digits_filtered() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "codice PA001234"
    span = DetectionSpan(7, 15, "PERSONA", "gliner")
    result = _filter_false_positive_personas(text, [span])
    assert result == []


def test_persona_without_digits_kept() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "Signor Mario Rossi"
    span = DetectionSpan(7, 18, "PERSONA", "gliner")
    result = _filter_false_positive_personas(text, [span])
    assert len(result) == 1


# ===========================================================================
# Reclassificazione ACCOUNT_NUMBER → PERSONA
# ===========================================================================

def test_account_number_multiword_reclassified_as_persona() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "intestatario: Mario Rossi"
    span = DetectionSpan(14, 25, "ACCOUNT_NUMBER", "opf")  # "Mario Rossi"
    result = _filter_false_positive_personas(text, [span])
    assert len(result) == 1
    assert result[0].label == "PERSONA"


def test_account_number_single_word_kept_as_is() -> None:
    from privacy_anonymizer.anonymizer import _filter_false_positive_personas

    text = "account IT12345"
    span = DetectionSpan(8, 15, "ACCOUNT_NUMBER", "opf")  # "IT12345"
    result = _filter_false_positive_personas(text, [span])
    assert len(result) == 1
    assert result[0].label == "ACCOUNT_NUMBER"


# ===========================================================================
# Expand all occurrences — entità ripetuta trovata ovunque
# ===========================================================================

def test_expand_finds_all_occurrences_of_multiword_entity() -> None:
    from privacy_anonymizer.anonymizer import _expand_all_occurrences

    text = "Mario Rossi è il responsabile. Contattare Mario Rossi per info."
    spans = [DetectionSpan(0, 11, "PERSONA", "gliner")]  # solo prima occorrenza
    expanded = _expand_all_occurrences(text, spans)
    persona_spans = [s for s in expanded if s.label == "PERSONA"]
    assert len(persona_spans) == 2


def test_expand_ignores_single_word_entities() -> None:
    from privacy_anonymizer.anonymizer import _expand_all_occurrences

    text = "Mario è qui. Mario è lì."
    spans = [DetectionSpan(0, 5, "PERSONA", "gliner")]  # "Mario" (singola parola)
    expanded = _expand_all_occurrences(text, spans)
    # Le parole singole non vengono espanse
    assert len(expanded) == 1
