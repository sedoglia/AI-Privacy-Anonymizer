from privacy_anonymizer.detectors.patterns_it import (
    ItalianPatternDetector,
    validate_codice_fiscale,
    validate_iban,
    validate_partita_iva,
)


def labels_for(text: str) -> list[str]:
    return [span.label for span in ItalianPatternDetector().detect(text)]


def test_codice_fiscale_checksum() -> None:
    assert validate_codice_fiscale("RSSMRA80A01L219M")
    assert not validate_codice_fiscale("RSSMRA80A01L219X")


def test_partita_iva_checksum() -> None:
    assert validate_partita_iva("01114601006")
    assert not validate_partita_iva("01114601007")


def test_iban_checksum() -> None:
    assert validate_iban("IT60X0542811101000000123456")
    assert not validate_iban("IT61X0542811101000000123456")


def test_detector_finds_structured_italian_pii() -> None:
    text = (
        "Mario Rossi CF RSSMRA80A01L219X, P.IVA 01114601006, "
        "IBAN IT60X0542811101000000123456, tel 3401234567, AB123CD."
    )
    assert set(labels_for(text)) >= {
        "CODICE_FISCALE",
        "PARTITA_IVA",
        "IBAN_IT",
        "CELL_IT",
        "TARGA_IT",
    }


def test_detector_finds_tessera_sanitaria_and_matricola_inps() -> None:
    text = "Tessera 80380030001234567890 matricola INPS 12345678 attiva."
    labels = set(labels_for(text))
    assert "TESSERA_SANITARIA" in labels
    assert "MATRICOLA_INPS" in labels


def test_detector_finds_contextual_documents_and_credit_card() -> None:
    text = "Passaporto: YA1234567 Patente: A12345678 carta 4111 1111 1111 1111"
    labels = set(labels_for(text))
    assert "PASSAPORTO" in labels
    assert "PATENTE" in labels
    assert "CARTA_CREDITO" in labels


def test_detector_finds_bare_piva_and_secret_token() -> None:
    text = "01114601006 sk-test-1234567890"
    labels = set(labels_for(text))
    assert "PARTITA_IVA" in labels
    assert "SECRET" in labels
