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
