"""Tests for POST /anonymize/text endpoint."""
from __future__ import annotations

import re

import pytest

# ── Costanti ────────────────────────────────────────────────────────────────────

_TEXT_PII = (
    "Mi chiamo Mario Rossi, il mio codice fiscale è RSSMRA85M01H501Z "
    "e la mia email è mario.rossi@gmail.com. Puoi chiamarmi al +39 02 1234567."
)
_TEXT_NO_PII = (
    "Il sistema elabora i documenti con tre livelli di rilevamento: "
    "OPF, GLiNER e Pattern. La pipeline è completamente automatizzata."
)
_TEXT_MULTI = (
    "Spettabile Dott. Luca Ferrari (FRRLCU80E15G224Y), "
    "nato il 15/05/1980, residente in Piazza San Marco 5, Venezia. "
    "Contatti: luca.ferrari@posta.it | 3391234567 | +39 06 9876543. "
    "Partita IVA: 12345678901. Targa veicolo: AB123CD."
)
_MODES = ["replace", "redact", "generalize", "hash"]


# ── Struttura della risposta ────────────────────────────────────────────────────

_DATA_PATTERN = {"text": _TEXT_PII, "hybrid": "false"}


class TestResponseStructure:
    def test_returns_200(self, client):
        assert client.post("/anonymize/text", data=_DATA_PATTERN).status_code == 200

    def test_has_text_and_audit_keys(self, client):
        body = client.post("/anonymize/text", data=_DATA_PATTERN).json()
        assert "text" in body and "audit" in body

    def test_text_is_string(self, client):
        assert isinstance(client.post("/anonymize/text", data=_DATA_PATTERN).json()["text"], str)

    def test_content_type_is_json(self, client):
        resp = client.post("/anonymize/text", data=_DATA_PATTERN)
        assert "application/json" in resp.headers["content-type"]

    def test_audit_required_fields(self, client):
        audit = client.post("/anonymize/text", data=_DATA_PATTERN).json()["audit"]
        for field in ("tool_version", "processed_at", "processing_time_seconds", "layers_used", "entities_found"):
            assert field in audit, f"Campo audit mancante: {field}"

    def test_entities_found_has_by_category(self, client):
        audit = client.post("/anonymize/text", data=_DATA_PATTERN).json()["audit"]
        assert "by_category" in audit["entities_found"]


# ── Effetto dell'anonimizzazione ────────────────────────────────────────────────

class TestAnonymizationEffect:
    def test_email_masked(self, client):
        resp = client.post("/anonymize/text", data={"text": "Email: mario.rossi@gmail.com", "hybrid": "false"})
        assert "mario.rossi@gmail.com" not in resp.json()["text"]

    def test_codice_fiscale_masked(self, client):
        resp = client.post("/anonymize/text", data={"text": "CF: RSSMRA85M01H501Z", "hybrid": "false"})
        assert "RSSMRA85M01H501Z" not in resp.json()["text"]

    def test_phone_masked(self, client):
        resp = client.post("/anonymize/text", data={"text": "Tel: +39 02 1234567", "hybrid": "false"})
        assert "+39 02 1234567" not in resp.json()["text"]

    def test_iban_masked(self, client):
        resp = client.post("/anonymize/text", data={"text": "IBAN: IT60 X054 2811 1010 0000 0123 456", "hybrid": "false"})
        assert "IT60 X054 2811 1010 0000 0123 456" not in resp.json()["text"]

    def test_pii_text_detects_entities(self, client):
        entities = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]["entities_found"]
        assert entities.get("merged_unique_spans", 0) > 0

    def test_no_pii_text_detects_few_entities(self, client):
        entities = client.post("/anonymize/text", data={"text": _TEXT_NO_PII, "hybrid": "false"}).json()["audit"]["entities_found"]
        assert entities.get("merged_unique_spans", 0) < 5

    def test_multiple_entity_types_detected(self, client):
        by_cat = client.post("/anonymize/text", data={"text": _TEXT_MULTI, "hybrid": "false"}).json()["audit"]["entities_found"]["by_category"]
        assert len(by_cat) > 1

    def test_output_text_non_empty_for_pii_input(self, client):
        result = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["text"]
        assert result.strip()


# ── Modalità di mascheramento ───────────────────────────────────────────────────

class TestMaskingModes:
    @pytest.mark.parametrize("mode", _MODES)
    def test_mode_returns_200(self, client, mode):
        resp = client.post("/anonymize/text", data={"text": _TEXT_PII, "mode": mode, "hybrid": "false"})
        assert resp.status_code == 200

    @pytest.mark.parametrize("mode", _MODES)
    def test_mode_masks_codice_fiscale(self, client, mode):
        resp = client.post("/anonymize/text", data={"text": "CF: RSSMRA85M01H501Z", "mode": mode, "hybrid": "false"})
        assert "RSSMRA85M01H501Z" not in resp.json()["text"]

    def test_default_mode_works(self, client):
        """Senza specificare mode (default=replace) l'endpoint deve rispondere 200."""
        assert client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).status_code == 200


# ── Parametro hybrid ───────────────────────────────────────────────────────────

class TestHybridParameter:
    def test_hybrid_false_activates_pattern_layer(self, client):
        layers = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]["layers_used"]
        assert "pattern" in layers

    def test_hybrid_true_returns_200(self, client):
        assert client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "true"}).status_code == 200

    def test_hybrid_default_returns_200(self, client):
        assert client.post("/anonymize/text", data={"text": _TEXT_PII}).status_code == 200


# ── Validazione input ───────────────────────────────────────────────────────────

class TestInputValidation:
    def test_missing_text_returns_422(self, client):
        assert client.post("/anonymize/text", data={"mode": "replace"}).status_code == 422

    def test_empty_text_returns_422(self, client):
        """FastAPI rifiuta la stringa vuota come campo obbligatorio."""
        assert client.post("/anonymize/text", data={"text": ""}).status_code == 422

    def test_whitespace_text_returns_200(self, client):
        """Stringa di soli spazi (non vuota per il form) viene accettata."""
        assert client.post("/anonymize/text", data={"text": "   \n\t  "}).status_code == 200

    def test_invalid_mode_does_not_crash_server(self, client):
        resp = client.post("/anonymize/text", data={"text": "ciao", "mode": "invalid_mode"})
        assert resp.status_code in (200, 422, 500)


# ── Metadati audit ──────────────────────────────────────────────────────────────

class TestAuditMetadata:
    def test_processing_time_is_non_negative(self, client):
        t = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]["processing_time_seconds"]
        assert isinstance(t, (int, float)) and t >= 0

    def test_tool_version_non_empty(self, client):
        v = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]["tool_version"]
        assert v and isinstance(v, str)

    def test_processed_at_is_iso_timestamp(self, client):
        ts = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]["processed_at"]
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts), f"Timestamp non ISO: {ts}"


# ── PII italiani specifici ──────────────────────────────────────────────────────

class TestItalianPII:
    @pytest.mark.parametrize("cf", [
        "RSSMRA85M01H501Z",
        "BNCGLI92A41F205Z",
        "FRRLCU80E15G224Y",
    ])
    def test_codice_fiscale_masked(self, client, cf):
        result = client.post("/anonymize/text", data={"text": f"CF: {cf}", "hybrid": "false"}).json()["text"]
        assert cf not in result

    @pytest.mark.parametrize("phone", [
        "+39 02 1234567",
        "338 765 4321",
        "3391234567",
    ])
    def test_phone_masked(self, client, phone):
        result = client.post("/anonymize/text", data={"text": f"Tel: {phone}", "hybrid": "false"}).json()["text"]
        assert phone not in result

    def test_iban_masked(self, client):
        result = client.post("/anonymize/text", data={"text": "IBAN: IT60 X054 2811 1010 0000 0123 456", "hybrid": "false"}).json()["text"]
        assert "IT60 X054 2811 1010 0000 0123 456" not in result
