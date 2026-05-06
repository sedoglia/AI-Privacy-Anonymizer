"""Edge cases and robustness tests for the API."""
from __future__ import annotations

import time

import pytest

_TEXT_PII = (
    "Mi chiamo Mario Rossi, il mio codice fiscale è RSSMRA85M01H501Z "
    "e la mia email è mario.rossi@gmail.com. Puoi chiamarmi al +39 02 1234567."
)


class TestTextEdgeCases:
    def test_very_long_text(self, client):
        long = (
            "Mario Rossi (RSSMRA85M01H501Z) abita in Via Roma 1 Milano. "
            "Contatto: mario.rossi@gmail.com, tel +39 02 1234567.\n"
        ) * 100
        resp = client.post("/anonymize/text", data={"text": long, "hybrid": "false"})
        assert resp.status_code == 200
        assert resp.json()["text"].strip()

    def test_special_characters(self, client):
        text = "Email: test@test.it — nota: €100, <tag>, &amp; #simboli"
        assert client.post("/anonymize/text", data={"text": text, "hybrid": "false"}).status_code == 200

    def test_crlf_and_tabs(self, client):
        text = "Nome:\tMario Rossi\nEmail:\nmario@test.it\r\nFine"
        assert client.post("/anonymize/text", data={"text": text, "hybrid": "false"}).status_code == 200

    def test_only_numbers(self, client):
        assert client.post("/anonymize/text", data={"text": "1234567890 9876543210", "hybrid": "false"}).status_code == 200

    def test_only_special_chars(self, client):
        assert client.post("/anonymize/text", data={"text": "!@#$%^&*()[]{}|", "hybrid": "false"}).status_code == 200

    def test_mixed_languages(self, client):
        text = "Name: John Smith (RSSMRA85M01H501Z) Nome: Mario Rossi email: mario@test.it"
        assert client.post("/anonymize/text", data={"text": text, "hybrid": "false"}).status_code == 200

    def test_url_in_text(self, client):
        text = "Vai su https://www.example.com/path?q=test&v=1 per info"
        assert client.post("/anonymize/text", data={"text": text, "hybrid": "false"}).status_code == 200

    def test_repeated_pii_all_masked(self, client):
        text = "mario@test.it mario@test.it mario@test.it"
        result = client.post("/anonymize/text", data={"text": text, "hybrid": "false"}).json()["text"]
        assert "mario@test.it" not in result

    def test_adjacent_pii_entities(self, client):
        assert client.post("/anonymize/text", data={"text": "RSSMRA85M01H501Zmario@test.it", "hybrid": "false"}).status_code == 200


class TestConcurrency:
    def test_sequential_requests_consistent(self, client):
        data = {"text": "CF: RSSMRA85M01H501Z", "hybrid": "false"}
        results = [client.post("/anonymize/text", data=data).json()["text"] for _ in range(3)]
        for r in results:
            assert "RSSMRA85M01H501Z" not in r

    def test_replace_mode_is_idempotent(self, client):
        data = {"text": _TEXT_PII, "mode": "replace", "hybrid": "false"}
        r1 = client.post("/anonymize/text", data=data).json()["text"]
        r2 = client.post("/anonymize/text", data=data).json()["text"]
        assert r1 == r2


class TestHTTPMethods:
    @pytest.mark.parametrize("method,path", [
        ("get", "/anonymize/text"),
        ("put", "/anonymize/text"),
        ("delete", "/anonymize/text"),
        ("get", "/anonymize/file"),
    ])
    def test_wrong_method_returns_405(self, client, method, path):
        resp = getattr(client, method)(path)
        assert resp.status_code == 405


class TestProcessingTime:
    def test_short_text_within_30s(self, client):
        start = time.time()
        resp = client.post("/anonymize/text", data={"text": "CF: RSSMRA85M01H501Z", "hybrid": "false"})
        assert resp.status_code == 200
        assert time.time() - start < 30

    def test_audit_time_is_realistic(self, client):
        audit = client.post("/anonymize/text", data={"text": _TEXT_PII, "hybrid": "false"}).json()["audit"]
        assert 0 <= audit["processing_time_seconds"] < 60
