"""Tests for POST /anonymize/file endpoint."""
from __future__ import annotations

import io
import pathlib

import pytest

_MODES = ["replace", "redact", "generalize", "hash"]
_SAMPLE_DIR = pathlib.Path(__file__).parent.parent / "sample_files"


def _upload(client, filename: str, content: bytes, mode: str = "replace", hybrid: str = "false"):
    return client.post(
        "/anonymize/file",
        files={"file": (filename, io.BytesIO(content), "text/plain")},
        data={"mode": mode, "hybrid": hybrid},
    )


# ── File TXT ────────────────────────────────────────────────────────────────────

class TestTxtFile:
    def test_returns_200(self, client):
        assert _upload(client, "doc.txt", b"test content").status_code == 200

    def test_response_has_content(self, client):
        assert len(_upload(client, "doc.txt", b"Nome: Mario Rossi").content) > 0

    def test_pii_masked_in_output(self, client):
        content = "Mario Rossi, RSSMRA85M01H501Z, mario.rossi@gmail.com, +39 02 1234567".encode()
        out = _upload(client, "pii.txt", content).content.decode("utf-8", errors="replace")
        assert "RSSMRA85M01H501Z" not in out

    def test_sample_file_masks_cf_and_email(self, client):
        content = (_SAMPLE_DIR / "sample_pii_it.txt").read_bytes()
        out = _upload(client, "sample_pii_it.txt", content).content.decode("utf-8", errors="replace")
        assert "RSSMRA85M01H501Z" not in out
        assert "mario.rossi@gmail.com" not in out

    def test_empty_file_accepted(self, client):
        assert _upload(client, "empty.txt", b"").status_code == 200

    def test_large_file_accepted(self, client):
        large = ("Mario Rossi mario.rossi@gmail.com RSSMRA85M01H501Z\n" * 500).encode()
        assert _upload(client, "large.txt", large).status_code == 200

    def test_unicode_content_accepted(self, client):
        content = "Piazzà Dàntë 3, Città di Vënice\n".encode("utf-8")
        assert _upload(client, "unicode.txt", content).status_code == 200


# ── File JSON ───────────────────────────────────────────────────────────────────

class TestJsonFile:
    def test_returns_200(self, client):
        import json
        payload = json.dumps({"nome": "Luigi Verdi", "email": "luigi@email.it"}).encode()
        resp = client.post(
            "/anonymize/file",
            files={"file": ("data.json", io.BytesIO(payload), "application/json")},
            data={"mode": "replace", "hybrid": "false"},
        )
        assert resp.status_code == 200

    def test_sample_file_processed(self, client):
        content = (_SAMPLE_DIR / "sample_data.json").read_bytes()
        resp = client.post(
            "/anonymize/file",
            files={"file": ("sample_data.json", io.BytesIO(content), "application/json")},
            data={"mode": "replace", "hybrid": "false"},
        )
        assert resp.status_code == 200


# ── Modalità di mascheramento ───────────────────────────────────────────────────

class TestFileModes:
    @pytest.mark.parametrize("mode", _MODES)
    def test_mode_accepted(self, client, mode):
        resp = _upload(client, "test.txt", b"CF: BNCGLI92A41F205Z", mode=mode)
        assert resp.status_code == 200

    @pytest.mark.parametrize("mode", _MODES)
    def test_mode_masks_codice_fiscale(self, client, mode):
        out = _upload(client, "test.txt", b"CF: BNCGLI92A41F205Z", mode=mode).content.decode("utf-8", errors="replace")
        assert "BNCGLI92A41F205Z" not in out


# ── Validazione input ───────────────────────────────────────────────────────────

class TestFileInputValidation:
    def test_missing_file_returns_422(self, client):
        assert client.post("/anonymize/file", data={"mode": "replace"}).status_code == 422

    def test_unsupported_extension_raises(self, client):
        """Formato senza estensione non supportato → ValueError dall'anonymizer."""
        with pytest.raises(Exception, match="Formato non supportato"):
            _upload(client, "noext", b"Nome: Mario Rossi")


# ── Parametro hybrid ───────────────────────────────────────────────────────────

class TestFileHybrid:
    def test_hybrid_false_masks_iban(self, client):
        out = _upload(client, "iban.txt", b"IBAN: IT60 X054 2811 1010 0000 0123 456", hybrid="false").content.decode("utf-8", errors="replace")
        assert "IT60 X054 2811 1010 0000 0123 456" not in out

    def test_hybrid_true_accepted(self, client):
        assert _upload(client, "test.txt", b"Nome: Giulia Bianchi", hybrid="true").status_code == 200
