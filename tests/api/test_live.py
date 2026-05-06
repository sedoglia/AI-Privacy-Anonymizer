"""
Integration tests against a real running server (http://127.0.0.1:8000).

Richiedono il server avviato:
    privacy-anonymizer --api
    # oppure
    uvicorn privacy_anonymizer.api:app --host 127.0.0.1 --port 8000

Esegui con:
    pytest tests/api/test_live.py --live -v
"""
from __future__ import annotations

import io
import pathlib

import pytest

_BASE_URL = "http://127.0.0.1:8000"
_SAMPLE_DIR = pathlib.Path(__file__).parent.parent / "sample_files"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get(path: str, **kw):
    import requests
    return requests.get(f"{_BASE_URL}{path}", timeout=10, **kw)


def _post_text(text: str, mode: str = "replace", hybrid: str = "false", timeout: int = 60):
    import requests
    return requests.post(
        f"{_BASE_URL}/anonymize/text",
        data={"text": text, "mode": mode, "hybrid": hybrid},
        timeout=timeout,
    )


def _post_file(filename: str, content: bytes, mime: str = "text/plain", mode: str = "replace", hybrid: str = "false", timeout: int = 120):
    import requests
    return requests.post(
        f"{_BASE_URL}/anonymize/file",
        files={"file": (filename, io.BytesIO(content), mime)},
        data={"mode": mode, "hybrid": hybrid},
        timeout=timeout,
    )


# ── Health ──────────────────────────────────────────────────────────────────────

class TestLiveHealth:
    def test_health(self, live):
        resp = _get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ── Testo ────────────────────────────────────────────────────────────────────────

class TestLiveText:
    def test_masks_cf_and_email(self, live):
        resp = _post_text("CF: RSSMRA85M01H501Z, email: mario@test.it")
        assert resp.status_code == 200
        body = resp.json()
        assert "RSSMRA85M01H501Z" not in body["text"]
        assert "mario@test.it" not in body["text"]

    @pytest.mark.parametrize("mode", ["replace", "redact", "generalize", "hash"])
    def test_all_modes_return_200(self, live, mode):
        assert _post_text("IBAN: IT60 X054 2811 1010 0000 0123 456", mode=mode).status_code == 200

    def test_audit_contains_pattern_layer(self, live):
        layers = _post_text("Tel: +39 02 1234567").json()["audit"]["layers_used"]
        assert "pattern" in layers

    def test_hybrid_true(self, live):
        assert _post_text("Mario Rossi, mario@test.it", hybrid="true", timeout=120).status_code == 200

    def test_missing_text_returns_422(self, live):
        import requests
        resp = requests.post(f"{_BASE_URL}/anonymize/text", data={"mode": "replace"}, timeout=10)
        assert resp.status_code == 422


# ── File ─────────────────────────────────────────────────────────────────────────

class TestLiveFile:
    def test_txt_sample_masked(self, live):
        content = (_SAMPLE_DIR / "sample_pii_it.txt").read_bytes()
        resp = _post_file("sample_pii_it.txt", content)
        assert resp.status_code == 200
        out = resp.content.decode("utf-8", errors="replace")
        assert "RSSMRA85M01H501Z" not in out
        assert "mario.rossi@gmail.com" not in out

    def test_json_sample_processed(self, live):
        content = (_SAMPLE_DIR / "sample_data.json").read_bytes()
        resp = _post_file("sample_data.json", content, mime="application/json")
        assert resp.status_code == 200

    def test_inline_cf_masked(self, live):
        out = _post_file("test.txt", b"CF: BNCGLI92A41F205Z").content.decode("utf-8", errors="replace")
        assert "BNCGLI92A41F205Z" not in out

    def test_missing_file_returns_422(self, live):
        import requests
        resp = requests.post(f"{_BASE_URL}/anonymize/file", data={"mode": "replace"}, timeout=10)
        assert resp.status_code == 422
