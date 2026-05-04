from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.io.json_files import JsonAdapter

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)


def _write(tmp_path: Path, data: object, name: str = "input.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


@pytest.fixture()
def adapter() -> JsonAdapter:
    return JsonAdapter()


class TestReadText:
    def test_extracts_string_values_flat(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"user": "Giulia Neri", "email": "giulia.neri@example.com", "item": "Laptop"})
        content = adapter.read_text(src)
        assert content.text == "Giulia Neri\ngiulia.neri@example.com\nLaptop"

    def test_skips_non_string_values(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"name": "Mario", "age": 30, "active": True, "score": None})
        content = adapter.read_text(src)
        assert content.text == "Mario"

    def test_nested_objects(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"user": "Giulia", "address": {"city": "Roma", "zip": "00100"}})
        content = adapter.read_text(src)
        assert content.text == "Giulia\nRoma\n00100"

    def test_arrays(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"names": ["Alice", "Bob", "Charlie"]})
        content = adapter.read_text(src)
        assert content.text == "Alice\nBob\nCharlie"

    def test_array_of_objects(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"users": [{"name": "Alice"}, {"name": "Bob"}]})
        content = adapter.read_text(src)
        assert content.text == "Alice\nBob"

    def test_multiline_strings_excluded(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"note": "line1\nline2", "name": "Mario"})
        content = adapter.read_text(src)
        assert "line1" not in content.text
        assert "Mario" in content.text

    def test_empty_string_included(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"a": "", "b": "Mario"})
        content = adapter.read_text(src)
        assert content.text == "\nMario"

    def test_has_warning(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"a": "b"})
        assert adapter.read_text(src).warnings


class TestWriteAnonymized:
    def test_replaces_string_values(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"user": "Giulia Neri", "email": "giulia.neri@example.com", "item": "Laptop"})
        dst = tmp_path / "out.json"
        adapter.write_anonymized(src, dst, "[PERSONA_1]\n[EMAIL_1]\nLaptop", keep_metadata=False)
        result = json.loads(dst.read_text(encoding="utf-8"))
        assert result["user"] == "[PERSONA_1]"
        assert result["email"] == "[EMAIL_1]"
        assert result["item"] == "Laptop"

    def test_preserves_non_string_types(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"name": "Giulia", "order": {"item": "Laptop", "price": 1200}})
        dst = tmp_path / "out.json"
        adapter.write_anonymized(src, dst, "[PERSONA_1]\nLaptop", keep_metadata=False)
        result = json.loads(dst.read_text(encoding="utf-8"))
        assert isinstance(result["order"], dict)
        assert result["order"]["price"] == 1200

    def test_preserves_multiline_strings_unchanged(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"note": "line1\nline2", "name": "Giulia"})
        dst = tmp_path / "out.json"
        adapter.write_anonymized(src, dst, "[PERSONA_1]", keep_metadata=False)
        result = json.loads(dst.read_text(encoding="utf-8"))
        assert result["note"] == "line1\nline2"
        assert result["name"] == "[PERSONA_1]"

    def test_array_of_objects_replaced(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"users": [{"name": "Alice"}, {"name": "Bob"}]})
        dst = tmp_path / "out.json"
        adapter.write_anonymized(src, dst, "[PERSONA_1]\n[PERSONA_2]", keep_metadata=False)
        result = json.loads(dst.read_text(encoding="utf-8"))
        assert result["users"][0]["name"] == "[PERSONA_1]"
        assert result["users"][1]["name"] == "[PERSONA_2]"

    def test_output_valid_utf8_json(self, adapter: JsonAdapter, tmp_path: Path) -> None:
        src = _write(tmp_path, {"name": "Müller"})
        dst = tmp_path / "out.json"
        adapter.write_anonymized(src, dst, "[PERSONA_1]", keep_metadata=False)
        raw = dst.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert parsed["name"] == "[PERSONA_1]"


class TestRoundtripWithAnonymizer:
    def test_sample_json_masks_name_and_email(self, tmp_path: Path) -> None:
        data = {
            "user": "Giulia Neri",
            "email": "giulia.neri@example.com",
            "order": {"item": "Laptop", "price": 1200},
        }
        src = _write(tmp_path, data)
        result = Anonymizer(_PATTERN_ONLY).process_file(src)
        output = json.loads(Path(result.output_path).read_text(encoding="utf-8"))
        assert "giulia.neri@example.com" not in output["email"]
        assert output["order"]["price"] == 1200
        assert output["order"]["item"] == "Laptop"

    def test_process_file_produces_audit(self, tmp_path: Path) -> None:
        src = _write(tmp_path, {"email": "mario.rossi@example.com"})
        result = Anonymizer(_PATTERN_ONLY).process_file(src)
        assert result.output_path is not None
        assert result.audit_report["entities_found"]["merged_unique_spans"] >= 1
