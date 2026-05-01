import sys
import types
from pathlib import Path

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig


class FakeDoclingDocument:
    def export_to_markdown(self):
        return "CF RSSMRA80A01L219X"


class FakeConversionResult:
    document = FakeDoclingDocument()


class FakeDocumentConverter:
    def convert(self, path):
        return FakeConversionResult()


def test_docling_parser_can_be_selected(monkeypatch, tmp_path: Path) -> None:
    fake_module = types.SimpleNamespace(DocumentConverter=FakeDocumentConverter)
    monkeypatch.setitem(sys.modules, "docling", types.ModuleType("docling"))
    monkeypatch.setitem(sys.modules, "docling.document_converter", fake_module)
    source = tmp_path / "input.txt"
    source.write_text("not used", encoding="utf-8")

    result = Anonymizer(LayerConfig(parser="docling")).process_file(source)

    assert result.anonymized_text == "CF [CF_1]"
