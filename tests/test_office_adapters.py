from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig

_PATTERN_ONLY = LayerConfig(opf_enabled=False, gliner_enabled=False, parallel=False)


def test_docx_adapter_masks_body_header_and_metadata(tmp_path: Path) -> None:
    docx = pytest.importorskip("docx")
    document = docx.Document()
    document.add_paragraph("CF RSSMRA80A01L219X")
    document.sections[0].header.paragraphs[0].text = "email mario.rossi@example.com"
    document.core_properties.author = "Mario Rossi"
    source = tmp_path / "sample.docx"
    document.save(source)

    result = Anonymizer().process_file(source)

    output = docx.Document(result.output_path)
    visible_text = "\n".join(
        [*(paragraph.text for paragraph in output.paragraphs), *(paragraph.text for paragraph in output.sections[0].header.paragraphs)]
    )
    assert "RSSMRA80A01L219X" not in visible_text
    assert "mario.rossi@example.com" not in visible_text
    assert output.core_properties.author == "Anonimo"


def test_xlsx_adapter_masks_cells_sheet_names_comments_and_metadata(tmp_path: Path) -> None:
    openpyxl = pytest.importorskip("openpyxl")
    Comment = pytest.importorskip("openpyxl.comments").Comment

    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.title = "mario.rossi@example.com"
    worksheet["A1"] = "P.IVA 01114601006"
    worksheet["A2"] = "=CONCAT(A1)"
    worksheet["A3"].comment = Comment("tel 3401234567", "Mario Rossi")
    source = tmp_path / "sample.xlsx"
    workbook.save(source)

    result = Anonymizer(_PATTERN_ONLY).process_file(source)

    output = openpyxl.load_workbook(result.output_path, data_only=False)
    worksheet = output.active
    assert worksheet.title == "_EMAIL_1_"
    assert worksheet["A1"].value == "P.IVA [PIVA_1]"
    assert worksheet["A2"].value == "=CONCAT(A1)"
    assert worksheet["A3"].comment.text == "tel [TEL_1]"
    assert worksheet["A3"].comment.author == "Anonimo"


def test_pptx_adapter_masks_slide_and_notes_text(tmp_path: Path) -> None:
    pptx = pytest.importorskip("pptx")
    presentation = pptx.Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[5])
    slide.shapes.title.text = "email mario.rossi@example.com"
    source = tmp_path / "sample.pptx"
    presentation.save(source)

    result = Anonymizer().process_file(source)

    output = pptx.Presentation(result.output_path)
    visible_text = "\n".join(
        shape.text
        for slide in output.slides
        for shape in slide.shapes
        if getattr(shape, "has_text_frame", False)
    )
    assert "mario.rossi@example.com" not in visible_text
