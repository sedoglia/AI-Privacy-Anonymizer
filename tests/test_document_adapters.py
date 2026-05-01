from email.message import EmailMessage
from pathlib import Path

import pytest

from privacy_anonymizer import Anonymizer


def test_eml_adapter_masks_headers_and_body(tmp_path: Path) -> None:
    message = EmailMessage()
    message["From"] = "Mario Rossi <mario.rossi@example.com>"
    message["To"] = "privacy@example.com"
    message["Subject"] = "CF RSSMRA80A01L219X"
    message.set_content("tel 3401234567")
    source = tmp_path / "message.eml"
    source.write_bytes(message.as_bytes())

    result = Anonymizer().process_file(source)

    output = result.output_path.read_text(encoding="utf-8", errors="ignore")
    assert "mario.rossi@example.com" not in output
    assert "RSSMRA80A01L219X" not in output
    assert "3401234567" not in output


def test_rtf_adapter_masks_text(tmp_path: Path) -> None:
    source = tmp_path / "sample.rtf"
    source.write_text(r"{\rtf1\ansi CF RSSMRA80A01L219X}", encoding="utf-8")

    result = Anonymizer().process_file(source)

    assert "RSSMRA80A01L219X" not in result.output_path.read_text(encoding="utf-8")


def test_pdf_adapter_masks_text_when_dependencies_available(tmp_path: Path) -> None:
    pytest.importorskip("pypdf")
    pytest.importorskip("reportlab")
    from reportlab.pdfgen import canvas

    source = tmp_path / "sample.pdf"
    c = canvas.Canvas(str(source))
    c.drawString(72, 720, "email mario.rossi@example.com")
    c.save()

    result = Anonymizer().process_file(source)

    assert result.output_path.suffix == ".pdf"
    assert result.audit_report["warnings"]
