from pathlib import Path

from PIL import Image

from privacy_anonymizer.io.images import ImageAdapter
from privacy_anonymizer.masking import ReplacementSpan


class FakeRapidOCROutput:
    """Mimics RapidOCR 3.x output object."""

    def __init__(self):
        self.boxes = [[[10, 10], [150, 10], [150, 30], [10, 30]]]
        self.txts = ["mario.rossi@example.com"]
        self.scores = [0.99]


class FakeRapidOCR:
    def __call__(self, image):
        return FakeRapidOCROutput()


def test_image_adapter_redacts_ocr_word_boxes(monkeypatch, tmp_path: Path) -> None:
    import privacy_anonymizer.io.images as images_module

    source = tmp_path / "sample.png"
    destination = tmp_path / "clean.png"
    Image.new("RGB", (220, 80), "white").save(source)

    monkeypatch.setattr(images_module, "_import_ocr", lambda: (Image, FakeRapidOCR()))

    result = ImageAdapter().write_anonymized(
        source,
        destination,
        "[EMAIL_1]",
        keep_metadata=False,
        replacements=[
            ReplacementSpan(
                start=0,
                end=23,
                label="EMAIL",
                original="mario.rossi@example.com",
                replacement="[EMAIL_1]",
            )
        ],
        original_text="mario.rossi@example.com",
    )

    assert destination.exists()
    assert "Immagine redatta a coordinate OCR" in result.warnings[0]
