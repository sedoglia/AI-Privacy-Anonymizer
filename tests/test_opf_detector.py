import sys
import types

from privacy_anonymizer.detectors.opf_detector import OpfDetector


class FakeDetectedSpan:
    """Mimics opf._core.runtime.DetectedSpan from openai/privacy-filter."""

    def __init__(self, label: str, start: int, end: int, text: str, placeholder: str) -> None:
        self.label = label
        self.start = start
        self.end = end
        self.text = text
        self.placeholder = placeholder


class FakeRedactionResult:
    def __init__(self, spans):
        self.detected_spans = tuple(spans)
        self.redacted_text = ""
        self.text = ""
        self.summary = {}


class FakeOPF:
    """Mimics the upstream `opf.OPF` class (openai/privacy-filter)."""

    def __init__(self, *, device="cpu", output_mode="typed", decode_mode="viterbi", **kwargs):
        self.device = device
        self.output_mode = output_mode
        self.decode_mode = decode_mode

    def redact(self, text: str) -> FakeRedactionResult:
        return FakeRedactionResult(
            [FakeDetectedSpan(label="person", start=0, end=11, text="Mario Rossi", placeholder="[PERSON_1]")]
        )


def test_opf_detector_loads_real_api(monkeypatch) -> None:
    fake_opf = types.SimpleNamespace(OPF=FakeOPF)
    monkeypatch.setitem(sys.modules, "opf", fake_opf)

    spans = OpfDetector(recall_mode="balanced").detect("Mario Rossi")

    assert len(spans) == 1
    assert spans[0].label == "PERSONA"
    assert spans[0].source == "opf"
    assert spans[0].start == 0
    assert spans[0].end == 11


def test_opf_detector_handles_unknown_api(monkeypatch, capsys) -> None:
    """When the imported `opf` package lacks the upstream API (e.g., the PyPI
    namesake Open Provenance Format), the detector should degrade gracefully."""
    fake_opf = types.SimpleNamespace()  # no OPF, no PrivacyFilter, no pipeline
    monkeypatch.setitem(sys.modules, "opf", fake_opf)

    spans = OpfDetector(recall_mode="balanced").detect("Mario Rossi")

    assert spans == []
    captured = capsys.readouterr()
    assert "OPF" in captured.err
