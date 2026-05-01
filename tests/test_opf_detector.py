import sys
import types

from privacy_anonymizer.detectors.opf_detector import OpfDetector


class FakePrivacyFilter:
    def __init__(self, viterbi_config):
        self.viterbi_config = viterbi_config

    def __call__(self, text):
        return [{"start": 0, "end": 11, "label": "private_person", "score": 0.8}]


def test_opf_detector_loads_lazy_api(monkeypatch) -> None:
    fake_opf = types.SimpleNamespace(PrivacyFilter=FakePrivacyFilter)
    monkeypatch.setitem(sys.modules, "opf", fake_opf)

    spans = OpfDetector(recall_mode="balanced").detect("Mario Rossi")

    assert len(spans) == 1
    assert spans[0].label == "PERSONA"
    assert spans[0].source == "opf"
