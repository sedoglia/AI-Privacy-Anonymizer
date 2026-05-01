from privacy_anonymizer.detectors.gliner_detector import GlinerDetector


class FakeGlinerModel:
    def predict_entities(self, text, labels, threshold):
        assert "person" in labels
        assert threshold == 0.42
        return [{"start": 0, "end": 11, "label": "person", "score": 0.91}]


def test_gliner_detector_normalizes_predictions(monkeypatch) -> None:
    detector = GlinerDetector(threshold=0.42)
    monkeypatch.setattr(detector, "_load_model", lambda: FakeGlinerModel())

    spans = detector.detect("Mario Rossi")

    assert len(spans) == 1
    assert spans[0].label == "PERSONA"
    assert spans[0].source == "gliner"
    assert spans[0].score == 0.91
