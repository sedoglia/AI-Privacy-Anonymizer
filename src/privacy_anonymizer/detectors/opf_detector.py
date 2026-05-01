from __future__ import annotations

from privacy_anonymizer.models import DetectionSpan

OPF_LABEL_MAP = {
    "private_person": "PERSONA",
    "private_email": "EMAIL",
    "private_phone": "TELEFONO",
    "private_address": "INDIRIZZO",
    "private_date": "DATA_PRIVATA",
    "private_url": "URL",
    "account_number": "ACCOUNT_NUMBER",
    "secret": "SECRET",
}

OPF_VITERBI_CONFIGS = {
    "conservative": {},
    "balanced": {
        "background_stay": -2.0,
        "background_to_start": 1.5,
        "span_continuation": 1.0,
    },
    "aggressive": {
        "background_stay": -3.0,
        "background_to_start": 2.0,
        "span_continuation": 1.5,
    },
}


class OpfDetector:
    source = "opf"

    def __init__(self, recall_mode: str = "balanced") -> None:
        self.recall_mode = recall_mode
        self._pipeline = None

    def detect(self, text: str) -> list[DetectionSpan]:
        pipeline = self._load_pipeline()
        predictions = pipeline(text)
        spans = [_prediction_to_span(item) for item in predictions]
        return sorted((span for span in spans if span is not None), key=lambda span: (span.start, span.end))

    def release(self) -> None:
        self._pipeline = None

    def _load_pipeline(self):
        if self._pipeline is not None:
            return self._pipeline
        try:
            import opf
        except ImportError as exc:
            raise RuntimeError(
                "Layer OPF non disponibile: installa OpenAI Privacy Filter dal repository ufficiale "
                "e riesegui con `--layers hybrid`."
            ) from exc

        if hasattr(opf, "PrivacyFilter"):
            self._pipeline = opf.PrivacyFilter(viterbi_config=OPF_VITERBI_CONFIGS.get(self.recall_mode, {}))
        elif hasattr(opf, "pipeline"):
            self._pipeline = opf.pipeline(viterbi_config=OPF_VITERBI_CONFIGS.get(self.recall_mode, {}))
        else:
            raise RuntimeError("Installazione OPF trovata ma API non riconosciuta.")
        return self._pipeline


def _prediction_to_span(prediction) -> DetectionSpan | None:
    if isinstance(prediction, DetectionSpan):
        return prediction
    if isinstance(prediction, dict):
        start = prediction.get("start")
        end = prediction.get("end")
        label = prediction.get("label") or prediction.get("entity") or prediction.get("type")
        score = prediction.get("score", 1.0)
    else:
        start = getattr(prediction, "start", None)
        end = getattr(prediction, "end", None)
        label = getattr(prediction, "label", None) or getattr(prediction, "entity", None) or getattr(prediction, "type", None)
        score = getattr(prediction, "score", 1.0)
    if start is None or end is None or label is None:
        return None
    normalized = OPF_LABEL_MAP.get(str(label), str(label).upper())
    return DetectionSpan(int(start), int(end), normalized, "opf", float(score))

