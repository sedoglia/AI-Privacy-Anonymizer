from __future__ import annotations

from privacy_anonymizer.models import DetectionSpan

DEFAULT_LABELS = [
    "person",
    "organization",
    "email",
    "phone number",
    "address",
    "date",
    "url",
    "username",
    "password",
    "ip address",
    "tax id",
    "social security number",
    "passport number",
    "driver license",
    "health insurance id",
    "credit card number",
    "iban",
    "medical condition",
]

LABEL_MAP = {
    "person": "PERSONA",
    "organization": "ORGANIZZAZIONE",
    "email": "EMAIL",
    "phone number": "TELEFONO",
    "address": "INDIRIZZO",
    "date": "DATA_PRIVATA",
    "url": "URL",
    "username": "USERNAME",
    "password": "SECRET",
    "ip address": "IP_ADDRESS",
    "tax id": "TAX_ID",
    "social security number": "CODICE_FISCALE",
    "passport number": "PASSAPORTO",
    "driver license": "PATENTE",
    "health insurance id": "TESSERA_SANITARIA",
    "credit card number": "CARTA_CREDITO",
    "iban": "IBAN",
    "medical condition": "CONDIZIONE_MEDICA",
}


class GlinerDetector:
    source = "gliner"

    def __init__(
        self,
        model_name: str = "urchade/gliner_multi_pii-v1",
        threshold: float = 0.5,
        labels: list[str] | None = None,
    ) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self.labels = labels or DEFAULT_LABELS
        self._model = None

    def detect(self, text: str) -> list[DetectionSpan]:
        model = self._load_model()
        entities = model.predict_entities(text, self.labels, threshold=self.threshold)
        spans = [
            DetectionSpan(
                start=int(entity["start"]),
                end=int(entity["end"]),
                label=LABEL_MAP.get(str(entity["label"]).lower(), str(entity["label"]).upper().replace(" ", "_")),
                source=self.source,
                score=float(entity.get("score", self.threshold)),
            )
            for entity in entities
        ]
        return sorted(spans, key=lambda span: (span.start, span.end))

    def _load_model(self):
        if self._model is not None:
            return self._model
        try:
            from gliner import GLiNER
        except ImportError as exc:
            raise RuntimeError("Layer GLiNER non disponibile: installa con `python -m pip install -e .[ml]`.") from exc
        self._model = GLiNER.from_pretrained(self.model_name)
        return self._model

