from __future__ import annotations

import logging
import os
import warnings

# Set before any huggingface_hub import so the library reads it at init time.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

# The truncation message is emitted via logging (not warnings.warn), so we must
# raise the log threshold instead of using warnings.filterwarnings.
logging.getLogger("transformers.tokenization_utils_base").setLevel(logging.ERROR)

from privacy_anonymizer.models import DetectionSpan

# Permanent filters: applied once at import time so they are visible to all threads.
# catch_warnings() context managers are NOT thread-safe and must not be used in
# methods called from ThreadPoolExecutor workers.
warnings.filterwarnings("ignore", message=".*sentencepiece tokenizer.*byte fallback.*")
warnings.filterwarnings("ignore", message=".*resume_download.*", category=FutureWarning)

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


def _suppress_hf_progress() -> None:
    """Disable huggingface_hub tqdm progress bars and noisy tokenizer log lines."""
    import logging

    # Belt-and-suspenders: also call the API in case the env var was set too late.
    try:
        import huggingface_hub.utils as _hf_utils
        if hasattr(_hf_utils, "disable_progress_bars"):
            _hf_utils.disable_progress_bars()
    except Exception:
        pass

    # The "Asking to truncate to max_length" message is emitted via logging, not
    # warnings.warn(), so warnings.filterwarnings() cannot catch it.
    logging.getLogger("transformers.tokenization_utils_base").setLevel(logging.ERROR)


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
        if model is None:
            return []
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

    def release(self) -> None:
        self._model = None

    def _load_model(self):
        if self._model is not None:
            return self._model
        if getattr(self, "_unavailable", False):
            return None
        try:
            from gliner import GLiNER
        except ImportError:
            import sys
            print(
                "[warning] Layer GLiNER non disponibile: pacchetto 'gliner' non installato."
                " Per il layer ML: pip install -e .[ml]. Patterns restano attivi.",
                file=sys.stderr,
            )
            self._unavailable = True
            return None
        _suppress_hf_progress()
        self._model = GLiNER.from_pretrained(self.model_name)
        return self._model

