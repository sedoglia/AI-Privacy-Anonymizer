from __future__ import annotations

import logging
import os
import warnings

# Mirror the same suppression applied in gliner_detector so that whichever
# detector is imported first establishes the filters for the whole process.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
logging.getLogger("transformers.tokenization_utils_base").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*resume_download.*", category=FutureWarning)

from privacy_anonymizer.models import DetectionSpan

# Mapping from upstream OPF labels (openai/privacy-filter) to project categories.
# Upstream uses lowercase typed labels; common ones include "person", "email",
# "phone", "address", "date_of_birth", "url", "account_number", "ssn", "secret".
OPF_LABEL_MAP = {
    "person": "PERSONA",
    "private_person": "PERSONA",
    "name": "PERSONA",
    "email": "EMAIL",
    "private_email": "EMAIL",
    "phone": "TELEFONO",
    "private_phone": "TELEFONO",
    "phone_number": "TELEFONO",
    "address": "INDIRIZZO",
    "private_address": "INDIRIZZO",
    "location": "LUOGO",
    "date": "DATA_PRIVATA",
    "private_date": "DATA_PRIVATA",
    "date_of_birth": "DATA_NASCITA",
    "url": "URL",
    "private_url": "URL",
    "account_number": "ACCOUNT_NUMBER",
    "iban": "IBAN",
    "credit_card": "CREDIT_CARD",
    "ssn": "SSN",
    "tax_id": "TAX_ID",
    "secret": "SECRET",
    "redacted": "PII",
}


class OpfDetector:
    """Detector wrapping `openai/privacy-filter` (package name: `opf`).

    The upstream API exposes:
        opf.OPF(device, output_mode, decode_mode, ...).redact(text) -> RedactionResult
        result.detected_spans -> tuple[DetectedSpan(label, start, end, text, placeholder), ...]

    On first call we resolve `opf.OPF`; if the imported `opf` is the PyPI
    namesake (Open Provenance Format) we degrade gracefully and return [].
    """

    source = "opf"

    def __init__(self, recall_mode: str = "balanced") -> None:
        # `recall_mode` previously selected a Viterbi config; the upstream API
        # exposes `decode_mode` ("viterbi" | "argmax") instead. We map any non-
        # default value to argmax (faster, less recall) and the rest to viterbi.
        self.recall_mode = recall_mode
        self._decode_mode = "argmax" if recall_mode == "conservative" else "viterbi"
        self._pipeline = None
        self._unavailable_reason: str | None = None
        self._warned = False

    def detect(self, text: str) -> list[DetectionSpan]:
        pipeline = self._load_pipeline()
        if pipeline is None:
            return []
        try:
            if hasattr(pipeline, "redact"):
                result = pipeline.redact(text)
                spans_iter = getattr(result, "detected_spans", None)
                if spans_iter is None and isinstance(result, (list, tuple)):
                    spans_iter = result
            else:
                # Legacy callable pipeline returning a list of dicts/objects
                spans_iter = pipeline(text)
        except Exception as exc:  # pragma: no cover - defensive
            self._unavailable_reason = f"OPF redact() ha fallito a runtime: {exc}"
            self._warn_once()
            self._pipeline = None
            return []

        if spans_iter is None:
            return []
        spans = [_detected_span_to_span(item) for item in spans_iter]
        return sorted((span for span in spans if span is not None), key=lambda span: (span.start, span.end))

    def release(self) -> None:
        self._pipeline = None

    def _load_pipeline(self):
        if self._pipeline is not None:
            return self._pipeline
        if self._unavailable_reason is not None:
            return None
        try:
            import opf
        except ImportError:
            self._unavailable_reason = (
                "Layer OPF non disponibile: pacchetto 'opf' non installato. "
                "Per l'OpenAI Privacy Filter: pip install \"opf @ git+https://github.com/openai/privacy-filter\". "
                "GLiNER + patterns restano attivi."
            )
            self._warn_once()
            return None

        # Real upstream API (openai/privacy-filter)
        if hasattr(opf, "OPF"):
            try:
                self._pipeline = opf.OPF(device="cpu", output_mode="typed", decode_mode=self._decode_mode)
            except Exception as exc:
                self._unavailable_reason = f"Inizializzazione OPF fallita: {exc}"
                self._warn_once()
                return None
            return self._pipeline

        # Legacy / hypothetical alternative APIs kept for backward compatibility
        if hasattr(opf, "PrivacyFilter"):
            self._pipeline = opf.PrivacyFilter()
            return self._pipeline
        if hasattr(opf, "pipeline"):
            self._pipeline = opf.pipeline()
            return self._pipeline

        self._unavailable_reason = (
            "Layer OPF disattivato: il pacchetto 'opf' installato non espone OPF/PrivacyFilter "
            "(probabilmente l'omonimo 'Open Provenance Format' su PyPI). "
            "Per usare il vero OpenAI Privacy Filter: "
            "pip install \"opf @ git+https://github.com/openai/privacy-filter\". "
            "GLiNER + patterns restano attivi."
        )
        self._warn_once()
        return None

    def _warn_once(self) -> None:
        if self._warned or self._unavailable_reason is None:
            return
        import sys
        print(f"[warning] {self._unavailable_reason}", file=sys.stderr)
        self._warned = True


def _detected_span_to_span(prediction) -> DetectionSpan | None:
    """Convert an upstream OPF DetectedSpan (or legacy dict/object) to DetectionSpan."""
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
        label = (
            getattr(prediction, "label", None)
            or getattr(prediction, "entity", None)
            or getattr(prediction, "type", None)
        )
        score = getattr(prediction, "score", 1.0)
    if start is None or end is None or label is None:
        return None
    label_key = str(label).strip().lower()
    normalized = OPF_LABEL_MAP.get(label_key, str(label).upper())
    return DetectionSpan(int(start), int(end), normalized, "opf", float(score))


# Backward-compat alias for any external callers / older tests.
_prediction_to_span = _detected_span_to_span

