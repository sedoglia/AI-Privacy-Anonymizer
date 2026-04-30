from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from privacy_anonymizer.config import MaskingMode
from privacy_anonymizer.models import DetectionSpan

PREFIXES = {
    "CODICE_FISCALE": "CF",
    "PARTITA_IVA": "PIVA",
    "IBAN_IT": "IBAN",
    "TARGA_IT": "TARGA",
    "CARTA_IDENTITA": "CI",
    "TELEFONO_IT": "TEL",
    "CELL_IT": "TEL",
    "TEL_IT": "TEL",
    "EMAIL": "EMAIL",
    "PEC": "PEC",
    "IP_ADDRESS": "IP",
}


@dataclass(slots=True)
class EntityMapper:
    mode: MaskingMode | str = MaskingMode.REPLACE
    _seen: dict[tuple[str, str], str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def placeholder(self, label: str, value: str) -> str:
        mode = MaskingMode(self.mode)
        prefix = PREFIXES.get(label, label)
        key = (label, _normalize_value(value))
        if key in self._seen:
            return self._seen[key]

        if mode == MaskingMode.REDACT:
            placeholder = "█" * max(4, len(value))
        elif mode == MaskingMode.GENERALIZE:
            placeholder = f"[{prefix}]"
        elif mode == MaskingMode.HASH:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
            placeholder = f"[SHA256:{digest}]"
        else:
            self._counts[prefix] = self._counts.get(prefix, 0) + 1
            placeholder = f"[{prefix}_{self._counts[prefix]}]"

        self._seen[key] = placeholder
        return placeholder


def mask_text(text: str, spans: list[DetectionSpan], mode: MaskingMode | str = MaskingMode.REPLACE) -> str:
    mapper = EntityMapper(mode=mode)
    parts: list[str] = []
    cursor = 0
    for span in sorted(spans, key=lambda item: item.start):
        if span.start < cursor:
            continue
        original = text[span.start : span.end]
        parts.append(text[cursor : span.start])
        parts.append(mapper.placeholder(span.label, original))
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts)


def _normalize_value(value: str) -> str:
    return " ".join(value.upper().split())

