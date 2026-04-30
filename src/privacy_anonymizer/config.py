from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class MaskingMode(StrEnum):
    REPLACE = "replace"
    REDACT = "redact"
    GENERALIZE = "generalize"
    HASH = "hash"


@dataclass(slots=True)
class LayerConfig:
    opf_enabled: bool = False
    gliner_enabled: bool = False
    pattern_enabled: bool = True
    masking_mode: MaskingMode | str = MaskingMode.REPLACE
    consistent_mapping: bool = True
    keep_metadata: bool = False

