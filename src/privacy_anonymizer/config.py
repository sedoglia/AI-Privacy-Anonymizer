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
    parser: str = "built-in"
    opf_enabled: bool = False
    opf_recall_mode: str = "balanced"
    gliner_enabled: bool = False
    gliner_model: str = "urchade/gliner_multi_pii-v1"
    gliner_threshold: float = 0.5
    pattern_enabled: bool = True
    masking_mode: MaskingMode | str = MaskingMode.REPLACE
    consistent_mapping: bool = True
    keep_metadata: bool = False
    recursive: bool = True
    low_memory: bool = False
    parallel: bool = False
