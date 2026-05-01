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
    opf_enabled: bool = True
    opf_recall_mode: str = "aggressive"
    gliner_enabled: bool = True
    gliner_model: str = "urchade/gliner_multi_pii-v1"
    gliner_threshold: float = 0.3
    pattern_enabled: bool = True
    masking_mode: MaskingMode | str = MaskingMode.REPLACE
    consistent_mapping: bool = True
    keep_metadata: bool = False
    recursive: bool = True
    low_memory: bool = False
    parallel: bool = True
