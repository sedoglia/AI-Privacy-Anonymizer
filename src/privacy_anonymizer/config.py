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
    # Performance tuning
    chunk_long_text: bool = True
    chunk_threshold: int = 4000
    chunk_size: int = 1500
    chunk_overlap: int = 100
    chunk_max_workers: int = 4
    ocr_dpi: int = 300
    ocr_parallel_pages: bool = True
    ocr_max_workers: int = 4
    ml_skip_extensions: tuple[str, ...] = (".log",)
    ml_skip_min_chars: int = 8000
