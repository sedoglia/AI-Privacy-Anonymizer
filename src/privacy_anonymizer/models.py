from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DetectionSpan:
    start: int
    end: int
    label: str
    source: str
    score: float = 1.0
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("Invalid span offsets")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps_or_touches(self, other: "DetectionSpan", max_gap: int = 0) -> bool:
        return self.start <= other.end + max_gap and other.start <= self.end + max_gap

