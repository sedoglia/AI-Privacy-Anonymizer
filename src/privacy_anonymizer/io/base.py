from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FileContent:
    text: str
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WriteResult:
    warnings: list[str] = field(default_factory=list)
    metadata_stripped: bool = False


class FileAdapter(ABC):
    extensions: set[str]

    @abstractmethod
    def read_text(self, path: Path) -> FileContent:
        raise NotImplementedError

    @abstractmethod
    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        raise NotImplementedError

