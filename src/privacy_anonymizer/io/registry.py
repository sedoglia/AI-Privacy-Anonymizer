from __future__ import annotations

from pathlib import Path

from privacy_anonymizer.io.base import FileAdapter
from privacy_anonymizer.io.email_files import EmlAdapter
from privacy_anonymizer.io.images import ImageAdapter
from privacy_anonymizer.io.legacy import RtfAdapter
from privacy_anonymizer.io.office import DocxAdapter, PptxAdapter, XlsxAdapter
from privacy_anonymizer.io.pdf import PdfAdapter
from privacy_anonymizer.io.text_files import TextFileAdapter

ADAPTERS: tuple[FileAdapter, ...] = (
    TextFileAdapter(),
    DocxAdapter(),
    XlsxAdapter(),
    PptxAdapter(),
    PdfAdapter(),
    ImageAdapter(),
    EmlAdapter(),
    RtfAdapter(),
)
SUPPORTED_EXTENSIONS = frozenset(extension for adapter in ADAPTERS for extension in adapter.extensions)


def get_adapter(path: Path) -> FileAdapter:
    extension = path.suffix.lower()
    for adapter in ADAPTERS:
        if extension in adapter.extensions:
            return adapter
    supported = ", ".join(supported_extensions())
    raise ValueError(f"Formato non supportato: {extension or '(senza estensione)'}. Supportati ora: {supported}")


def supported_extensions() -> list[str]:
    return sorted(SUPPORTED_EXTENSIONS)
