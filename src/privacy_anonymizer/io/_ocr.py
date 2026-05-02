"""Shared OCR helpers: configurable settings + singleton RapidOCR engine.

The PDF and image adapters both rely on RapidOCR. Constructing a fresh
engine per file (or per page) is wasteful — model files have to be loaded
each time. This module exposes a thread-safe singleton plus a small
settings record set once by the Anonymizer at startup.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass


@dataclass(slots=True)
class OcrSettings:
    dpi: int = 300
    parallel_pages: bool = True
    max_workers: int = 4


_settings = OcrSettings()
_engine = None
_engine_lock = threading.Lock()


def configure(*, dpi: int | None = None, parallel_pages: bool | None = None, max_workers: int | None = None) -> None:
    """Update OCR settings. Unset values keep their previous value."""
    if dpi is not None:
        _settings.dpi = max(72, int(dpi))
    if parallel_pages is not None:
        _settings.parallel_pages = bool(parallel_pages)
    if max_workers is not None:
        _settings.max_workers = max(1, int(max_workers))


def get_settings() -> OcrSettings:
    return _settings


def get_engine(warnings: list[str] | None = None):
    """Return a process-wide RapidOCR engine, creating it on first call.

    Returns ``None`` when RapidOCR is not installed; the caller decides how
    to surface that to the user (warning, fallback, etc.).
    """
    global _engine
    if _engine is not None:
        return _engine
    with _engine_lock:
        if _engine is not None:
            return _engine
        engine = _instantiate(warnings)
        _engine = engine
        return _engine


def reset_engine() -> None:
    """Drop the cached engine (test helper / `--wipe-cache`)."""
    global _engine
    with _engine_lock:
        _engine = None


def _instantiate(warnings: list[str] | None):
    try:
        from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
        _redirect_rapidocr_logging()
        return RapidOCR()
    except ImportError:
        pass
    try:
        from rapidocr import RapidOCR  # type: ignore[import-not-found]
        _redirect_rapidocr_logging()
        return RapidOCR()
    except ImportError:
        if warnings is not None:
            warnings.append("RapidOCR non installato: nessun fallback OCR disponibile.")
        return None
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"Inizializzazione RapidOCR fallita: {exc}")
        return None


def _redirect_rapidocr_logging() -> None:
    """Let RapidOCR logs propagate to root rather than printing to stderr."""
    for name in ("RapidOCR", "rapidocr"):
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        logger.propagate = True
