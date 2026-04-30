from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from privacy_anonymizer.config import LayerConfig, MaskingMode
from privacy_anonymizer.detectors import ItalianPatternDetector
from privacy_anonymizer.masking import mask_text
from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import category_counts, resolve_spans

TEXT_EXTENSIONS = {".txt", ".md", ".log", ".csv"}


@dataclass(slots=True)
class ProcessResult:
    text: str
    anonymized_text: str
    spans: list[DetectionSpan]
    audit_report: dict
    output_path: Path | None = None

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.write_text(self.anonymized_text, encoding="utf-8")
        self.output_path = destination
        return destination


class Anonymizer:
    def __init__(self, config: LayerConfig | None = None, device: str = "cpu") -> None:
        self.config = config or LayerConfig()
        self.device = device
        self.pattern_detector = ItalianPatternDetector()

    def process_text(self, text: str, language: str = "it") -> tuple[str, dict[str, int]]:
        spans = self.detect_text(text, language=language)
        return mask_text(text, spans, self.config.masking_mode), category_counts(spans)

    def analyze_text(self, text: str, language: str = "it") -> ProcessResult:
        started = time.perf_counter()
        spans = self.detect_text(text, language=language)
        anonymized = mask_text(text, spans, self.config.masking_mode)
        audit = self._audit_report(
            source_file=None,
            output_file=None,
            spans=spans,
            elapsed=time.perf_counter() - started,
        )
        return ProcessResult(text=text, anonymized_text=anonymized, spans=spans, audit_report=audit)

    def process_file(
        self,
        path: str | Path,
        output_dir: str | Path | None = None,
        output_path: str | Path | None = None,
        dry_run: bool = False,
    ) -> ProcessResult:
        source = Path(path)
        if source.suffix.lower() not in TEXT_EXTENSIONS:
            raise ValueError(f"Formato non ancora supportato nell'MVP: {source.suffix or '(senza estensione)'}")

        started = time.perf_counter()
        text = source.read_text(encoding="utf-8")
        spans = self.detect_text(text)
        anonymized = mask_text(text, spans, self.config.masking_mode)
        destination = Path(output_path) if output_path else self._output_path(source, output_dir)
        output_path_resolved = None if dry_run else destination
        audit = self._audit_report(
            source_file=source,
            output_file=output_path_resolved,
            spans=spans,
            elapsed=time.perf_counter() - started,
        )
        result = ProcessResult(text, anonymized, spans, audit, output_path_resolved)

        if output_path_resolved is not None:
            output_path_resolved.parent.mkdir(parents=True, exist_ok=True)
            result.save(output_path_resolved)
            output_path_resolved.with_suffix(output_path_resolved.suffix + ".audit.json").write_text(
                json.dumps(audit, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return result

    def detect_text(self, text: str, language: str = "it") -> list[DetectionSpan]:
        del language
        spans: list[DetectionSpan] = []
        if self.config.pattern_enabled:
            spans.extend(self.pattern_detector.detect(text))
        return resolve_spans(spans)

    def _audit_report(
        self,
        source_file: Path | None,
        output_file: Path | None,
        spans: list[DetectionSpan],
        elapsed: float,
    ) -> dict:
        return {
            "tool_version": "0.1.0",
            "source_file": str(source_file) if source_file else None,
            "output_file": str(output_file) if output_file else None,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "processing_time_seconds": round(elapsed, 4),
            "layers_used": ["pattern"] if self.config.pattern_enabled else [],
            "entities_found": {
                "pattern_spans": len(spans),
                "merged_unique_spans": len(spans),
                "by_category": category_counts(spans),
            },
            "metadata_stripped": not self.config.keep_metadata,
            "warnings": [],
        }

    def _output_path(self, source: Path, output_dir: str | Path | None) -> Path:
        directory = Path(output_dir) if output_dir else source.parent
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{source.stem}_anonymized{source.suffix}"
