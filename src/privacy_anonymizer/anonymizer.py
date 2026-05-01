from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from privacy_anonymizer.config import LayerConfig, MaskingMode
from privacy_anonymizer.detectors import GlinerDetector, ItalianPatternDetector, OpfDetector
from privacy_anonymizer.io import SUPPORTED_EXTENSIONS, get_adapter
from privacy_anonymizer.io.docling_parser import DoclingTextExtractor
from privacy_anonymizer.masking import ReplacementSpan, build_masking_plan, mask_text
from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import category_counts, resolve_spans


@dataclass(slots=True)
class ProcessResult:
    text: str
    anonymized_text: str
    spans: list[DetectionSpan]
    audit_report: dict
    output_path: Path | None = None
    replacements: list[ReplacementSpan] | None = None

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.write_text(self.anonymized_text, encoding="utf-8")
        self.output_path = destination
        return destination


@dataclass(slots=True)
class BatchProcessResult:
    results: list[ProcessResult]
    skipped: list[tuple[Path, str]]

    @property
    def processed_count(self) -> int:
        return len(self.results)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


class Anonymizer:
    def __init__(self, config: LayerConfig | None = None, device: str = "cpu") -> None:
        self.config = config or LayerConfig()
        self.device = device
        self.pattern_detector = ItalianPatternDetector()
        self.docling_extractor = DoclingTextExtractor() if self.config.parser == "docling" else None
        self.gliner_detector = (
            GlinerDetector(self.config.gliner_model, self.config.gliner_threshold)
            if self.config.gliner_enabled
            else None
        )
        self.opf_detector = OpfDetector(self.config.opf_recall_mode) if self.config.opf_enabled else None

    def process_text(self, text: str, language: str = "it") -> tuple[str, dict[str, int]]:
        spans = self.detect_text(text, language=language)
        return mask_text(text, spans, self.config.masking_mode), category_counts(spans)

    def analyze_text(self, text: str, language: str = "it") -> ProcessResult:
        started = time.perf_counter()
        spans = self.detect_text(text, language=language)
        plan = build_masking_plan(text, spans, self.config.masking_mode)
        audit = self._audit_report(
            source_file=None,
            output_file=None,
            spans=spans,
            elapsed=time.perf_counter() - started,
        )
        return ProcessResult(
            text=text,
            anonymized_text=plan.text,
            spans=spans,
            audit_report=audit,
            replacements=plan.replacements,
        )

    def process_file(
        self,
        path: str | Path,
        output_dir: str | Path | None = None,
        output_path: str | Path | None = None,
        dry_run: bool = False,
    ) -> ProcessResult:
        source = Path(path)
        adapter = get_adapter(source)

        started = time.perf_counter()
        content = self.docling_extractor.read_text(source) if self.docling_extractor else adapter.read_text(source)
        spans = self.detect_text(content.text)
        plan = build_masking_plan(content.text, spans, self.config.masking_mode)
        destination = Path(output_path) if output_path else self._output_path(source, output_dir, adapter.output_suffix(source))
        output_path_resolved = None if dry_run else destination
        write_warnings: list[str] = []
        metadata_stripped = not self.config.keep_metadata

        if output_path_resolved is not None:
            output_path_resolved.parent.mkdir(parents=True, exist_ok=True)
            write_result = adapter.write_anonymized(
                source,
                output_path_resolved,
                plan.text,
                keep_metadata=self.config.keep_metadata,
                replacements=plan.replacements,
                original_text=content.text,
            )
            write_warnings.extend(write_result.warnings)
            metadata_stripped = write_result.metadata_stripped

        audit = self._audit_report(
            source_file=source,
            output_file=output_path_resolved,
            spans=spans,
            elapsed=time.perf_counter() - started,
            warnings=[*content.warnings, *write_warnings],
            metadata_stripped=metadata_stripped,
        )
        result = ProcessResult(content.text, plan.text, spans, audit, output_path_resolved, plan.replacements)

        if output_path_resolved is not None:
            output_path_resolved.with_suffix(output_path_resolved.suffix + ".audit.json").write_text(
                json.dumps(audit, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return result

    def process_folder(
        self,
        folder: str | Path,
        output_dir: str | Path,
        dry_run: bool = False,
        recursive: bool | None = None,
    ) -> BatchProcessResult:
        source_dir = Path(folder)
        destination_dir = Path(output_dir)
        if not source_dir.is_dir():
            raise ValueError(f"Cartella non trovata: {source_dir}")

        should_recurse = self.config.recursive if recursive is None else recursive
        iterator = source_dir.rglob("*") if should_recurse else source_dir.glob("*")
        results: list[ProcessResult] = []
        skipped: list[tuple[Path, str]] = []

        for source in sorted(path for path in iterator if path.is_file()):
            if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
                skipped.append((source, "formato non supportato"))
                continue
            relative = source.relative_to(source_dir)
            target_dir = destination_dir / relative.parent
            try:
                results.append(self.process_file(source, output_dir=target_dir, dry_run=dry_run))
            except Exception as exc:
                skipped.append((source, str(exc)))

        return BatchProcessResult(results=results, skipped=skipped)

    def detect_text(self, text: str, language: str = "it") -> list[DetectionSpan]:
        del language
        spans: list[DetectionSpan] = []
        if self.config.opf_enabled and self.opf_detector is not None:
            spans.extend(self.opf_detector.detect(text))
        if self.config.gliner_enabled and self.gliner_detector is not None:
            spans.extend(self.gliner_detector.detect(text))
        if self.config.pattern_enabled:
            spans.extend(self.pattern_detector.detect(text))
        return resolve_spans(spans)

    def _audit_report(
        self,
        source_file: Path | None,
        output_file: Path | None,
        spans: list[DetectionSpan],
        elapsed: float,
        warnings: list[str] | None = None,
        metadata_stripped: bool | None = None,
    ) -> dict:
        return {
            "tool_version": "0.1.0",
            "source_file": str(source_file) if source_file else None,
            "output_file": str(output_file) if output_file else None,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "processing_time_seconds": round(elapsed, 4),
            "layers_used": self._layers_used(),
            "entities_found": {
                "opf_spans": sum(1 for span in spans if span.source == "opf"),
                "gliner_spans": sum(1 for span in spans if span.source == "gliner"),
                "pattern_spans": sum(1 for span in spans if span.source == "pattern"),
                "merged_unique_spans": len(spans),
                "by_category": category_counts(spans),
            },
            "metadata_stripped": not self.config.keep_metadata if metadata_stripped is None else metadata_stripped,
            "warnings": warnings or [],
        }

    def _output_path(self, source: Path, output_dir: str | Path | None, suffix: str | None = None) -> Path:
        directory = Path(output_dir) if output_dir else source.parent
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{source.stem}_anonymized{suffix or source.suffix}"

    def _layers_used(self) -> list[str]:
        layers = []
        if self.config.opf_enabled:
            layers.append("opf")
        if self.config.gliner_enabled:
            layers.append("gliner")
        if self.config.pattern_enabled:
            layers.append("pattern")
        return layers
