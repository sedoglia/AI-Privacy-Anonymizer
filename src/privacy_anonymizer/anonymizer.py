from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from privacy_anonymizer.config import LayerConfig, MaskingMode

logger = logging.getLogger(__name__)
from privacy_anonymizer.detectors import GlinerDetector, ItalianPatternDetector, OpfDetector
from privacy_anonymizer.io import SUPPORTED_EXTENSIONS, get_adapter
from privacy_anonymizer.io import _ocr
from privacy_anonymizer.masking import ReplacementSpan, build_masking_plan, mask_text
from privacy_anonymizer.models import DetectionSpan
from privacy_anonymizer.resolver import category_counts, resolve_spans


class _RichProgressBar:
    def __init__(self, total: int) -> None:
        from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeRemainingColumn

        self._progress = Progress(
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("{task.fields[current]}"),
            TimeRemainingColumn(),
            transient=True,
        )
        self._task_id = self._progress.add_task("Anonimizzazione", total=total, current="")
        self._progress.start()

    def advance(self, current: str) -> None:
        self._progress.update(self._task_id, advance=1, current=current)

    def close(self) -> None:
        self._progress.stop()


class _PlainProgressBar:
    def __init__(self, total: int) -> None:
        self._total = total
        self._index = 0

    def advance(self, current: str) -> None:
        self._index += 1
        print(f"  [{self._index}/{self._total}] {current}", flush=True)

    def close(self) -> None:
        return None


def _open_progress_bar(total: int):
    if total <= 0:
        return None
    try:
        return _RichProgressBar(total)
    except ImportError:
        return _PlainProgressBar(total)


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
    def __init__(self, config: LayerConfig | None = None, device: str = "auto") -> None:
        self.config = config or LayerConfig()
        self.device = _resolve_device(device)
        if device == "auto":
            logger.info("Device ML auto-detect: %s", self.device)
        self.pattern_detector = ItalianPatternDetector()
        self.gliner_detector = (
            GlinerDetector(self.config.gliner_model, self.config.gliner_threshold, device=self.device)
            if self.config.gliner_enabled
            else None
        )
        self.opf_detector = (
            OpfDetector(self.config.opf_recall_mode, device=self.device)
            if self.config.opf_enabled
            else None
        )
        _ocr.configure(
            dpi=self.config.ocr_dpi,
            parallel_pages=self.config.ocr_parallel_pages,
            max_workers=self.config.ocr_max_workers,
        )
        logger.info("Layer attivi: %s", ", ".join(self._layers_used()) or "nessuno")

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

        logger.info("Elaborazione: %s", source.name)
        started = time.perf_counter()
        content = adapter.read_text(source)
        logger.info("Testo estratto: %d caratteri da %s", len(content.text), source.name)
        skip_ml = self._should_skip_ml(source, content.text)
        if skip_ml:
            logger.info(
                "ML skip: %s (estensione %s, %d caratteri >= %d) — solo layer pattern.",
                source.name,
                source.suffix.lower(),
                len(content.text),
                self.config.ml_skip_min_chars,
            )
        spans = self.detect_text(content.text, skip_ml=skip_ml)
        logger.info("Rilevati %d span PII in %s", len(spans), source.name)
        plan = build_masking_plan(content.text, spans, self.config.masking_mode)
        destination = Path(output_path) if output_path else self._output_path(source, output_dir, adapter.output_suffix(source))
        output_path_resolved = None if dry_run else destination
        write_warnings: list[str] = []
        metadata_stripped = not self.config.keep_metadata

        if output_path_resolved is not None:
            output_path_resolved.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Scrittura output: %s", output_path_resolved.name)
            write_result = adapter.write_anonymized(
                source,
                output_path_resolved,
                plan.text,
                keep_metadata=self.config.keep_metadata,
                replacements=plan.replacements,
                original_text=content.text,
                source_content=content,
            )
            write_warnings.extend(write_result.warnings)
            metadata_stripped = write_result.metadata_stripped

        elapsed = time.perf_counter() - started
        logger.info("Completato %s: %d span in %.2fs", source.name, len(spans), elapsed)
        audit = self._audit_report(
            source_file=source,
            output_file=output_path_resolved,
            spans=spans,
            elapsed=elapsed,
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
        progress: bool = False,
    ) -> BatchProcessResult:
        source_dir = Path(folder)
        destination_dir = Path(output_dir)
        if not source_dir.is_dir():
            raise ValueError(f"Cartella non trovata: {source_dir}")

        should_recurse = self.config.recursive if recursive is None else recursive
        iterator = source_dir.rglob("*") if should_recurse else source_dir.glob("*")
        candidates = sorted(path for path in iterator if path.is_file())
        logger.info("Cartella %s: %d file trovati", source_dir.name, len(candidates))
        results: list[ProcessResult] = []
        skipped: list[tuple[Path, str]] = []

        progress_bar = _open_progress_bar(len(candidates)) if progress else None
        try:
            for source in candidates:
                if source.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    skipped.append((source, "formato non supportato"))
                    if progress_bar is not None:
                        progress_bar.advance(source.name)
                    continue
                relative = source.relative_to(source_dir)
                target_dir = destination_dir / relative.parent
                try:
                    results.append(self.process_file(source, output_dir=target_dir, dry_run=dry_run))
                except Exception as exc:
                    skipped.append((source, str(exc)))
                if progress_bar is not None:
                    progress_bar.advance(source.name)
        finally:
            if progress_bar is not None:
                progress_bar.close()

        return BatchProcessResult(results=results, skipped=skipped)

    def detect_text(
        self, text: str, language: str = "it", skip_ml: bool = False
    ) -> list[DetectionSpan]:
        del language
        ml_active = not skip_ml
        tasks: list[tuple[str, callable]] = []
        if ml_active and self.config.opf_enabled and self.opf_detector is not None:
            tasks.append(("opf", lambda: self._chunked_detect(self.opf_detector, text)))
        if ml_active and self.config.gliner_enabled and self.gliner_detector is not None:
            tasks.append(("gliner", lambda: self._chunked_detect(self.gliner_detector, text)))
        if self.config.pattern_enabled:
            tasks.append(("pattern", lambda: self.pattern_detector.detect(text)))

        spans: list[DetectionSpan] = []
        if self.config.parallel and len(tasks) > 1 and not self.config.low_memory:
            logger.info("Rilevamento parallelo: %s", ", ".join(n for n, _ in tasks))
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                for partial in executor.map(lambda task: task[1](), tasks):
                    spans.extend(partial)
        else:
            for name, run in tasks:
                logger.info("Layer %s: avvio", name)
                t0 = time.perf_counter()
                result = run()
                logger.info("Layer %s: %d span in %.2fs", name, len(result), time.perf_counter() - t0)
                spans.extend(result)
                if self.config.low_memory and name == "opf" and self.opf_detector is not None:
                    self.opf_detector.release()
                if self.config.low_memory and name == "gliner" and self.gliner_detector is not None:
                    self.gliner_detector.release()
        resolved = resolve_spans(spans, text=text)
        resolved = _filter_false_positive_personas(text, resolved)
        return _expand_all_occurrences(text, resolved)

    def _chunked_detect(self, detector, text: str) -> list[DetectionSpan]:
        """Run a detector on text, splitting long inputs into overlapping chunks.

        For texts shorter than `chunk_threshold` the detector runs once on the
        full text. Otherwise the text is split into overlapping windows and
        chunks are processed in parallel; spans are remapped to absolute offsets
        and overlapping duplicates near boundaries are deduplicated downstream
        by `resolve_spans`.
        """
        if (
            not self.config.chunk_long_text
            or len(text) <= self.config.chunk_threshold
            or self.config.chunk_size <= 0
        ):
            return detector.detect(text)

        windows = _build_chunks(
            text,
            chunk_size=self.config.chunk_size,
            overlap=max(0, self.config.chunk_overlap),
        )
        if len(windows) <= 1:
            return detector.detect(text)

        logger.info(
            "Chunking %s: %d finestre (size=%d, overlap=%d, max_workers=%d)",
            getattr(detector, "source", "detector"),
            len(windows),
            self.config.chunk_size,
            self.config.chunk_overlap,
            self.config.chunk_max_workers,
        )

        from concurrent.futures import ThreadPoolExecutor

        def _run(window: tuple[int, int]) -> list[DetectionSpan]:
            start, end = window
            sub_spans = detector.detect(text[start:end])
            return [
                DetectionSpan(
                    start=span.start + start,
                    end=span.end + start,
                    label=span.label,
                    source=span.source,
                    score=span.score,
                )
                for span in sub_spans
            ]

        workers = max(1, min(self.config.chunk_max_workers, len(windows)))
        results: list[DetectionSpan] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for partial in executor.map(_run, windows):
                results.extend(partial)
        return results

    def _should_skip_ml(self, source: Path, text: str) -> bool:
        extensions = {ext.lower() for ext in (self.config.ml_skip_extensions or ())}
        if not extensions:
            return False
        if source.suffix.lower() not in extensions:
            return False
        return len(text) >= self.config.ml_skip_min_chars



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
            "track_changes_accepted": not self.config.keep_metadata,
            "opf_recall_mode": self.config.opf_recall_mode if self.config.opf_enabled else None,
            "low_memory": self.config.low_memory,
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


def _resolve_device(requested: str) -> str:
    """Resolve a requested device string to an actual device name.

    "auto" probes for CUDA via torch and falls back to CPU. Any explicit
    value is returned unchanged so users can force "cpu"/"cuda"/"mps".
    """
    if not requested or requested == "auto":
        try:
            import torch  # type: ignore[import-not-found]

            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        except Exception:
            pass
        return "cpu"
    return requested


def _build_chunks(text: str, chunk_size: int, overlap: int) -> list[tuple[int, int]]:
    """Split text into overlapping windows aligned to whitespace where possible.

    Returns a list of (start, end) absolute offsets covering the full text.
    Boundaries are nudged backward to the nearest whitespace inside the last
    20% of the window to avoid cutting words/entities. Overlap helps span
    detection across boundaries; duplicate spans are deduplicated by the
    span resolver downstream.
    """
    n = len(text)
    if chunk_size <= 0 or n <= chunk_size:
        return [(0, n)]
    overlap = max(0, min(overlap, chunk_size // 2))
    windows: list[tuple[int, int]] = []
    start = 0
    while start < n:
        end = min(start + chunk_size, n)
        if end < n:
            soft_floor = end - max(1, chunk_size // 5)
            for cursor in range(end, soft_floor, -1):
                if text[cursor - 1] in (" ", "\n", "\t", "\r"):
                    end = cursor
                    break
        windows.append((start, end))
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return windows


_URL_LIKE_RE = re.compile(r"https?://|www\.|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}", re.I)


def _filter_false_positive_personas(text: str, spans: list[DetectionSpan]) -> list[DetectionSpan]:
    """Remove spans that ML models misclassify as PII.

    - PERSONA containing Arabic digits → institutional code, not a person name.
    - URL with no URL-like pattern (no protocol, dot-domain, or www) → common word
      misidentified as a link by GLiNER/OPF.
    """
    result = []
    for span in spans:
        span_text = text[span.start : span.end]
        if span.label == "PERSONA" and re.search(r"\d", span_text):
            continue
        if span.label == "URL" and not _URL_LIKE_RE.search(span_text):
            continue
        result.append(span)
    return result


def _expand_all_occurrences(text: str, spans: list[DetectionSpan]) -> list[DetectionSpan]:
    """For every detected multi-word entity, find ALL literal occurrences in the text.

    NER models can miss repeated instances of the same entity (e.g. a person's name
    appearing in the header and again in the body). This step ensures that once an
    entity value is confirmed as PII, every verbatim occurrence is covered.
    Only multi-word values are expanded to avoid over-redacting common single words.
    """
    covered: set[tuple[int, int]] = {(s.start, s.end) for s in spans}
    entity_map: dict[str, tuple[str, str, float]] = {}
    for span in spans:
        value = text[span.start : span.end].strip()
        if len(value.split()) >= 2:
            norm = " ".join(value.upper().split())
            if norm not in entity_map:
                entity_map[norm] = (span.label, span.source, span.score)

    if not entity_map:
        return spans

    extra: list[DetectionSpan] = []
    for norm, (label, source, score) in entity_map.items():
        for match in re.finditer(re.escape(norm), text, re.IGNORECASE):
            key = (match.start(), match.end())
            if key not in covered:
                extra.append(DetectionSpan(match.start(), match.end(), label, source, score))
                covered.add(key)

    if not extra:
        return spans
    return resolve_spans(spans + extra, text=text)
