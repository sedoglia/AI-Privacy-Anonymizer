# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-05-08

### Changed
- Removed the `[opf]` pip extra: PyPI rejects packages containing `git+https://` URL dependencies. Users who need Layer 1 (OPF) must install it manually after `[recommended]`.
- The `[full]` extra now equals `[recommended]` (OPF is no longer pulled in automatically).
- Installation docs updated in both READMEs to show the two-step OPF install and the `--install-full` shortcut.

### Fixed
- **PDF output**: JPEG pages are now written at the original scan DPI instead of a hard-coded value, preserving image quality.
- **JSON reader**: files encoded with a UTF-8 BOM (`﻿`) are now read correctly (`utf-8-sig` codec).
- **PII detection**: improved robustness across edge cases — tighter phone regexes, better handling of product names / URLs / CSV separators in ML spans, refined vehicle-type and name categorisation.

---

## [0.2.0] - 2026-05-07

First public release on [PyPI](https://pypi.org/project/ai-privacy-anonymizer/0.2.0/).  
Focus: packaging quality, test coverage, and Windows EXE distribution.

### Added
- **REST API test suite** (`tests/api/`) — 83 tests covering all endpoints; includes a `--live` marker for tests that require a running server.
- **Windows standalone EXE** — PyInstaller build scripts in `dist/`; bundles all data files and Python sources needed by Gradio.
- **Comprehensive test coverage** — 446 tests total (363 core + 83 API), zero blocking warnings.

### Changed
- PyPI metadata enriched: `classifiers`, `keywords`, `[project.urls]` (Homepage, Repository, Issues, Releases).
- All version references aligned to `0.2.0` across `pyproject.toml`, audit JSON, FastAPI app, MCP `serverInfo`, and both READMEs.
- Updated READMEs with missing pattern docs, `DetectionSpan` methods, and test structure overview.

### Fixed
- CI: added `httpx` to `[dev]` (required by FastAPI `TestClient`).
- CI: added `[api]` extra to the install step (FastAPI is not in `[recommended]`).
- PyInstaller bundle: missing Gradio data files and Python sources are now explicitly included.
- Removed unused imports across `src/` (verified with `pyflakes` / `vulture`).

---

## [0.1.0] - 2026-05-05

Initial release. Full feature set for local, offline PII anonymization of Italian documents.

### Added

#### Core pipeline
- Hybrid 3-layer detection pipeline:
  - **Layer 1 — OPF** (OpenAI Privacy Filter): semantic context, 8 categories.
  - **Layer 2 — GLiNER**: multilingual NER, 60+ PII categories.
  - **Layer 3 — Italian patterns**: deterministic regex + checksum validation.
- All layers are optional and independently configurable via `LayerConfig`.
- Conflict resolution with source priority (pattern > OPF > GLiNER) and span deduplication.

#### Italian PII patterns
- Codice Fiscale (checksum-validated)
- Partita IVA (checksum-validated)
- IBAN
- Targa automobilistica
- Tessera Sanitaria / STP / ENI
- Codice INPS
- Indirizzo postale italiano (`INDIRIZZO_IT_PATTERN`)
- Documento d'identità (CI, patente, passaporto — `DOCUMENTO_ID`)
- Numero di telefono (fisso e mobile, varianti internazionali)
- Email, URL, coordinate GPS
- Nome/cognome, organizzazione, data, importo monetario

#### Supported file formats
- Plain text (`.txt`)
- PDF — selectable text and scanned (OCR via RapidOCR)
- Word (`.docx`)
- Excel (`.xlsx`, `.xls`)
- PowerPoint (`.pptx`)
- CSV
- JSON (full round-trip anonymization)
- HTML
- RTF (`.rtf`)
- Outlook messages (`.msg`)

#### Interfaces
- **CLI** (`privacy-anonymizer`): single file, batch folder, stdin/stdout.
- **Web UI** (`privacy-anonymizer-web`): Gradio interface, auto-opens browser on launch.
- **REST API** (`privacy-anonymizer --api`): FastAPI, endpoints for text, file upload, batch, and compliance report.
- **MCP server** (`privacy-anonymizer-mcp`): stdio transport for Claude Desktop integration.

#### CLI flags
- `--output` — custom output path.
- `--pattern-only` — skip ML layers, use regex only (fast, no GPU needed).
- `--disable-layer opf|gliner|pattern` — selectively disable individual layers.
- `--recall-mode conservative|balanced|aggressive` — OPF sensitivity.
- `--log` — enable verbose INFO logging.
- `--setup` — print dependency status and layer availability.
- `--install-full` — install `[recommended]` + OPF from GitHub in one command.

#### Performance
- Text chunking for long documents.
- Parallel OCR page processing.
- GPU auto-detection (CUDA → CPU fallback).
- ML-layer skip for short texts below threshold.
- Singleton model engine (load once, reuse across calls).
- OPF GPU fix: Triton MoE kernels disabled to prevent CUDA crashes.

#### OCR & PDF redaction
- RapidOCR + ONNX Runtime for image-based PDF pages.
- Coordinate-based redaction (black boxes) for PDFs and images.
- Fuzzy matching fallback for heavily corrupted OCR output.
- Char-offset matching for tokens with punctuation.

#### Resilience
- GLiNER degrades gracefully when the package is not installed.
- OPF degrades gracefully when the package is not installed.
- Fallback text-content matching when char-offset alignment fails.

#### Documentation
- Bilingual READMEs (Italian `README.md` and English `README_EN.md`).
- Architecture diagram, layer comparison table, API reference, Python SDK examples.
- Quick Start section for CLI, Web UI, REST API, and MCP.

---

[0.2.1]: https://github.com/sedoglia/AI-Privacy-Anonymizer/releases/tag/v0.2.1
[0.2.0]: https://github.com/sedoglia/AI-Privacy-Anonymizer/releases/tag/v0.2.0
[0.1.0]: https://github.com/sedoglia/AI-Privacy-Anonymizer/releases/tag/v0.1.0
