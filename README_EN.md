# AI Privacy Anonymizer

**Version:** 0.1.0  
**Author:** Sergio Dogliani  
**License:** MIT  
**Python:** ≥ 3.11

A local Python tool for automatically detecting and masking personally identifiable information (PII) from documents of various formats before uploading them to AI chatbots (Claude, ChatGPT, Gemini, etc.) without risk of data leakage. Everything runs locally: **no data ever leaves the device** during anonymization.

---

## Table of Contents

- [3-layer hybrid architecture](#3-layer-hybrid-architecture)
- [Detected PII categories](#detected-pii-categories)
- [Supported file formats](#supported-file-formats)
- [Masking modes](#masking-modes)
- [Installation](#installation)
- [Usage — CLI](#usage--cli)
- [Usage — Python API](#usage--python-api)
- [Local Web UI (Gradio)](#local-web-ui-gradio)
- [Local REST API (FastAPI)](#local-rest-api-fastapi)
- [MCP stdio Server](#mcp-stdio-server)
- [Span Resolver and consistent mapping](#span-resolver-and-consistent-mapping)
- [Metadata handling](#metadata-handling)
- [JSON audit log](#json-audit-log)
- [GDPR compliance report (PDF)](#gdpr-compliance-report-pdf)
- [Synthetic dataset and evaluation](#synthetic-dataset-and-evaluation)
- [Entity vault for de-anonymization](#entity-vault-for-de-anonymization)
- [System requirements](#system-requirements)
- [Known limitations](#known-limitations)

---

## 3-layer hybrid architecture

The project uses a hybrid architecture combining three complementary detectors to maximize recall (prioritized over precision for the pre-chatbot use case):

```
INPUT FILE
    │
    ▼
DOCLING (optional) ─── multi-format parser with AI layout and OCR
    │
    ▼
TEXT SEGMENTER ─── splits into sentence-respecting chunks
    │
    ├─────────────────────┬─────────────────────┐
    ▼                     ▼                     ▼
LAYER 1               LAYER 2               LAYER 3
OpenAI OPF            GLiNER                Italian Pattern Recognizer
8 categories          60+ categories        Regex + checksum
semantic context      Italian-native        deterministic
    │                     │                     │
    └─────────────────────┴─────────────────────┘
                          │
                    SPAN RESOLVER
              (merge, deduplication, priority)
                          │
                    MASKING ENGINE
                          │
                 FILE RECONSTRUCTOR
                          │
              OUTPUT FILE + JSON AUDIT LOG
```

### Layer 1 — OpenAI Privacy Filter (OPF)

- Transformer-based model with up to 128K token context window
- Detects 8 semantic categories: `private_person`, `private_email`, `private_phone`, `private_address`, `private_date`, `private_url`, `account_number`, `secret`
- Configurable Viterbi decoder for high recall:
  - `conservative`: default parameters (high precision)
  - `balanced`: `background_stay=-2.0`, `background_to_start=+1.5`, `span_continuation=+1.0`
  - `aggressive`: `background_stay=-3.0`, `background_to_start=+2.0`, `span_continuation=+1.5`
- Only layer with native `SECRET` category for passwords, API keys, JWT tokens, `.env` values
- Requires external installation (see Installation section)

### Layer 2 — GLiNER `gliner_multi_pii-v1`

- Zero-shot model fine-tuned on Italian for named entity recognition
- Over 60 PII categories including those absent from OPF: `passport_number`, `driver_license`, `health_insurance_id`, `medical_condition`, `credit_card_number`, `cvv`, `blood_type`, `username`, `digital_signature`, `organization`
- Configurable threshold (default: 0.5) to balance recall and precision
- Automatic model download (~300 MB) on first use
- Apache 2.0 license; install via `[ml]` extra

### Layer 3 — Italian Pattern Recognizers (deterministic)

Regex with checksum validation where applicable. Active by default with no extra dependencies.

| Entity | Validation | Example |
|---|---|---|
| `CODICE_FISCALE` | ✅ Luhn-like control character checksum | `RSSMRA80A01L219M` |
| `PARTITA_IVA` | ✅ Mod-11 algorithm | `01114601006` |
| `IBAN_IT` | ✅ IBAN ISO 7064 mod-97-10 algorithm | `IT60X0542811101000000123456` |
| `TARGA_IT` | Pattern (car + motorcycle) | `AB123CD` |
| `CARTA_IDENTITA` | Pattern (`AA1234567` or `CA1234567AB`) | `AX1234567` |
| `CELL_IT` | Pattern (prefix 3xx, opt. +39/0039) | `3401234567` |
| `TEL_IT` | Landline pattern (prefix 0, opt. +39/0039) | `011 1234567` |
| `EMAIL` | RFC-like pattern | `mario@example.it` |
| `PEC` | Email pattern + `.pec.` or `.pec.it` domains | `studio@legalmail.pec.it` |
| `TESSERA_SANITARIA` | 20-digit pattern with `80` prefix | `80380030001234567890` |
| `MATRICOLA_INPS` | 8-9 digit pattern with context keyword | `12345678` (after "matricola INPS") |
| `IP_ADDRESS` | IPv4 pattern with 0-255 octet validation | `192.168.1.10` |

---

## Detected PII categories

Full set of categories emitted to the masking engine after normalization across the three layers:

| Normalized category | Primary source | Notes |
|---|---|---|
| `PERSONA` | OPF + GLiNER | Proper names with context-awareness |
| `EMAIL` | L3 + OPF | Standard mailboxes |
| `PEC` | L3 | Italian Certified Email |
| `TELEFONO` / `CELL_IT` / `TEL_IT` | L3 + OPF | Italian and international numbers |
| `INDIRIZZO` | OPF + GLiNER | Street addresses |
| `DATA_PRIVATA` | OPF + GLiNER | Dates of birth and private dates |
| `URL` | OPF + GLiNER | URLs with personal path |
| `ACCOUNT_NUMBER` | OPF | Generic bank account number |
| `SECRET` | OPF | Passwords, API keys, tokens, secrets |
| `CODICE_FISCALE` | L3 + GLiNER | With checksum validation |
| `PARTITA_IVA` | L3 | With mod-11 validation |
| `IBAN_IT` | L3 + GLiNER | With ISO validation |
| `TARGA_IT` | L3 | Vehicle license plates |
| `CARTA_IDENTITA` | L3 | Italian ID card |
| `TESSERA_SANITARIA` | L3 + GLiNER | Health insurance card and TEAM |
| `MATRICOLA_INPS` | L3 | With context words |
| `IP_ADDRESS` | L3 + GLiNER | Valid IPv4 addresses |
| `USERNAME` | GLiNER | Handles and usernames |
| `PASSAPORTO` | GLiNER | Passport number |
| `PATENTE` | GLiNER | Driver's license |
| `CARTA_CREDITO` | GLiNER | Credit card number |
| `CONDIZIONE_MEDICA` | GLiNER | Diagnoses and clinical conditions |
| `ORGANIZZAZIONE` | GLiNER | Private company name in context |
| `TAX_ID` | GLiNER | Generic tax identifier |

---

## Supported file formats

### Full round-trip (same format in and out)

| Format | Extensions | Parsing | Reconstruction | Notes |
|---|---|---|---|---|
| Plain text | `.txt` `.md` `.log` `.csv` | built-in | built-in | Direct UTF-8 read/write |
| Word | `.docx` | `python-docx` | `python-docx` | Paragraphs + headers + footers + tables + comments |
| Excel | `.xlsx` | `openpyxl` | `openpyxl` | String cells + sheet names + cell comments |
| PowerPoint | `.pptx` | `python-pptx` | `python-pptx` | Shape text + speaker notes |
| Selectable PDF | `.pdf` | `pypdf` | PyMuPDF overlay | Coordinate-level redaction on original bounding boxes |
| Images | `.png` `.jpg` `.jpeg` `.tiff` `.bmp` | RapidOCR (ONNX) | Pillow | Coordinate OCR redaction; fallback to plain-text image |
| Email | `.eml` | stdlib `email` | stdlib `email` | From/To/Cc/Subject + body |
| XML/FatturaPA | `.xml` | `xml.etree` | `xml.etree` | Text and attributes; XML structure preserved |
| RTF | `.rtf` | `striprtf` | minimal built-in | Simplified RTF reconstruction |

### Read-only (anonymized `.txt` output)

| Format | Extensions | Dependency |
|---|---|---|
| Outlook MSG | `.msg` | `extract-msg` (`documents` extra) |
| Legacy Word | `.doc` | best-effort binary (LibreOffice recommended) |
| Legacy Excel | `.xls` | `xlrd` (`documents` extra) |

### Docling parser (optional)

Activated with `--parser docling`. Docling (IBM, MIT license) adds:
- Advanced PDF layout parsing with DocLayNet AI model
- Integrated OCR for scanned PDFs and images
- Table recognition with TableFormer
- Unified multi-format support (PDF, DOCX, XLSX, PPTX, HTML, images)

Requires `[docling]` extra (`pip install -e .[docling]`). Models are downloaded automatically on first use.

---

## Masking modes

| Mode | Output example | Use case |
|---|---|---|
| `replace` *(default)* | `[CF_1]`, `[EMAIL_2]`, `[PERSONA_1]` | Chatbot upload — readable context |
| `redact` | `████████████████` | Documents shared with third parties |
| `generalize` | `[CF]`, `[EMAIL]`, `[PERSONA]` | When sequential numbering is unnecessary |
| `hash` | `[SHA256:a3f2c1d4e5f6]` | Technical pipelines with optional de-anonymization |

All modes support **consistent mapping**: the same entity receives the same placeholder throughout the document (e.g., every occurrence of "Mario Rossi", including partial variants, always becomes `[PERSONA_1]`).

---

## Installation

### Base (Layer 3 only — Italian patterns, no ML)

```bash
pip install ai-privacy-anonymizer
```

### With Office support (DOCX, XLSX, PPTX)

```bash
pip install "ai-privacy-anonymizer[office]"
```

### With document support (PDF, OCR images, EML, MSG, XLS, RTF)

```bash
pip install "ai-privacy-anonymizer[documents]"
```

### With Layer 2 GLiNER

```bash
pip install "ai-privacy-anonymizer[ml]"
```

### With Docling parser

```bash
pip install "ai-privacy-anonymizer[docling]"
```

### With Gradio Web UI

```bash
pip install "ai-privacy-anonymizer[webui]"
```

### With FastAPI REST API

```bash
pip install "ai-privacy-anonymizer[api]"
```

### Recommended setup without OPF (`[recommended]` extra)

```bash
pip install "ai-privacy-anonymizer[recommended]"
```

Installs office, documents, ml (GLiNER), docling, webui, api, rich. **Excludes OPF** (Layer 1) to avoid the ~3 GB download for users who don't need it. This is the suggested choice for most users.

### Complete setup including OPF (`[full]` extra)

```bash
pip install "ai-privacy-anonymizer[full]"
```

Installs the `[recommended]` extra **plus** OPF from the official repository (`git+https://github.com/openai/privacy-filter`). Requires ~5 GB total between dependencies and models.

### One-shot command (alternative to `[full]`)

If you already have the base package installed, you can install everything with:

```bash
privacy-anonymizer --install-full
```

This internally runs `pip install "ai-privacy-anonymizer[recommended]"` followed by the OPF installation from git.

### Local development

```bash
git clone https://github.com/sedoglia/AI-Privacy-Anonymizer.git
cd AI-Privacy-Anonymizer
pip install -e ".[dev,office,documents,ml]"
pytest
```

### Layer 1 OPF only (external, separate installation)

If you don't want `[full]` and prefer to install OPF separately:

```bash
pip install git+https://github.com/openai/privacy-filter
```

Requires ~3 GB of disk space for the model download on first run.

### Italian spaCy model (optional, for Presidio)

```bash
python -m spacy download it_core_news_lg
```

### Setup check

```bash
privacy-anonymizer --setup
```

---

## Usage — CLI

### Anonymize a single file

```bash
privacy-anonymizer documento.docx
```

Output: `documento_anonymized.docx` in the same folder, plus `documento_anonymized.docx.audit.json`.

### Specify output file or folder

```bash
privacy-anonymizer documento.docx --output /path/to/output/
privacy-anonymizer documento.docx --output documento_clean.docx
```

### Anonymize an entire folder

```bash
privacy-anonymizer ./docs/ --output ./docs_clean/
# With recursion disabled
privacy-anonymizer ./docs/ --output ./out/ --no-recursive
```

### Direct text from command line

```bash
privacy-anonymizer --text "Mario Rossi, CF RSSMRA80A01L219M, tel 3401234567"
```

### Masking modes

```bash
privacy-anonymizer report.pdf --mode redact
privacy-anonymizer contratto.docx --mode generalize
privacy-anonymizer dati.xlsx --mode hash
```

### Enable hybrid stack (L1 + L2 + L3)

```bash
# All layers
privacy-anonymizer file.txt --layers hybrid

# GLiNER + patterns only (without OPF)
privacy-anonymizer file.txt --layers hybrid --disable-layer opf

# OPF + patterns only (without GLiNER)
privacy-anonymizer file.txt --layers hybrid --disable-layer gliner

# Italian patterns only (default, fastest)
privacy-anonymizer file.txt --layers pattern-only
```

### OPF recall configuration

```bash
# Conservative mode (high precision, lower recall)
privacy-anonymizer file.txt --layers hybrid --recall-mode conservative

# Balanced mode (default — balanced for chatbot use)
privacy-anonymizer file.txt --layers hybrid --recall-mode balanced

# Aggressive mode (maximum recall)
privacy-anonymizer file.txt --layers hybrid --recall-mode aggressive
```

### Docling parser

```bash
privacy-anonymizer documento.pdf --parser docling
```

### Dry-run (analysis without writing output)

```bash
privacy-anonymizer contratto.docx --dry-run
```

Displays detected spans, categories and counts without producing any file.

### Entity map (categories and placeholders, without original values)

```bash
privacy-anonymizer contratto.docx --show-map
```

Example output:
```
Entity map (categories and placeholders, no original values):
  [CF_1]       ←  CODICE_FISCALE
  [EMAIL_1]    ←  EMAIL
  [PERSONA_1]  ←  PERSONA
  [PIVA_1]     ←  PARTITA_IVA
```

### GDPR compliance report (PDF)

```bash
privacy-anonymizer documento.docx --compliance-report gdpr_report.pdf
```

### Audit output as JSON

```bash
privacy-anonymizer documento.docx --json
```

### Export entity vault (for de-anonymization in hash mode)

```bash
privacy-anonymizer documento.txt --mode hash --export-vault vault.json
```

`vault.json` contains the mapping `placeholder → {label, original}`. **Store securely.**

### Metadata

```bash
# Disable metadata stripping
privacy-anonymizer documento.docx --keep-metadata
```

### Performance and memory

```bash
# Low-memory mode: layers run sequentially, RAM freed between each
privacy-anonymizer file.txt --layers hybrid --low-memory

# Parallelization: layers run on separate threads (incompatible with --low-memory)
privacy-anonymizer file.txt --layers hybrid --parallel

# Force CPU (disables GPU even if available)
privacy-anonymizer file.txt --device cpu
```

### De-anonymization from vault

```bash
# 1. Anonymize in hash mode + export vault
privacy-anonymizer document.txt --mode hash --export-vault vault.json --output anon.txt

# 2. Restore the original text from the vault
privacy-anonymizer --restore vault.json anon.txt --output restored.txt
```

### Maintenance

```bash
# Clear local model/parser cache
privacy-anonymizer --wipe-cache

# Show supported formats
privacy-anonymizer --supported-formats

# Check setup and dependencies
privacy-anonymizer --setup
privacy-anonymizer --download-models --verbose
```

### Synthetic dataset and evaluation

```bash
# Generate synthetic JSONL dataset
privacy-anonymizer --generate-synthetic-dataset ./synthetic.jsonl

# Evaluate a JSONL dataset with "text" and "labels" fields
privacy-anonymizer --evaluate ./synthetic.jsonl
```

---

## Usage — Python API

```python
from privacy_anonymizer import Anonymizer, LayerConfig

# Custom configuration
config = LayerConfig(
    parser="built-in",             # "built-in" | "docling"
    opf_enabled=False,             # requires external OPF installation
    opf_recall_mode="balanced",    # "conservative" | "balanced" | "aggressive"
    gliner_enabled=True,           # requires [ml] extra
    gliner_model="urchade/gliner_multi_pii-v1",
    gliner_threshold=0.5,
    pattern_enabled=True,
    masking_mode="replace",        # "replace" | "redact" | "generalize" | "hash"
    consistent_mapping=True,
    keep_metadata=False,
    recursive=True,
    low_memory=False,
)

anon = Anonymizer(config=config, device="cpu")

# ── Direct text ────────────────────────────────────────────────
masked_text, counts = anon.process_text(
    "Mario Rossi, CF RSSMRA80A01L219M, tel 3401234567",
    language="it",
)
# masked_text → "Mario Rossi, [CF_1], [TEL_1]"
# counts → {"CODICE_FISCALE": 1, "CELL_IT": 1}

# Full result with audit
result = anon.analyze_text("Mario Rossi, mario@example.com")
print(result.anonymized_text)
print(result.audit_report)

# ── Single file ────────────────────────────────────────────────
result = anon.process_file("input.docx")
result.save("output.docx")
print(result.audit_report)

# With explicit output_path
result = anon.process_file("input.pdf", output_path="clean/output.pdf")

# Dry-run
result = anon.process_file("input.xlsx", dry_run=True)

# ── Batch on folder ────────────────────────────────────────────
batch = anon.process_folder("./docs_in/", output_dir="./docs_out/")
print(f"Processed: {batch.processed_count}")
print(f"Skipped: {batch.skipped_count}")
for path, reason in batch.skipped:
    print(f"  SKIP {path}: {reason}")

# ── Span detection without masking ────────────────────────────
spans = anon.detect_text("Mario Rossi, IBAN IT60X0542811101000000123456")
for span in spans:
    print(span.start, span.end, span.label, span.source, span.score)

# ── MaskingPlan with entity vault ─────────────────────────────
from privacy_anonymizer.masking import build_masking_plan
plan = build_masking_plan(text, spans, mode="hash")
vault = plan.entity_vault()  # {placeholder: {label, original}}
```

### Data model: DetectionSpan

```python
@dataclass
class DetectionSpan:
    start: int           # character offset start (inclusive)
    end: int             # character offset end (exclusive)
    label: str           # normalized category (e.g. "CODICE_FISCALE")
    source: str          # "pattern" | "opf" | "gliner"
    score: float         # confidence (1.0 for deterministic patterns)
    metadata: dict       # {"checksum_valid": "true"/"false"} for CF
```

---

## Local Web UI (Gradio)

```bash
privacy-anonymizer --webui
# or
privacy-anonymizer-web
```

Opens `http://127.0.0.1:7860` with:
- **Text tab**: free text input, mode selection, GLiNER checkbox, output + JSON audit
- **File tab**: drag & drop file, same options, anonymized file download

No Internet connection required during use. Requires `pip install -e .[webui]`.

---

## Local REST API (FastAPI)

```bash
privacy-anonymizer --api
# or
privacy-anonymizer-api
```

Starts server at `http://127.0.0.1:8000`. Requires `pip install -e .[api]`.

### Available endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Healthcheck — returns `{"status": "ok"}` |
| `POST` | `/anonymize/text` | Anonymize text (form: `text`, `mode`, `hybrid`) |
| `POST` | `/anonymize/file` | Anonymize file (multipart: `file`, `mode`, `hybrid`) |

### Example with curl

```bash
# Text
curl -X POST http://127.0.0.1:8000/anonymize/text \
  -F "text=Mario Rossi, CF RSSMRA80A01L219M" \
  -F "mode=replace"

# File
curl -X POST http://127.0.0.1:8000/anonymize/file \
  -F "file=@documento.docx" \
  -F "mode=redact" \
  --output documento_redacted.docx
```

Interactive Swagger documentation available at `http://127.0.0.1:8000/docs`.

---

## MCP stdio Server

Integration as an MCP (Model Context Protocol) tool for Claude Desktop and other compatible clients.

```bash
privacy-anonymizer-mcp
```

The server reads JSON-RPC requests from stdin and writes responses to stdout (MCP protocol 2024-11-05).

### Exposed tool: `anonymize_text`

```json
{
  "method": "tools/call",
  "params": {
    "name": "anonymize_text",
    "arguments": { "text": "Mario Rossi, mario@example.com" }
  }
}
```

Configuration in `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "privacy-anonymizer": {
      "command": "privacy-anonymizer-mcp"
    }
  }
}
```

---

## Span Resolver and consistent mapping

The resolver merges spans from the three layers using these rules:

### Source priority

```
Layer 3 (deterministic pattern) > Layer 1 (OPF) > Layer 2 (GLiNER)
```

When two spans overlap exactly, the one with higher priority wins.

### Merge cases

- **Identical spans**: deduplicated, keeps the higher-priority one
- **Nested / overlapping spans**: wider span wins (e.g., `[Mario]` + `[Mario Rossi]` → `[Mario Rossi]`)
- **Adjacent compatible spans** (gap ≤ 3 characters): merged into a single span of the same semantic category
- **Type conflict**: if L3 validates the checksum, L3 wins; otherwise the higher-priority layer wins

### Consistent entity mapping

```
"Mario Rossi"      → [PERSONA_1]   (all occurrences, including partial variants)
"mario@company.it" → [EMAIL_1]
"RSSMRA80A01L219M" → [CF_1]
```

Variant normalization (case-insensitive, collapsed whitespace) ensures the same entity always gets the same placeholder in the document. The map is kept **in RAM only** during execution and never written to disk, unless `--export-vault` is used explicitly.

---

## Metadata handling

Office and PDF file metadata is stripped by default (disable with `--keep-metadata`):

| Field | Format | Action |
|---|---|---|
| Author | DOCX, XLSX, PPTX, PDF | Replaced with `"Anonimo"` |
| `LastModifiedBy` | DOCX, XLSX, PPTX | Replaced with `"Anonimo"` |
| Organization / Company | XLSX | Removed |
| Title, Subject, Keywords | DOCX, XLSX, PPTX | Cleared |
| Document comments | DOCX, XLSX, PPTX | Zeroed (author replaced) |
| XMP / Info dict metadata | PDF | Removed via PyMuPDF |
| EXIF / XMP | JPEG, TIFF, PNG | Full strip (image rebuilt) |
| Cell comment author | XLSX | Replaced with `"Anonimo"` |

---

## JSON audit log

Each processing run produces a `.audit.json` file in the same location as the output file. The log never contains original PII values, only categories and counts.

```json
{
  "tool_version": "0.1.0",
  "source_file": "contratto_fornitura.docx",
  "output_file": "contratto_fornitura_anonymized.docx",
  "processed_at": "2026-04-30T14:32:01+00:00",
  "processing_time_seconds": 12.4,
  "layers_used": ["opf", "gliner", "pattern"],
  "opf_recall_mode": "balanced",
  "low_memory": false,
  "entities_found": {
    "opf_spans": 12,
    "gliner_spans": 4,
    "pattern_spans": 3,
    "merged_unique_spans": 17,
    "by_category": {
      "PERSONA": 4,
      "EMAIL": 2,
      "CODICE_FISCALE": 1,
      "PARTITA_IVA": 1,
      "TELEFONO_IT": 1,
      "INDIRIZZO": 2,
      "DATA_PRIVATA": 3,
      "SECRET": 2,
      "IP_ADDRESS": 1
    }
  },
  "metadata_stripped": true,
  "track_changes_accepted": true,
  "warnings": []
}
```

---

## GDPR compliance report (PDF)

```bash
privacy-anonymizer documento.docx --compliance-report gdpr_report.pdf
```

Generates a PDF (via ReportLab) containing:
- Source and output file references
- Processing timestamp
- Layers used and recall mode
- List of detected PII categories with counts
- Metadata stripping flag
- Processing warnings
- Audit JSON excerpt (truncated to 1500 characters)

Requires `pip install -e .[documents]` (ReportLab).

---

## Synthetic dataset and evaluation

### Generate a synthetic dataset

```bash
privacy-anonymizer --generate-synthetic-dataset ./synthetic.jsonl
```

Each line is a JSON object with `text` (test text) and `labels` (list of expected categories):

```jsonl
{"text": "Mario Rossi CF RSSMRA80A01L219M email mario.rossi@example.com tel 3401234567", "labels": ["CODICE_FISCALE", "EMAIL", "TELEFONO_IT"]}
{"text": "P.IVA 01114601006 IBAN IT60X0542811101000000123456 targa AB123CD", "labels": ["PARTITA_IVA", "IBAN_IT", "TARGA_IT"]}
{"text": "Server 192.168.1.10, PEC studio.rossi@legalmail.pec.it", "labels": ["IP_ADDRESS", "PEC"]}
```

### Evaluate a dataset

```bash
privacy-anonymizer --evaluate ./synthetic.jsonl
```

JSON output with metrics:

```json
{
  "documents": 3,
  "expected_labels": 8,
  "matched_labels": 8,
  "extra_labels": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0
}
```

### From Python

```python
from privacy_anonymizer.evaluation import evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer import Anonymizer, LayerConfig

write_synthetic_dataset("./my_dataset.jsonl")

anon = Anonymizer(LayerConfig(gliner_enabled=True))
metrics = evaluate_dataset("./my_dataset.jsonl", anonymizer=anon)
print(f"F1: {metrics.f1:.2%}")
```

---

## Entity vault for de-anonymization

In `hash` mode, each PII value is replaced with `[SHA256:xxxxxxxx]`. To retain the ability to de-anonymize, use `--export-vault`:

```bash
privacy-anonymizer documento.txt --mode hash --export-vault vault.json
```

`vault.json` example:

```json
{
  "[SHA256:a3f2c1d4e5f6]": {
    "label": "CODICE_FISCALE",
    "original": "RSSMRA80A01L219M"
  },
  "[SHA256:9b1c3e7f2a4d]": {
    "label": "EMAIL",
    "original": "mario@company.it"
  }
}
```

> **Security note:** the vault contains original values in plaintext. Store it on encrypted storage, separate from the anonymized document, and delete it when no longer needed.

From Python:

```python
from privacy_anonymizer.masking import build_masking_plan
plan = build_masking_plan(text, spans, mode="hash")
vault = plan.entity_vault()  # dict {placeholder: {label, original}}
```

---

## System requirements

| Requirement | Minimum (L3 only) | With L2 GLiNER | With L1 OPF |
|---|---|---|---|
| Python | 3.11 | 3.11 | 3.11 |
| RAM | 512 MB | 2 GB | 8 GB |
| Model storage | — | ~300 MB | ~3.3 GB |
| OS | Windows 10 / Ubuntu 20.04 / macOS 12 | same | same |
| GPU | Not required | Optional (CUDA 11.8+) | Optional (4 GB VRAM) |
| OCR engine | — | RapidOCR (ONNX, in `[documents]`) | RapidOCR (ONNX, in `[documents]`) |
| LibreOffice | — | — | Optional (for legacy `.doc`) |

---

## Known limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| OPF low recall with default parameters | Undetected PII | Use `--recall-mode balanced` or `aggressive` |
| Scanned PDFs: OCR quality depends on DPI | Unrecognized text | Scan at ≥ 200 DPI; audit log warns if DPI is low |
| DOCX reconstruction with complex styles | Formatting loss in rare cases | Falls back to `.txt` with warning in audit log |
| GLiNER is not L1: F1 ~81% vs ~96% OPF on EN benchmarks | False negatives on non-OPF categories | Complementary layer: covers categories absent from OPF |
| EML/MSG: attachments not processed recursively | PII in attachments undetected | Audit log warns; process attachments separately |
| DOCX track-changes: revisions accepted but not explicitly purged | Residual data in document | Use Word to "Accept all" before final export |
| Text in images embedded in DOCX/PPTX | Not analyzed in text pass | Docling extracts embedded images → OCR processing |
| Full hybrid stack (all 3 layers): ~5-6 GB RAM, ~2-3x slower | Not viable on limited hardware | `--low-memory` or `--layers pattern-only` |

---

## Project structure

```
src/privacy_anonymizer/
├── __init__.py              # Exports Anonymizer, LayerConfig, DetectionSpan, ProcessResult
├── anonymizer.py            # Main Anonymizer class + ProcessResult + BatchProcessResult
├── config.py                # LayerConfig, MaskingMode
├── models.py                # DetectionSpan
├── masking.py               # EntityMapper, MaskingPlan, build_masking_plan, mask_text
├── resolver.py              # resolve_spans — span merge and deduplication
├── compliance.py            # write_compliance_report — GDPR PDF
├── evaluation.py            # evaluate_dataset, write_synthetic_dataset
├── errors.py                # MissingOptionalDependencyError
├── cli.py                   # CLI entry point (argparse)
├── webui.py                 # Gradio Web UI
├── api.py                   # FastAPI REST API
├── mcp_server.py            # MCP stdio server
├── detectors/
│   ├── patterns_it.py       # Layer 3 — Italian patterns + checksum
│   ├── gliner_detector.py   # Layer 2 — GLiNER lazy loader
│   └── opf_detector.py      # Layer 1 — OPF lazy loader + Viterbi config
└── io/
    ├── registry.py          # Adapter registry + get_adapter()
    ├── base.py              # FileAdapter (ABC), FileContent, WriteResult
    ├── text_files.py        # .txt .md .log .csv
    ├── office.py            # .docx .xlsx .pptx
    ├── pdf.py               # .pdf (pypdf + PyMuPDF + ReportLab)
    ├── images.py            # .png .jpg .jpeg .tiff .bmp (Pillow + RapidOCR)
    ├── email_files.py       # .eml .msg
    ├── legacy.py            # .doc .xls .rtf
    ├── xml_files.py         # .xml (FatturaPA)
    └── docling_parser.py    # Optional Docling parser

tests/
├── test_anonymizer.py          # End-to-end Anonymizer tests
├── test_patterns_it.py         # Italian pattern + checksum tests
├── test_masking.py             # EntityMapper and MaskingPlan tests
├── test_office_adapters.py     # DOCX/XLSX/PPTX tests
├── test_document_adapters.py   # PDF/image/EML/legacy tests
├── test_gliner_detector.py     # GlinerDetector tests (mock)
├── test_opf_detector.py        # OpfDetector tests (mock)
├── test_docling_parser.py      # DoclingTextExtractor tests (mock)
├── test_image_redaction.py     # Image coordinate redaction tests (mock)
└── test_completion_features.py # CLI + evaluation + compliance + MCP tests
```
