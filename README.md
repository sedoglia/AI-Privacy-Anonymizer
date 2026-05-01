# AI Privacy Anonymizer

**Versione:** 0.1.0  
**Autore:** Sergio Dogliani  
**Licenza:** MIT  
**Python:** ≥ 3.11

Strumento Python locale per rilevare e mascherare automaticamente dati personali (PII) da documenti di vario formato prima di caricarli su chatbot AI (Claude, ChatGPT, Gemini, ecc.) senza rischi di data leakage. Tutto avviene localmente: **nessun dato lascia il dispositivo** durante l'anonimizzazione.

---

## Indice

- [Architettura ibrida a 3 livelli](#architettura-ibrida-a-3-livelli)
- [Categorie PII rilevate](#categorie-pii-rilevate)
- [Formati file supportati](#formati-file-supportati)
- [Modalità di mascheratura](#modalità-di-mascheratura)
- [Installazione](#installazione)
- [Utilizzo — CLI](#utilizzo--cli)
- [Utilizzo — Python API](#utilizzo--python-api)
- [Web UI locale (Gradio)](#web-ui-locale-gradio)
- [API REST locale (FastAPI)](#api-rest-locale-fastapi)
- [MCP Server stdio](#mcp-server-stdio)
- [Span Resolver e mapping consistente](#span-resolver-e-mapping-consistente)
- [Gestione metadati](#gestione-metadati)
- [Audit log JSON](#audit-log-json)
- [Report compliance GDPR (PDF)](#report-compliance-gdpr-pdf)
- [Dataset sintetico ed evaluation](#dataset-sintetico-ed-evaluation)
- [Entity vault per de-anonimizzazione](#entity-vault-per-de-anonimizzazione)
- [Requisiti di sistema](#requisiti-di-sistema)
- [Limitazioni note](#limitazioni-note)

---

## Architettura ibrida a 3 livelli

Il progetto adotta un'architettura ibrida che combina tre rilevatori complementari per massimizzare il recall (priorità rispetto alla precision nel caso d'uso pre-chatbot):

```
INPUT FILE
    │
    ▼
DOCLING (opzionale) ─── parser multi-formato con AI layout e OCR
    │
    ▼
TEXT SEGMENTER ─── divide in chunk rispettando i confini di frase
    │
    ├─────────────────────┬─────────────────────┐
    ▼                     ▼                     ▼
LAYER 1               LAYER 2               LAYER 3
OpenAI OPF            GLiNER                Presidio Pattern IT
8 categorie           60+ categorie         Regex + checksum
contesto semantico    italiano nativo       deterministico
    │                     │                     │
    └─────────────────────┴─────────────────────┘
                          │
                    SPAN RESOLVER
              (merge, deduplication, priorità)
                          │
                    MASKING ENGINE
                          │
                 FILE RECONSTRUCTOR
                          │
              OUTPUT FILE + AUDIT LOG JSON
```

### Layer 1 — OpenAI Privacy Filter (OPF)

- Modello basato su Transformer con finestra di contesto fino a 128K token
- Rileva 8 categorie semantiche: `private_person`, `private_email`, `private_phone`, `private_address`, `private_date`, `private_url`, `account_number`, `secret`
- Decoder Viterbi configurabile per alto recall:
  - `conservative`: parametri di default (alta precision)
  - `balanced`: `background_stay=-2.0`, `background_to_start=+1.5`, `span_continuation=+1.0`
  - `aggressive`: `background_stay=-3.0`, `background_to_start=+2.0`, `span_continuation=+1.5`
- Unico layer con categoria nativa `SECRET` per password, API key, token JWT, valori `.env`
- Installazione esterna richiesta (vedi sezione Installazione)

### Layer 2 — GLiNER `gliner_multi_pii-v1`

- Modello zero-shot fine-tuned su italiano per riconoscimento entità named
- Oltre 60 categorie PII comprese quelle assenti in OPF: `passport_number`, `driver_license`, `health_insurance_id`, `medical_condition`, `credit_card_number`, `cvv`, `blood_type`, `username`, `digital_signature`, `organization`
- Threshold configurabile (default: 0.5) per bilanciare recall e precision
- Download automatico del modello (~300 MB) al primo utilizzo
- Licenza Apache 2.0; installazione via extra `[ml]`

### Layer 3 — Pattern Recognizer italiani (deterministico)

Regex con validazione checksum dove applicabile. Attivo per default senza dipendenze extra.

| Entità | Validazione | Esempio |
|---|---|---|
| `CODICE_FISCALE` | ✅ Checksum controllo carattere Luhn-like | `RSSMRA80A01L219M` |
| `PARTITA_IVA` | ✅ Algoritmo mod-11 | `01114601006` |
| `IBAN_IT` | ✅ Algoritmo IBAN ISO 7064 mod-97-10 | `IT60X0542811101000000123456` |
| `TARGA_IT` | Pattern (auto + moto) | `AB123CD` |
| `CARTA_IDENTITA` | Pattern (`AA1234567` o `CA1234567AB`) | `AX1234567` |
| `CELL_IT` | Pattern (prefisso 3xx, opz. +39/0039) | `3401234567` |
| `TEL_IT` | Pattern fisso (prefisso 0, opz. +39/0039) | `011 1234567` |
| `EMAIL` | Pattern RFC-like | `mario@esempio.it` |
| `PEC` | Pattern email + domini `.pec.` o `.pec.it` | `studio@legalmail.pec.it` |
| `TESSERA_SANITARIA` | Pattern 20 cifre con prefisso `80` | `80380030001234567890` |
| `MATRICOLA_INPS` | Pattern 8-9 cifre con parola chiave di contesto | `12345678` (dopo "matricola INPS") |
| `IP_ADDRESS` | Pattern IPv4 con validazione ottetti 0-255 | `192.168.1.10` |

---

## Categorie PII rilevate

L'insieme completo delle categorie emesse verso il masking engine, dopo normalizzazione dei label dei tre layer:

| Categoria normalizzata | Sorgente principale | Note |
|---|---|---|
| `PERSONA` | OPF + GLiNER | Nomi propri con context-awareness |
| `EMAIL` | L3 + OPF | Mailbox standard |
| `PEC` | L3 | Posta Elettronica Certificata |
| `TELEFONO` / `CELL_IT` / `TEL_IT` | L3 + OPF | Numeri IT e internazionali |
| `INDIRIZZO` | OPF + GLiNER | Indirizzi stradali |
| `DATA_PRIVATA` | OPF + GLiNER | Date di nascita e date private |
| `URL` | OPF + GLiNER | URL con path personale |
| `ACCOUNT_NUMBER` | OPF | Numero conto corrente generico |
| `SECRET` | OPF | Password, API key, token, segreti |
| `CODICE_FISCALE` | L3 + GLiNER | Con validazione checksum |
| `PARTITA_IVA` | L3 | Con validazione mod-11 |
| `IBAN_IT` | L3 + GLiNER | Con validazione ISO |
| `TARGA_IT` | L3 | Targhe autoveicoli |
| `CARTA_IDENTITA` | L3 | CIE e documenti identità |
| `TESSERA_SANITARIA` | L3 + GLiNER | Tessera sanitaria e TEAM |
| `MATRICOLA_INPS` | L3 | Con context words |
| `IP_ADDRESS` | L3 + GLiNER | Indirizzi IPv4 validi |
| `USERNAME` | GLiNER | Handle e nomi utente |
| `PASSAPORTO` | GLiNER | Numero passaporto |
| `PATENTE` | GLiNER | Patente di guida |
| `CARTA_CREDITO` | GLiNER | Numero carta di credito |
| `CONDIZIONE_MEDICA` | GLiNER | Diagnosi e condizioni cliniche |
| `ORGANIZZAZIONE` | GLiNER | Nome azienda privata in contesto |
| `TAX_ID` | GLiNER | Identificativo fiscale generico |

---

## Formati file supportati

### Round-trip completo (stesso formato in input e output)

| Formato | Estensioni | Parsing | Ricostruzione | Note |
|---|---|---|---|---|
| Testo puro | `.txt` `.md` `.log` `.csv` | built-in | built-in | Lettura/scrittura UTF-8 diretta |
| Word | `.docx` | `python-docx` | `python-docx` | Paragrafi + intestazioni + piè di pagina + tabelle + commenti |
| Excel | `.xlsx` | `openpyxl` | `openpyxl` | Celle (stringhe) + nomi foglio + commenti autore |
| PowerPoint | `.pptx` | `python-pptx` | `python-pptx` | Testo shape + note relatore |
| PDF selezionabile | `.pdf` | `pypdf` | PyMuPDF overlay | Redazione a coordinate sui bounding box originali |
| Immagini | `.png` `.jpg` `.jpeg` `.tiff` `.bmp` | Tesseract OCR | Pillow | Redazione a coordinate OCR; fallback a immagine testo plano |
| Email | `.eml` | stdlib `email` | stdlib `email` | From/To/Cc/Subject + body |
| XML/FatturaPA | `.xml` | `xml.etree` | `xml.etree` | Testo e attributi; struttura XML preservata |
| RTF | `.rtf` | `striprtf` | built-in minimal | Ricostruzione RTF semplificata |

### Solo lettura (output `.txt` anonimizzato)

| Formato | Estensioni | Dipendenza |
|---|---|---|
| Outlook MSG | `.msg` | `extract-msg` (extra `documents`) |
| Word legacy | `.doc` | best-effort binary (suggerito LibreOffice) |
| Excel legacy | `.xls` | `xlrd` (extra `documents`) |

### Parser Docling (opzionale)

Attivabile con `--parser docling`. Docling (IBM, MIT license) aggiunge:
- Parsing avanzato layout PDF con modello AI DocLayNet
- OCR integrato per PDF scansionati e immagini
- Riconoscimento tabelle con TableFormer
- Support multi-formato unificato (PDF, DOCX, XLSX, PPTX, HTML, immagini)

Richiede extra `[docling]` (`pip install -e .[docling]`). I modelli vengono scaricati automaticamente al primo utilizzo.

---

## Modalità di mascheratura

| Modalità | Output esempio | Caso d'uso |
|---|---|---|
| `replace` *(default)* | `[CF_1]`, `[EMAIL_2]`, `[PERSONA_1]` | Upload chatbot — contesto leggibile |
| `redact` | `████████████████` | Documenti da condividere con terzi |
| `generalize` | `[CF]`, `[EMAIL]`, `[PERSONA]` | Quando la numerazione progressiva è superflua |
| `hash` | `[SHA256:a3f2c1d4e5f6]` | Pipeline tecniche con eventuale de-anonimizzazione |

Tutte le modalità supportano il **consistent mapping**: la stessa entità riceve lo stesso placeholder in tutto il documento (es. ogni occorrenza di "Mario Rossi", incluse varianti parziali, diventa sempre `[PERSONA_1]`).

---

## Installazione

### Base (solo Layer 3 — pattern italiani, nessun ML)

```bash
pip install ai-privacy-anonymizer
```

### Con supporto Office (DOCX, XLSX, PPTX)

```bash
pip install "ai-privacy-anonymizer[office]"
```

### Con supporto documenti (PDF, immagini OCR, EML, MSG, XLS, RTF)

```bash
pip install "ai-privacy-anonymizer[documents]"
```

### Con Layer 2 GLiNER

```bash
pip install "ai-privacy-anonymizer[ml]"
```

### Con parser Docling

```bash
pip install "ai-privacy-anonymizer[docling]"
```

### Con Web UI Gradio

```bash
pip install "ai-privacy-anonymizer[webui]"
```

### Con API REST FastAPI

```bash
pip install "ai-privacy-anonymizer[api]"
```

### Tutto insieme

```bash
pip install "ai-privacy-anonymizer[all]"
```

### Sviluppo locale

```bash
git clone https://github.com/sedoglia/AI-Privacy-Anonymizer.git
cd AI-Privacy-Anonymizer
pip install -e ".[dev,office,documents,ml]"
pytest
```

### Layer 1 OPF (installazione esterna)

```bash
pip install git+https://github.com/openai/privacy-filter
```

Richiede ~3 GB di spazio per il download del modello al primo avvio.

### Modello spaCy italiano (opzionale, per Presidio)

```bash
python -m spacy download it_core_news_lg
```

### Verifica setup

```bash
privacy-anonymizer --setup
```

---

## Utilizzo — CLI

### Anonimizzare un singolo file

```bash
privacy-anonymizer documento.docx
```

Output: `documento_anonymized.docx` nella stessa cartella, più `documento_anonymized.docx.audit.json`.

### Specificare file o cartella di output

```bash
privacy-anonymizer documento.docx --output /percorso/output/
privacy-anonymizer documento.docx --output documento_clean.docx
```

### Anonimizzare una cartella intera

```bash
privacy-anonymizer ./documenti/ --output ./documenti_clean/
# Con ricorsione disabilitata
privacy-anonymizer ./documenti/ --output ./out/ --no-recursive
```

### Testo diretto da riga di comando

```bash
privacy-anonymizer --text "Mario Rossi, CF RSSMRA80A01L219M, tel 3401234567"
```

### Modalità di mascheratura

```bash
privacy-anonymizer report.pdf --mode redact
privacy-anonymizer contratto.docx --mode generalize
privacy-anonymizer dati.xlsx --mode hash
```

### Attivare lo stack ibrido (L1 + L2 + L3)

```bash
# Tutti i layer
privacy-anonymizer file.txt --layers hybrid

# Solo GLiNER + pattern (senza OPF)
privacy-anonymizer file.txt --layers hybrid --disable-layer opf

# Solo OPF + pattern (senza GLiNER)
privacy-anonymizer file.txt --layers hybrid --disable-layer gliner

# Solo pattern italiani (default, più veloce)
privacy-anonymizer file.txt --layers pattern-only
```

### Configurazione recall OPF

```bash
# Modalità conservative (alta precision, meno recall)
privacy-anonymizer file.txt --layers hybrid --recall-mode conservative

# Modalità balanced (default — bilanciato per uso chatbot)
privacy-anonymizer file.txt --layers hybrid --recall-mode balanced

# Modalità aggressive (massimo recall)
privacy-anonymizer file.txt --layers hybrid --recall-mode aggressive
```

### Parser Docling

```bash
privacy-anonymizer documento.pdf --parser docling
```

### Dry-run (analisi senza scrivere output)

```bash
privacy-anonymizer contratto.docx --dry-run
```

Mostra span rilevati, categorie e conteggi senza produrre file.

### Mappa entità (categorie e placeholder, senza valori originali)

```bash
privacy-anonymizer contratto.docx --show-map
```

Esempio output:
```
Mappa entità (categorie e placeholder, nessun valore originale):
  [CF_1]       ←  CODICE_FISCALE
  [EMAIL_1]    ←  EMAIL
  [PERSONA_1]  ←  PERSONA
  [PIVA_1]     ←  PARTITA_IVA
```

### Report compliance GDPR (PDF)

```bash
privacy-anonymizer documento.docx --compliance-report report_gdpr.pdf
```

### Output audit in JSON

```bash
privacy-anonymizer documento.docx --json
```

### Export entity vault (per de-anonimizzazione in modalità hash)

```bash
privacy-anonymizer documento.txt --mode hash --export-vault vault.json
```

`vault.json` contiene il mapping `placeholder → {label, originale}`. **Conservare in modo sicuro.**

### Metadata

```bash
# Disabilita la rimozione metadati
privacy-anonymizer documento.docx --keep-metadata
```

### Performance e memoria

```bash
# Elaborazione low-memory (layer in sequenza, libera RAM tra uno e l'altro)
privacy-anonymizer file.txt --layers hybrid --low-memory

# Forza CPU (disabilita GPU anche se disponibile)
privacy-anonymizer file.txt --device cpu
```

### Manutenzione

```bash
# Cancella cache locale di modelli/parser
privacy-anonymizer --wipe-cache

# Mostra formati supportati
privacy-anonymizer --supported-formats

# Verifica setup e dipendenze
privacy-anonymizer --setup
privacy-anonymizer --download-models --verbose
```

### Dataset sintetico e valutazione

```bash
# Genera dataset sintetico JSONL
privacy-anonymizer --generate-synthetic-dataset ./synthetic.jsonl

# Valuta un dataset JSONL con campi "text" e "labels"
privacy-anonymizer --evaluate ./synthetic.jsonl
```

---

## Utilizzo — Python API

```python
from privacy_anonymizer import Anonymizer, LayerConfig

# Configurazione personalizzata
config = LayerConfig(
    parser="built-in",             # "built-in" | "docling"
    opf_enabled=False,             # richiede installazione OPF esterna
    opf_recall_mode="balanced",    # "conservative" | "balanced" | "aggressive"
    gliner_enabled=True,           # richiede extra [ml]
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

# ── Testo diretto ──────────────────────────────────────────────
masked_text, counts = anon.process_text(
    "Mario Rossi, CF RSSMRA80A01L219M, tel 3401234567",
    language="it",
)
# masked_text → "Mario Rossi, [CF_1], [TEL_1]"
# counts → {"CODICE_FISCALE": 1, "CELL_IT": 1}

# Oppure con accesso completo al risultato
result = anon.analyze_text("Mario Rossi, mario@example.com")
print(result.anonymized_text)
print(result.audit_report)
# Entity vault (solo se mode=hash)
vault = result.replacements and [r.__dict__ for r in result.replacements]

# ── Singolo file ───────────────────────────────────────────────
result = anon.process_file("input.docx")
result.save("output.docx")
print(result.audit_report)

# Con output_path esplicito
result = anon.process_file("input.pdf", output_path="clean/output.pdf")

# Dry-run
result = anon.process_file("input.xlsx", dry_run=True)

# ── Batch su cartella ──────────────────────────────────────────
batch = anon.process_folder("./docs_in/", output_dir="./docs_out/")
print(f"Processati: {batch.processed_count}")
print(f"Saltati: {batch.skipped_count}")
for path, reason in batch.skipped:
    print(f"  SKIP {path}: {reason}")

# ── Rilevamento span senza mascheratura ────────────────────────
spans = anon.detect_text("Mario Rossi, IBAN IT60X0542811101000000123456")
for span in spans:
    print(span.start, span.end, span.label, span.source, span.score)

# ── MaskingPlan con entity vault ───────────────────────────────
from privacy_anonymizer.masking import build_masking_plan
plan = build_masking_plan(text, spans, mode="hash")
vault = plan.entity_vault()  # {placeholder: {label, original}}
```

### Modello dati: DetectionSpan

```python
@dataclass
class DetectionSpan:
    start: int           # offset carattere inizio (inclusivo)
    end: int             # offset carattere fine (esclusivo)
    label: str           # categoria normalizzata (es. "CODICE_FISCALE")
    source: str          # "pattern" | "opf" | "gliner"
    score: float         # confidenza (1.0 per pattern deterministico)
    metadata: dict       # {"checksum_valid": "true"/"false"} per CF
```

---

## Web UI locale (Gradio)

```bash
privacy-anonymizer --webui
# oppure
privacy-anonymizer-web
```

Apre `http://127.0.0.1:7860` con:
- **Tab Testo**: input testuale libero, selezione modalità, checkbox GLiNER, output + audit JSON
- **Tab File**: drag & drop file, stesse opzioni, download file anonimizzato

Non richiede connessione Internet durante l'uso. Richiede `pip install -e .[webui]`.

---

## API REST locale (FastAPI)

```bash
privacy-anonymizer --api
# oppure
privacy-anonymizer-api
```

Avvia il server su `http://127.0.0.1:8000`. Richiede `pip install -e .[api]`.

### Endpoint disponibili

| Metodo | Path | Descrizione |
|---|---|---|
| `GET` | `/health` | Healthcheck — restituisce `{"status": "ok"}` |
| `POST` | `/anonymize/text` | Anonimizza testo (form: `text`, `mode`, `hybrid`) |
| `POST` | `/anonymize/file` | Anonimizza file (multipart: `file`, `mode`, `hybrid`) |

### Esempio con curl

```bash
# Testo
curl -X POST http://127.0.0.1:8000/anonymize/text \
  -F "text=Mario Rossi, CF RSSMRA80A01L219M" \
  -F "mode=replace"

# File
curl -X POST http://127.0.0.1:8000/anonymize/file \
  -F "file=@documento.docx" \
  -F "mode=redact" \
  --output documento_redacted.docx
```

Documentazione interattiva Swagger disponibile su `http://127.0.0.1:8000/docs`.

---

## MCP Server stdio

Integrazione come strumento MCP (Model Context Protocol) per Claude Desktop e altri client compatibili.

```bash
privacy-anonymizer-mcp
```

Il server legge richieste JSON-RPC da stdin e scrive risposte su stdout (protocollo MCP 2024-11-05).

### Tool esposto: `anonymize_text`

```json
{
  "method": "tools/call",
  "params": {
    "name": "anonymize_text",
    "arguments": { "text": "Mario Rossi, mario@example.com" }
  }
}
```

Configurazione in `claude_desktop_config.json`:
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

## Span Resolver e mapping consistente

Il resolver gestisce la fusione degli span prodotti dai tre layer con le seguenti regole:

### Priorità sorgente

```
Layer 3 (pattern deterministico) > Layer 1 (OPF) > Layer 2 (GLiNER)
```

Quando due span si sovrappongono esattamente, vince quello con priorità maggiore.

### Casi di fusione

- **Span identici**: deduplicati, mantiene quello a priorità maggiore
- **Span annidati / sovrapposti**: vince lo span più ampio (es. `[Mario]` + `[Mario Rossi]` → `[Mario Rossi]`)
- **Span adiacenti compatibili** (gap ≤ 3 caratteri): fusi in un unico span della stessa categoria semantica
- **Conflitto di tipo**: se L3 valida il checksum, vince L3; altrimenti vince il layer a priorità maggiore

### Consistent entity mapping

```
"Mario Rossi"      → [PERSONA_1]   (tutte le occorrenze, incluse varianti parziali)
"mario@azienda.it" → [EMAIL_1]
"RSSMRA80A01L219M" → [CF_1]
```

La normalizzazione delle varianti (case-insensitive, whitespace collassato) garantisce che la stessa entità riceva sempre lo stesso placeholder nel documento. La mappa è mantenuta **solo in RAM** durante l'esecuzione e mai scritta su disco, salvo uso esplicito di `--export-vault`.

---

## Gestione metadati

I metadati dei file Office e PDF vengono rimossi per default (disattivabile con `--keep-metadata`):

| Campo | Formato | Azione |
|---|---|---|
| Autore (`Author`) | DOCX, XLSX, PPTX, PDF | Sostituito con `"Anonimo"` |
| `LastModifiedBy` | DOCX, XLSX, PPTX | Sostituito con `"Anonimo"` |
| Organizzazione (`Company`) | XLSX | Rimosso |
| Titolo, Oggetto, Parole chiave | DOCX, XLSX, PPTX | Svuotati |
| Commenti documento | DOCX, XLSX, PPTX | Azzerati (autore sostituito) |
| Metadati XMP / Info dict | PDF | Rimossi via PyMuPDF |
| EXIF / XMP | JPEG, TIFF, PNG | Strip completo (immagine ricostruita) |
| Autore commento cella | XLSX | Sostituito con `"Anonimo"` |

---

## Audit log JSON

Ogni elaborazione produce un file `.audit.json` nella stessa posizione del file output. Il log non contiene mai i valori PII originali, solo categorie e conteggi.

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

## Report compliance GDPR (PDF)

```bash
privacy-anonymizer documento.docx --compliance-report report_gdpr.pdf
```

Genera un PDF (via ReportLab) con:
- Riferimenti file sorgente e output
- Timestamp di elaborazione
- Layer utilizzati e recall mode
- Elenco categorie PII rilevate con conteggi
- Flag metadati rimossi
- Warnings di elaborazione
- Estratto dell'audit JSON (troncato a 1500 caratteri)

Richiede `pip install -e .[documents]` (ReportLab).

---

## Dataset sintetico ed evaluation

### Generare un dataset sintetico

```bash
privacy-anonymizer --generate-synthetic-dataset ./synthetic.jsonl
```

Ogni riga è un oggetto JSON con campi `text` (testo di test) e `labels` (lista di categorie attese):

```jsonl
{"text": "Mario Rossi CF RSSMRA80A01L219M email mario.rossi@example.com tel 3401234567", "labels": ["CODICE_FISCALE", "EMAIL", "TELEFONO_IT"]}
{"text": "P.IVA 01114601006 IBAN IT60X0542811101000000123456 targa AB123CD", "labels": ["PARTITA_IVA", "IBAN_IT", "TARGA_IT"]}
{"text": "Server 192.168.1.10, PEC studio.rossi@legalmail.pec.it", "labels": ["IP_ADDRESS", "PEC"]}
```

### Valutare un dataset

```bash
privacy-anonymizer --evaluate ./synthetic.jsonl
```

Output JSON con metriche:

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

### Da Python

```python
from privacy_anonymizer.evaluation import evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer import Anonymizer, LayerConfig

write_synthetic_dataset("./my_dataset.jsonl")

anon = Anonymizer(LayerConfig(gliner_enabled=True))
metrics = evaluate_dataset("./my_dataset.jsonl", anonymizer=anon)
print(f"F1: {metrics.f1:.2%}")
```

---

## Entity vault per de-anonimizzazione

In modalità `hash`, ogni valore PII viene sostituito con `[SHA256:xxxxxxxx]`. Per mantenere la possibilità di de-anonimizzazione, usare `--export-vault`:

```bash
privacy-anonymizer documento.txt --mode hash --export-vault vault.json
```

`vault.json` esempio:

```json
{
  "[SHA256:a3f2c1d4e5f6]": {
    "label": "CODICE_FISCALE",
    "original": "RSSMRA80A01L219M"
  },
  "[SHA256:9b1c3e7f2a4d]": {
    "label": "EMAIL",
    "original": "mario@azienda.it"
  }
}
```

> **Nota di sicurezza:** il vault contiene i valori originali in chiaro. Conservarlo su storage cifrato, separato dal documento anonimizzato, e cancellarlo quando non più necessario.

Da Python:

```python
from privacy_anonymizer.masking import build_masking_plan
plan = build_masking_plan(text, spans, mode="hash")
vault = plan.entity_vault()  # dict {placeholder: {label, original}}
```

---

## Requisiti di sistema

| Requisito | Minimo (solo L3) | Con L2 GLiNER | Con L1 OPF |
|---|---|---|---|
| Python | 3.11 | 3.11 | 3.11 |
| RAM | 512 MB | 2 GB | 8 GB |
| Storage modelli | — | ~300 MB | ~3.3 GB |
| OS | Windows 10 / Ubuntu 20.04 / macOS 12 | stesso | stesso |
| GPU | Non necessaria | Opzionale (CUDA 11.8+) | Opzionale (4 GB VRAM) |
| Tesseract OCR | — | — | v4.0+ (per immagini) |
| LibreOffice | — | — | Opzionale (per `.doc` legacy) |

---

## Limitazioni note

| Limitazione | Impatto | Mitigazione |
|---|---|---|
| OPF recall basso con parametri default | PII non rilevate | Usa `--recall-mode balanced` o `aggressive` |
| PDF scansionati: qualità OCR dipendente da DPI | Testo non riconosciuto | Scansionare a ≥ 200 DPI; audit log avvisa se DPI basso |
| Ricostruzione DOCX con stili complessi | Perdita formattazione in rari casi | Fallback a `.txt` con warning in audit log |
| GLiNER non è L1: F1 ~81% vs ~96% OPF su benchmark EN | Falsi negativi su categorie non-OPF | Layer complementare: copre categorie assenti in OPF |
| EML/MSG: allegati non processati ricorsivamente | PII negli allegati non rilevate | Audit log avvisa; processare gli allegati separatamente |
| DOCX track-changes: revisioni accettate ma non cancellate esplicitamente | Dati residui nel documento | Usare Word per "Accetta tutto" prima dell'export finale |
| Testo in immagini incorporate in DOCX/PPTX | Non analizzato nel passaggio testo | Docling estrae le immagini embedded → elaborazione OCR |
| Stack ibrido (tutti e 3 i layer): ~5-6 GB RAM, ~2-3x più lento | Impraticabile su hardware limitato | `--low-memory` o `--layers pattern-only` |

---

## Struttura del progetto

```
src/privacy_anonymizer/
├── __init__.py              # Esporta Anonymizer, LayerConfig, DetectionSpan, ProcessResult
├── anonymizer.py            # Classe principale Anonymizer + ProcessResult + BatchProcessResult
├── config.py                # LayerConfig, MaskingMode
├── models.py                # DetectionSpan
├── masking.py               # EntityMapper, MaskingPlan, build_masking_plan, mask_text
├── resolver.py              # resolve_spans — merge e deduplication span
├── compliance.py            # write_compliance_report — PDF GDPR
├── evaluation.py            # evaluate_dataset, write_synthetic_dataset
├── errors.py                # MissingOptionalDependencyError
├── cli.py                   # Entry point CLI (argparse)
├── webui.py                 # Web UI Gradio
├── api.py                   # API REST FastAPI
├── mcp_server.py            # MCP stdio server
├── detectors/
│   ├── patterns_it.py       # Layer 3 — pattern italiani + checksum
│   ├── gliner_detector.py   # Layer 2 — GLiNER lazy loader
│   └── opf_detector.py      # Layer 1 — OPF lazy loader + Viterbi config
└── io/
    ├── registry.py          # Registro adapter + get_adapter()
    ├── base.py              # FileAdapter (ABC), FileContent, WriteResult
    ├── text_files.py        # .txt .md .log .csv
    ├── office.py            # .docx .xlsx .pptx
    ├── pdf.py               # .pdf (pypdf + PyMuPDF + ReportLab)
    ├── images.py            # .png .jpg .jpeg .tiff .bmp (Pillow + Tesseract)
    ├── email_files.py       # .eml .msg
    ├── legacy.py            # .doc .xls .rtf
    ├── xml_files.py         # .xml (FatturaPA)
    └── docling_parser.py    # Parser Docling opzionale

tests/
├── test_anonymizer.py          # Test Anonymizer end-to-end
├── test_patterns_it.py         # Test pattern + checksum italiani
├── test_masking.py             # Test EntityMapper e MaskingPlan
├── test_office_adapters.py     # Test DOCX/XLSX/PPTX
├── test_document_adapters.py   # Test PDF/immagini/EML/legacy
├── test_gliner_detector.py     # Test GlinerDetector (mock)
├── test_opf_detector.py        # Test OpfDetector (mock)
├── test_docling_parser.py      # Test DoclingTextExtractor (mock)
├── test_image_redaction.py     # Test redazione coordinate immagini (mock)
└── test_completion_features.py # Test CLI + evaluation + compliance + MCP
```
