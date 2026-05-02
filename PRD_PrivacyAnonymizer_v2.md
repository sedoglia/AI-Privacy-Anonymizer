# PRD — AI Privacy Anonymizer
**Product Requirements Document**
**Versione:** 2.0 — Architettura Ibrida Massima Accuratezza
**Data:** 2026-04-30
**Autore:** Sergio Dogliani
**Sostituisce:** v1.0 (motore singolo OpenAI Privacy Filter)

---

## Changelog v1.0 → v2.0

| Area | v1.0 | v2.0 |
|---|---|---|
| Motore PII | OpenAI Privacy Filter (singolo) | Stack ibrido a 3 livelli (OPF + GLiNER + Presidio) |
| Parser documenti | Da costruire ex-novo | Docling (IBM, MIT) come layer di parsing |
| Supporto italiano | Regex custom | GLiNER `gliner_multi_pii-v1` fine-tuned su IT + PatternRecognizer italiani |
| Recall default | Basso (OPF conservativo) | Ottimizzato per massimo recall con controllo false positive |
| Taxonomy | 8 categorie fisse | 8 OPF + 60+ GLiNER + N custom IT illimitati |
| CF / P.IVA / Targa | Assenti | Coperti con validazione checksum |

---

## 1. Sommario Esecutivo

**AI Privacy Anonymizer** è uno strumento Python CLI (con opzionale interfaccia web locale) che consente di caricare file di vario formato contenenti dati personali, rilevare e mascherare automaticamente le PII (Personally Identifiable Information), e produrre in output un file anonimizzato con la stessa estensione dell'originale, pronto per essere caricato su chatbot AI (Claude, ChatGPT, Gemini, ecc.) senza rischi di data leakage.

L'obiettivo primario della v2.0 è **massimizzare l'accuratezza di rilevamento** attraverso un'architettura ibrida a tre livelli complementari che si compensano reciprocamente nei rispettivi punti deboli:

- **Livello 1 — OpenAI Privacy Filter (OPF):** contesto lungo (128K token), eccellente per nomi ambigui, segreti, API key, riferimenti impliciti. Finestra semantica superiore ma taxonomy fisso a 8 categorie.
- **Livello 2 — GLiNER `gliner_multi_pii-v1`:** fine-tuned su italiano, 60+ categorie PII, zero-shot su entità nuove. Copre le lacune della taxonomy OPF.
- **Livello 3 — Presidio PatternRecognizer:** pattern regex italiani con validazione checksum per Codice Fiscale, Partita IVA, targa, IBAN, CI. Precisione 100% sugli identificatori strutturati.
- **Docling (IBM):** parsing multi-formato (PDF, Office, immagini, HTML) con AI per layout e OCR. Elimina il bisogno di costruire il layer di estrazione testo.

---

## 2. Motivazione dell'Architettura Ibrida

### 2.1 Perché nessun singolo motore è sufficiente

La ricerca pre-implementazione ha evidenziato che ogni motore disponibile ha punti ciechi sistematici che rendono un approccio singolo inadeguato per l'uso in produzione con testi italiani:

| Problema | OPF standalone | GLiNER standalone | Presidio standalone |
|---|---|---|---|
| Recall default basso | ❌ 10–38% su testi reali | ✅ Buono | ✅ Per pattern |
| Nomi italiani ambigui | ✅ Context-aware | ✅ Fine-tuned IT | ❌ Dipende dal modello spaCy |
| Codice Fiscale | ❌ Non nella taxonomy | ⚠️ Parziale | ✅ Con custom recognizer |
| Segreti / API key | ✅ Categoria nativa | ❌ Non specifico | ⚠️ Richiede custom |
| Parsing DOCX/PDF/OCR | ❌ Solo testo grezzo | ❌ Solo testo grezzo | ❌ Solo testo grezzo |
| Taxonomy estendibile | ❌ Fisso 8 categorie | ✅ Zero-shot | ✅ Illimitato |

### 2.2 Come i livelli si compensano

```
TESTO IN INPUT
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  LIVELLO 1: OpenAI Privacy Filter                       │
│  → Rileva: nomi in contesto, segreti, date private,     │
│    indirizzi, email, telefoni, URL, account number      │
│  → Forza: contesto semantico lungo, anti-ambiguità      │
│  → Debolezza: taxonomy fisso, recall basso per default  │
└────────────────────────┬────────────────────────────────┘
                         │  (span già trovati)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  LIVELLO 2: GLiNER gliner_multi_pii-v1                  │
│  → Rileva: entità non coperte da OPF (60+ categorie),   │
│    nomi italiani specifici, titoli, ruoli, ecc.         │
│  → Forza: italiano nativo, zero-shot, scalabile         │
│  → Debolezza: F1 81% vs 96% OPF su benchmark EN         │
└────────────────────────┬────────────────────────────────┘
                         │  (span aggiuntivi)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  LIVELLO 3: Presidio PatternRecognizer (IT)             │
│  → Rileva: Codice Fiscale (+ checksum), P.IVA,          │
│    targa veicolo, carta d'identità, IBAN IT,            │
│    telefoni italiani, tessera sanitaria                  │
│  → Forza: precisione 100% su identificatori strutturati │
│  → Debolezza: solo pattern regolari, non semantico      │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
              UNION RESOLVER + DEDUPLICATION
              (merge span sovrapposti, risolve conflitti)
                         │
                         ▼
                   SPAN FINALI PII
```

### 2.3 Tuning del recall di OPF

OPF di default è calibrato per alta precisione (pochi falsi positivi), il che lo rende conservativo. Per il nostro caso d'uso (pre-upload a chatbot AI) il **recall è più critico della precision**: meglio mascherare qualcosa in più che perdere dati sensibili.

Il decoder Viterbi di OPF sarà configurato con parametri ottimizzati per alto recall:

```python
# Configurazione high-recall per uso pre-chatbot
OPF_VITERBI_CONFIG = {
    "background_stay": -2.0,      # default: 0.0 — penalizza lo stare fuori dagli span
    "background_to_start": +1.5,  # default: 0.0 — favorisce l'entrata negli span
    "span_continuation": +1.0,    # default: 0.0 — favorisce continuazione span
}
```

---

## 3. Obiettivi del Prodotto

| Obiettivo | Metrica di successo |
|---|---|
| Massimizzare rilevamento PII | F1 score ≥ 95% su dataset test italiano (nomi IT, CF, P.IVA inclusi) |
| Zero falsi negativi su identificatori strutturati | Recall 100% su CF, P.IVA, IBAN, targa (pattern deterministici) |
| Preservare estensione e struttura del file originale | 100% dei file output apribili correttamente nelle rispettive applicazioni |
| Supportare ≥ 8 formati file enterprise | Copertura formati definiti in sezione 5 |
| Esecuzione completamente locale (offline dopo setup) | Zero traffico di rete durante la fase di anonimizzazione |
| Installazione < 15 min su Windows 10+/Ubuntu 20.04+ | Setup documentato e testato su entrambe le piattaforme |
| Performance accettabile su CPU | File da 50 pagine processato in < 90 secondi su CPU |

---

## 4. Utenti Target

- **Tecnici IT / Support Engineer** in ambito enterprise italiano (es. supporto PROFIS, ESOLVER, JOB) che condividono log, query SQL, report e configurazioni con AI per troubleshooting — spesso contenenti dati di dipendenti o clienti
- **Professionisti di studio** (commercialisti, avvocati, HR) che analizzano documenti con dati anagrafici tramite AI
- **Sviluppatori** che sanitizzano dataset prima di invocare API AI esterne nei loro workflow
- **Pubblica Amministrazione** che deve rispettare GDPR e Codice Privacy italiano (D.Lgs. 196/2003 e s.m.i.) prima di usare sistemi AI esterni
- **Utenti finali non tecnici** che caricano documenti personali su chatbot per assistenza

---

## 5. Formati File Supportati

### 5.1 Formati con round-trip completo (parsing + ricostruzione nel formato originale)

| Categoria | Estensioni | Layer parsing | Layer ricostruzione | Note |
|---|---|---|---|---|
| Documenti Word | `.docx` | Docling | `python-docx` | Testo + intestazioni + piè di pagina + commenti + tabelle |
| Fogli Excel | `.xlsx`, `.csv` | Docling | `openpyxl` / built-in | Contenuto celle + nomi fogli + commenti + formule (preserve) |
| Presentazioni | `.pptx` | Docling | `python-pptx` | Testo slide + note relatore + caselle testo |
| PDF (testo selezionabile) | `.pdf` | Docling (DocLayNet AI) | `reportlab` + overlay | Testo layer + tabelle riconosciute da TableFormer |
| Immagini raster (testo) | `.png`, `.jpg`, `.jpeg`, `.tiff`, `.bmp` | Docling (OCR) | `Pillow` (bounding-box redact) | OCR + ridisegno rettangoli neri su span PII |
| Testo puro | `.txt`, `.log`, `.md`, `.csv` | built-in | built-in | Lettura/scrittura diretta |
| Email | `.eml` | `mail-parser` | `email` stdlib | Header + body + allegati ricorsivi |

### 5.2 Formati con output .txt anonimizzato (solo lettura)

- `.doc` (legacy Word 97–2003) — conversione via `python-docx` o `libreoffice --headless`
- `.xls` (legacy Excel) — conversione via `xlrd`
- `.msg` (Outlook) — `extract-msg` per body + allegati
- `.rtf` — `striprtf` per estrazione testo
- PDF scansionati senza layer testo — OCR Docling, output PNG con redaction box

---

## 6. Categorie PII Rilevate — Stack Ibrido Completo

### 6.1 Livello 1: OpenAI Privacy Filter (8 categorie, alta context-awareness)

| Categoria OPF | Esempi | Forza del rilevamento |
|---|---|---|
| `private_person` | Mario Rossi, Dott. Bianchi, "il mio collega" | ✅✅ Context-aware, anti-ambiguità |
| `private_email` | mario@azienda.it | ✅✅ |
| `private_phone` | +39 011 1234567 | ✅✅ |
| `private_address` | Via Roma 12, 10138 Torino | ✅✅ |
| `private_date` | 01/01/1980, nata il 3 marzo 1990 | ✅✅ |
| `private_url` | https://user.domain.com/private | ✅✅ |
| `account_number` | IBAN IT60X..., n. conto 123456 | ✅ |
| `secret` | password, API key, token JWT, `.env` values | ✅✅ Unico con categoria nativa |

### 6.2 Livello 2: GLiNER `gliner_multi_pii-v1` (60+ categorie, italiano nativo)

Categorie aggiuntive rispetto a OPF più rilevanti per contesto italiano:

| Categoria GLiNER | Esempi | Note |
|---|---|---|
| `tax_id` / `social_security_number` | Codice Fiscale (fallback se regex fallisce) | Backup al livello 3 |
| `driver_license` | Patente di guida B123456IT | |
| `passport_number` | AA1234567 | |
| `health_insurance_id` | Tessera sanitaria / TEAM | |
| `medical_condition` | "affetto da diabete", "diagnosi di…" | Categoria clinica |
| `ip_address` | 192.168.1.100 | |
| `username` | user_mario_rossi | |
| `credit_card_number` | 4111 1111 1111 1111 | |
| `cvv` | CVV 123 | |
| `blood_type` | gruppo sanguigno A+ | |
| `digital_signature` | hash firma, checksum | |
| `organization` (privata) | Nome azienda del cliente | Con contesto |

### 6.3 Livello 3: Presidio PatternRecognizer — Identificatori italiani strutturati

Validazione deterministica con checksum algoritmico dove applicabile:

| Entità | Regex pattern | Validazione | Esempio |
|---|---|---|---|
| `CODICE_FISCALE` | `[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]` | ✅ Checksum controllo carattere | `RSSMRA80A01L219X` |
| `PARTITA_IVA` | `[0-9]{11}` con prefisso contesto | ✅ Algoritmo mod-11 | `01234567890` |
| `IBAN_IT` | `IT[0-9]{2}[A-Z][0-9]{10}[0-9A-Z]{12}` | ✅ IBAN checksum | `IT60X0542811101000000123456` |
| `TARGA_IT` | `[A-Z]{2}[0-9]{3}[A-Z]{2}` + varianti moto | ❌ Pattern only | `AB123CD` |
| `CARTA_IDENTITA` | `[A-Z]{2}[0-9]{7}` o `CA[0-9]{7}[A-Z]{2}` | ❌ Pattern only | `AX1234567` |
| `TESSERA_SANITARIA` | `[0-9]{20}` su 3 righe o numero TEAM | ❌ Pattern only | `80380030001234567890` |
| `TEL_IT` | `(\+39\|0039)?[\s-]?(0[0-9]{1,4}[\s-]?[0-9]{4,8})` | ❌ Pattern only | `+39 011 1234567` |
| `CELL_IT` | `(\+39\|0039)?3[0-9]{9}` | ❌ Pattern only | `3401234567` |
| `PEC` | Pattern email + domini `.pec.it` e registri noti | ❌ Pattern only | `mario@firma.pec.it` |
| `MATRICOLA_INPS` | `[0-9]{8,9}` con context words | ❌ Context + pattern | `12345678` + "matricola" |

---

## 7. Architettura del Sistema — Dettaglio

```
┌──────────────────────────────────────────────────────────────────────┐
│                        AI Privacy Anonymizer v2.0                    │
│                      Architettura Ibrida 3-Layer                     │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INPUT FILE(S)                                                       │
│  (.docx .xlsx .pptx .pdf .png .jpg .txt .eml ...)                   │
│       │                                                              │
│       ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │               DOCLING  (IBM, MIT license)                   │    │
│  │  • PDF parser con AI layout (DocLayNet)                     │    │
│  │  • OCR integrato (immagini + PDF scansionati)               │    │
│  │  • TableFormer per riconoscimento tabelle                   │    │
│  │  • Output: DoclingDocument (testo posizionale strutturato)  │    │
│  │  • Formati: PDF, DOCX, XLSX, PPTX, HTML, immagini          │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │  TextItem + TableItem + ImageItem      │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │               TEXT SEGMENTER                                │    │
│  │  • Divide in chunk ≤ 4096 token (OPF) / ≤ 512 token       │    │
│  │    (GLiNER) rispettando le frasi                            │    │
│  │  • Mantiene mappa offset chunk → posizione documento        │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│              ┌──────────────┼──────────────────┐                    │
│              │              │                  │                    │
│              ▼              ▼                  ▼                    │
│  ┌─────────────────┐ ┌────────────────┐ ┌──────────────────────┐   │
│  │ LAYER 1         │ │ LAYER 2        │ │ LAYER 3              │   │
│  │ OpenAI OPF      │ │ GLiNER         │ │ Presidio             │   │
│  │                 │ │ multi_pii-v1   │ │ PatternRecognizer    │   │
│  │ • 8 categorie   │ │                │ │                      │   │
│  │ • 1.5B param    │ │ • 60+ categ.   │ │ • CF + checksum      │   │
│  │ • 50M attivi    │ │ • IT nativo    │ │ • P.IVA + mod-11     │   │
│  │ • 128K context  │ │ • ~300MB       │ │ • IBAN + checksum    │   │
│  │ • Viterbi tune  │ │ • Apache 2.0   │ │ • Targa, CI, ecc.    │   │
│  │ • Apache 2.0    │ │                │ │ • MIT license        │   │
│  └────────┬────────┘ └───────┬────────┘ └──────────┬───────────┘   │
│           │                  │                     │                │
│           └──────────────────┼─────────────────────┘                │
│                              │  Lista span PII da 3 sorgenti        │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  SPAN RESOLVER                              │    │
│  │  • Merge span sovrapposti (union strategy)                  │    │
│  │  • Priorità: L3 (deterministico) > L1 (OPF) > L2 (GLiNER)  │    │
│  │  • Consistent mapping: stessa entità → stesso placeholder   │    │
│  │  • Genera entity_map per de-anonimizzazione opzionale       │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │  Span finali unificati                │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  MASKING ENGINE                             │    │
│  │  Modalità: replace | redact | generalize | consistent       │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │               FILE RECONSTRUCTOR                            │    │
│  │  DOCX: python-docx (run-level replacement)                  │    │
│  │  XLSX: openpyxl (cell-level replacement)                    │    │
│  │  PPTX: python-pptx (shape text replacement)                 │    │
│  │  PDF:  reportlab overlay su coordinata bbox                 │    │
│  │  IMG:  Pillow fill rettangolo su bbox OCR                   │    │
│  │  TXT:  sostituzione diretta con regex offset                │    │
│  │  + Strip metadati (autore, PC, org, revisioni)              │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                        │
│                             ▼                                        │
│  OUTPUT FILE (stessa estensione) + AUDIT LOG JSON                   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 8. Span Resolver — Logica di Merge

Il resolver gestisce tre casi di sovrapposizione tra span dei tre livelli:

### 8.1 Casi di sovrapposizione

```
Caso A — Span identici (stessa entità rilevata da più layer):
  OPF:    [Mario Rossi] PERSON
  GLiNER: [Mario Rossi] person
  → OUTPUT: [Mario Rossi] PERSON  (L1 ha priorità, deduplicato)

Caso B — Span sovrapposti parzialmente (nesting):
  OPF:    [Mario]       PERSON   (0-5)
  GLiNER: [Mario Rossi] person   (0-11)
  → OUTPUT: [Mario Rossi] PERSON  (span più ampio vince)

Caso C — Span adiacenti della stessa entità:
  OPF:    [Via Roma]    ADDRESS  (0-8)
  GLiNER: [12, Torino]  address  (9-20)
  → OUTPUT: [Via Roma 12, Torino] ADDRESS  (merge se gap ≤ 3 char)

Caso D — Conflitto di tipo sullo stesso testo:
  OPF:    [01/01/1980]  DATE
  L3:     [01/01/1980]  CODICE_FISCALE (falso positivo)
  → OUTPUT: L3 vince se validazione checksum positiva, altrimenti L1
```

### 8.2 Consistent entity mapping

Ogni entità unica nel documento riceve un placeholder stabile e numerato:

```
"Mario Rossi" → [PERSONA_1]  (tutte le occorrenze, incluse varianti "M. Rossi", "il sig. Rossi")
"01/01/1980"  → [DATA_NASC_1]
"RSSMRA80A01L219X" → [CF_1]
```

Il mapping è mantenuto in memoria durante l'elaborazione e **mai persistito su disco**.

---

## 9. Modalità di Mascheratura

| Modalità | Output | Caso d'uso |
|---|---|---|
| `replace` *(default)* | `[PERSONA_1]`, `[EMAIL_1]`, `[CF_1]` | Upload chatbot AI — mantiene contesto leggibile |
| `redact` | `████████` | Documenti da condividere con terzi |
| `generalize` | `[NOME]`, `[EMAIL]`, `[CODICE_FISCALE]` | Quando il numero progressivo è irrilevante |
| `hash` | `[SHA256:a3f2c1...]` | Pipeline tecniche con necessità di de-anonimizzazione |
| `consistent` | Stesso placeholder per stessa entità | Modalità attiva per tutti i metodi sopra |

---

## 10. Requisiti Tecnici

### 10.1 Stack completo delle dipendenze

```toml
[tool.poetry.dependencies]
python = ">=3.11"

# ── Layer parsing (Docling) ──────────────────────────────────────────
docling = ">=2.0"              # MIT — IBM document parser
docling-core = ">=2.0"         # MIT — DoclingDocument data model

# ── Layer PII detection ──────────────────────────────────────────────
# L1: OpenAI Privacy Filter
# (installato da git, ~3GB download modello al primo run)
opf = { git = "https://github.com/openai/privacy-filter" }

# L2: GLiNER multilingue
gliner = ">=0.2.5"             # Apache 2.0
gliner-spacy = ">=0.0.4"       # integrazione spaCy pipeline

# L3: Presidio + spaCy italiano
presidio-analyzer = ">=2.2"    # MIT
presidio-anonymizer = ">=2.2"  # MIT
# modello spaCy italiano (download separato)
# python -m spacy download it_core_news_lg

# ── Layer ricostruzione file ─────────────────────────────────────────
python-docx = ">=1.1"
openpyxl = ">=3.1"
python-pptx = ">=0.6"
reportlab = ">=4.0"
pypdf = ">=4.0"
pillow = ">=10.0"

# ── Parsing email / legacy ───────────────────────────────────────────
mail-parser = ">=3.15"
extract-msg = ">=0.48"
striprtf = ">=0.0.26"

# ── CLI e UI ─────────────────────────────────────────────────────────
click = ">=8.1"
rich = ">=13.0"
gradio = { version = ">=4.0", optional = true }  # extra: webui

# ── Utility ──────────────────────────────────────────────────────────
pydantic = ">=2.0"
tqdm = ">=4.0"

[tool.poetry.extras]
webui = ["gradio"]
gpu   = []   # torcia GPU rilevata automaticamente
```

### 10.2 Requisiti di sistema

| Requisito | Minimo (CPU only) | Raccomandato |
|---|---|---|
| Python | 3.11 | 3.12 |
| RAM | 8 GB | 16 GB |
| Storage (modelli) | ~5 GB (OPF 3GB + GLiNER 300MB + spaCy 700MB) | SSD |
| OS | Windows 10 / Ubuntu 20.04 | Windows 11 / Ubuntu 22.04 |
| GPU (opzionale) | — | CUDA 11.8+ (4GB VRAM min per OPF FP16) |
| OCR | RapidOCR (incluso in `[documents]`, ONNX runtime, nessun binario esterno) | — |
| LibreOffice | Opzionale (solo per `.doc`/`.xls` legacy) | 7.x |

### 10.3 Installazione

```bash
# Installazione base (CPU)
pip install ai-privacy-anonymizer

# Con Web UI
pip install ai-privacy-anonymizer[webui]

# Download modelli al primo avvio (automatico, ~5GB totali)
privacy-anonymizer --setup

# Download esplicito con feedback
privacy-anonymizer --download-models --verbose

# Download manuale dei modelli spaCy
python -m spacy download it_core_news_lg
python -m spacy download en_core_web_lg
```

---

## 11. Interfaccia Utente

### 11.1 CLI

```bash
# Singolo file — usa stack ibrido completo per default
privacy-anonymizer documento.docx

# Folder intera
privacy-anonymizer ./documenti/ --output ./documenti_clean/

# Modalità redact
privacy-anonymizer report.pdf --mode redact

# Disabilita layer specifici (per debug o performance)
privacy-anonymizer file.txt --disable-layer gliner
privacy-anonymizer file.txt --disable-layer opf

# Mostra entity map (per verifica, senza i valori originali)
privacy-anonymizer file.docx --show-map

# Dry-run: mostra span rilevati senza produrre output
privacy-anonymizer file.docx --dry-run

# Forza alto recall OPF (più aggressivo)
privacy-anonymizer file.txt --recall-mode aggressive

# Solo identificatori italiani strutturati (L3 only, veloce)
privacy-anonymizer cedolino.pdf --pattern-only

# CPU esplicita (no GPU)
privacy-anonymizer file.txt --device cpu
```

### 11.2 Output CLI — esempio dry-run

```
📄 Analisi: contratto.docx
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Layer 1 (OPF):      12 span rilevati
Layer 2 (GLiNER):    4 span aggiuntivi
Layer 3 (Pattern):   3 span aggiuntivi (CF×1, P.IVA×1, Tel×1)

Totale dopo merge:  17 span unici

Categorie rilevate:
  PERSONA           ×4   [PERSONA_1..4]
  EMAIL             ×2   [EMAIL_1..2]
  CODICE_FISCALE    ×1   [CF_1]
  PARTITA_IVA       ×1   [PIVA_1]
  TELEFONO_IT       ×1   [TEL_1]
  INDIRIZZO         ×2   [INDIRIZZO_1..2]
  DATA_PRIVATA      ×3   [DATA_1..3]
  SECRET            ×2   [SECRET_1..2]
  IP_ADDRESS        ×1   [IP_1]

Metadati rimossi:   Autore, LastModifiedBy, Organizzazione
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Nessun errore di struttura previsto nell'output.
💾 Output: contratto_anonymized.docx  (dimensione: 42KB → 41KB)
```

### 11.3 Web UI locale (Gradio, opzionale)

- Drag & drop multi-file
- Visualizzazione inline del testo anonimizzato con highlight per categoria
- Toggle per abilitare/disabilitare ogni layer
- Slider recall/precision per OPF
- Download file output + audit log
- Modalità "confronto side-by-side" originale vs anonimizzato

### 11.4 Python API

```python
from privacy_anonymizer import Anonymizer, LayerConfig

# Configurazione ibrida personalizzata
config = LayerConfig(
    opf_enabled=True,
    opf_recall_mode="balanced",   # "conservative" | "balanced" | "aggressive"
    gliner_enabled=True,
    gliner_threshold=0.5,
    pattern_enabled=True,
    italian_patterns=["CF", "PIVA", "IBAN", "TARGA", "TEL_IT"],
    masking_mode="replace",        # "replace" | "redact" | "generalize" | "hash"
    consistent_mapping=True,
)

anon = Anonymizer(config=config, device="cpu")

# Singolo file
result = anon.process_file("input.docx")
result.save("output.docx")

# Batch
results = anon.process_folder("./docs_in/", output_dir="./docs_out/")

# Testo diretto
masked_text, entity_map = anon.process_text(
    "Mario Rossi, CF RSSMRA80A01L219X, tel 3401234567",
    language="it"
)

# Audit
print(result.audit_report)  # Dizionario con conteggi per categoria
```

---

## 12. Gestione Metadati

Oltre al testo visibile, Office e PDF contengono metadati che possono esporre PII:

| Metadato | Dove | Trattamento |
|---|---|---|
| Autore documento | DOCX, XLSX, PPTX, PDF | Rimosso / sostituito con "Anonimo" |
| `LastModifiedBy` | DOCX, XLSX, PPTX | Rimosso |
| Organizzazione | DOCX, XLSX, PPTX, PDF | Rimosso |
| Nome PC/server nel path | DOCX, XLSX | Rimosso dal `rsid` e `customXml` |
| Cronologia revisioni | DOCX | Azzerata (Accept all + strip track changes) |
| Commenti | DOCX, XLSX, PPTX | Anonimizzati (autore + testo commento) |
| EXIF / XMP | JPEG, TIFF, PNG | Strip completo via Pillow |
| PDF XMP metadata | PDF | Strip via pypdf |

Flag `--keep-metadata` disponibile per disabilitare questo comportamento.

---

## 13. Audit Log

```json
{
  "tool_version": "2.0.0",
  "source_file": "contratto_fornitura.docx",
  "output_file": "contratto_fornitura_anonymized.docx",
  "processed_at": "2026-04-30T14:32:01+02:00",
  "processing_time_seconds": 12.4,
  "layers_used": ["opf", "gliner", "pattern"],
  "opf_recall_mode": "balanced",
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
  "output_valid": true,
  "warnings": []
}
```

I valori PII originali **non vengono mai scritti nel log**.

---

## 14. Limitazioni Note e Rischi

| Limitazione | Impatto | Mitigazione |
|---|---|---|
| OPF recall basso con parametri default | PII non rilevate | Tuning Viterbi in modalità "balanced" o "aggressive" per il caso d'uso chatbot |
| GLiNER F1 81% (vs 96% OPF) | Falsi negativi su L2 | L2 agisce su categorie non coperte da OPF — il confronto F1 non è diretto |
| PDF scansionati → qualità OCR dipendente da DPI | Testo non riconosciuto = PII persa | Warning con DPI rilevato + soglia minima raccomandata (≥ 200 DPI) |
| OPF e GLiNER sono principalmente EN/multilingual, non IT-first | Nomi italiani rari o dialettali possono sfuggire | L3 copre identificatori strutturati; fine-tuning futuro su dataset IT per L1/L2 |
| Ricostruzione DOCX con stili complessi | Perdita di formattazione in rari casi | Fallback a `.txt` anonimizzato con warning; test su template comuni |
| Testo in immagini incorporate in DOCX/PPTX | Non analizzato nel passaggio testo | Docling estrae le immagini → processo OCR su ogni immagine embedded |
| Stack ibrido: tempo di processing aumentato | ~2-3x rispetto a singolo motore | Parallelizzazione dei 3 layer su thread separati |
| 3 modelli in RAM simultaneamente | ~5-6 GB RAM richiesti | Modalità `--low-memory` che processa i layer in sequenza liberando RAM |

---

## 15. Strategia di Test e Validazione

### 15.1 Dataset di test italiano

Sarà costruito un dataset sintetico di 500 documenti italiani con ground truth annotata manualmente, coprendo:
- Cedolini paga (Codice Fiscale, nome, banca, importi)
- Contratti di fornitura (P.IVA, indirizzi aziendali, referenti)
- Report di supporto IT (log con IP, hostname, nomi utente)
- Email aziendali (mittente, destinatario, riferimenti personali)
- Documenti medici sintetici (dati anagrafici, diagnosi generiche)

### 15.2 Metriche target per il dataset italiano

| Metrica | Target v2.0 |
|---|---|
| F1 globale (tutti i tipi) | ≥ 95% |
| Recall su CF / P.IVA / IBAN | 100% (deterministico L3) |
| Precision (falsi positivi) | ≥ 90% in modalità "balanced" |
| File output apribili e validi | 100% |
| Metadati rimossi correttamente | 100% |

---

## 16. Roadmap

### v1.0 — MVP
- [ ] CLI funzionante con stack ibrido OPF + GLiNER + Presidio
- [ ] Docling come layer di parsing (PDF, DOCX, XLSX, PPTX, TXT, immagini)
- [ ] PatternRecognizer italiani: CF, P.IVA, IBAN, targa, telefono
- [ ] Modalità `replace` con consistent mapping
- [ ] Strip metadati Office/PDF
- [ ] Audit log JSON
- [ ] Ricostruzione DOCX, XLSX, PPTX, TXT

### v1.1
- [ ] Tuning Viterbi OPF per alto recall (modalità `balanced` / `aggressive`)
- [ ] Modalità `redact` e `generalize`
- [ ] Modalità `--low-memory` per macchine con < 8GB RAM
- [ ] Web UI Gradio locale con highlight per layer sorgente
- [ ] Supporto `.eml` e `.msg`
- [ ] Batch processing su cartelle con progress bar

### v1.2
- [ ] Fine-tuning OPF su dataset italiano (cedolini, log PROFIS/ESOLVER)
- [ ] PatternRecognizer aggiuntivi: tessera sanitaria, matricola INPS, PEC
- [ ] Parallel processing dei 3 layer (riduzione latenza)
- [ ] Plugin CLI per integrazione in workflow PowerShell (wrapper `.exe` via PyInstaller)
- [ ] Dataset sintetico italiano per evaluation continua

### v2.0
- [ ] Integrazione come pre-processor nel workflow Claude Desktop (MCP server locale)
- [ ] API REST locale (FastAPI) per integrazione con automazioni esterne
- [ ] Dashboard Gradio con storico file processati (localStorage)
- [ ] Modalità `hash` con de-anonimizzazione opzionale (entity vault locale)
- [ ] Report PDF di compliance GDPR generato automaticamente
- [ ] Supporto FatturaPA XML (formato fattura elettronica italiana SDI)

---

## 17. Considerazioni di Sicurezza

- **Nessun dato lascia il dispositivo** durante la fase di anonimizzazione — tutti i modelli girano in locale
- I modelli vengono scaricati da HuggingFace / GitHub **una sola volta** al setup, poi operano offline
- I file originali **non vengono mai sovrascritti** — output sempre in file separato o directory dedicata
- L'entity map (mapping entità→placeholder) è mantenuta **solo in memoria RAM** durante l'esecuzione, mai su disco
- La cache Docling dei risultati di parsing viene cancellata al termine del processo
- Flag `--wipe-cache` disponibile per cancellazione esplicita di eventuali file temporanei

---

## 18. Criteri di Accettazione (Definition of Done — v1.0)

1. Dato un `.docx` con nome, CF, email e IBAN, l'output `.docx` è apribile in Word e non contiene nessuno dei valori originali
2. Dato un `.pdf` con testo selezionabile, l'output `.pdf` è apribile e caricabile su Claude/ChatGPT senza errori
3. Il Codice Fiscale `RSSMRA80A01L219X` viene rilevato e sostituito in tutti i formati supportati
4. La CLI processa un file da 50 pagine in meno di 90 secondi su CPU (senza GPU)
5. L'audit log non contiene mai i valori PII originali — solo categorie e conteggi
6. I metadati (autore, organizzazione) sono assenti nel file output
7. In caso di formato non supportato, errore chiaro senza crash
8. Il dataset di test italiano raggiunge F1 ≥ 95% con stack ibrido completo

---

## 19. Note di Implementazione — Priorità Tecniche

### 19.1 Ordine di sviluppo raccomandato

1. **Presidio PatternRecognizer italiani** (L3) — Implementazione più semplice, valore immediato, 100% precision su identificatori strutturati. Ideale per test iniziali del pipeline.
2. **Docling parsing layer** — Sblocca tutti i formati file; output testo per L1 e L2.
3. **GLiNER L2** — Aggiunge copertura italiana; più veloce da integrare di OPF.
4. **OPF L1** — Il più complesso da installare e tunare; integrare per ultimo.
5. **File Reconstructor** — Sviluppare in parallelo dal punto 2, formato per formato.
6. **Span Resolver / merge logic** — Dopo che i 3 layer producono output separati.

### 19.2 Decisione architetturale aperta

L'unico gap non ancora risolto da librerie esistenti è la **ricostruzione round-trip del PDF** con testo mascherato nelle coordinate esatte. L'approccio raccomandato è:

- **PDF con layer testo**: `pypdf` + `reportlab` per overlay bianco/colorato sui bounding box OPF/GLiNER → ridisegno del testo mascherato nella stessa posizione
- **PDF scansionati**: ridisegno rettangolo nero (`Pillow`) sul bounding box OCR, rasterizzazione pagina, ricostruzione PDF via `img2pdf`

Questa è l'area di maggiore complessità implementativa e richiederà test approfonditi su PDF con layout multiplo-colonna e tabelle.

---

*Documento v2.0 — pronto per il kick-off di implementazione.*
*Prossimo passo: implementazione Layer 3 (PatternRecognizer italiani) come primo sprint.*
