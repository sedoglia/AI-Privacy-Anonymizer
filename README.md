# AI Privacy Anonymizer

Implementazione iniziale del progetto descritto in `PRD_PrivacyAnonymizer_v2.md`.

Stato implementazione:

- Layer 3 deterministico per identificatori italiani strutturati.
- Layer GLiNER opzionale con lazy loading (`--layers hybrid`, extra `ml`).
- Layer OPF opzionale con lazy loading (`--layers hybrid`, installazione OPF esterna).
- Resolver degli span con merge di overlap e adiacenze.
- Masking con placeholder consistenti.
- API Python per testo, file e cartelle.
- CLI per testo diretto, file e cartelle.
- Supporto testo puro (`.txt`, `.md`, `.log`, `.csv`) senza dipendenze extra.
- Supporto Office opzionale (`.docx`, `.xlsx`, `.pptx`) con extra `office`.
- Supporto documenti opzionale (`.pdf`, immagini, `.eml`, `.rtf`) con extra `documents`.
- Redaction a coordinate per PDF selezionabili tramite PyMuPDF e immagini tramite bounding box OCR.
- Parser Docling opzionale selezionabile con `--parser docling`.
- Strip metadati base Office, disattivabile con `--keep-metadata`.
- Web UI Gradio opzionale e API REST FastAPI locale.
- Audit log JSON senza valori PII originali.

## Esempi

```bash
privacy-anonymizer documento.txt
privacy-anonymizer documento.txt --dry-run
privacy-anonymizer documento.txt --mode redact
privacy-anonymizer ./documenti --output ./documenti_clean
privacy-anonymizer documento.docx --output documento_clean.docx
privacy-anonymizer report.pdf --mode redact
privacy-anonymizer file.txt --layers hybrid --disable-layer opf
privacy-anonymizer --supported-formats
privacy-anonymizer --setup
privacy-anonymizer --webui
privacy-anonymizer --api
privacy-anonymizer --text "Mario, CF RSSMRA80A01L219X, tel 3401234567"
```

## Installazione extra

```bash
python -m pip install -e .[office]
python -m pip install -e .[documents]
python -m pip install -e .[docling]
python -m pip install -e .[ml]
python -m pip install -e .[webui]
python -m pip install -e .[api]
python -m pip install -e .[all]
```

## Note

Alcune feature dipendono da componenti esterni pesanti:

- GLiNER scarica il modello al primo uso.
- OPF richiede l'installazione del pacchetto OpenAI Privacy Filter.
- OCR immagini richiede Tesseract installato nel sistema.
- PDF selezionabili vengono redatti a coordinate quando PyMuPDF trova il testo originale; in caso contrario il sistema usa un fallback testuale.
- Immagini vengono redatte a coordinate quando l'OCR restituisce bounding box allineabili alle entità; in caso contrario viene generata una versione testuale semplificata.

## Sviluppo

```bash
python -m pip install -e .[dev,office]
pytest
```
