# AI Privacy Anonymizer

Implementazione iniziale del progetto descritto in `PRD_PrivacyAnonymizer_v2.md`.

Stato implementazione:

- Layer 3 deterministico per identificatori italiani strutturati.
- Layer GLiNER opzionale con lazy loading (`--layers hybrid`, extra `ml`).
- Resolver degli span con merge di overlap e adiacenze.
- Masking con placeholder consistenti.
- API Python per testo, file e cartelle.
- CLI per testo diretto, file e cartelle.
- Supporto testo puro (`.txt`, `.md`, `.log`, `.csv`) senza dipendenze extra.
- Supporto Office opzionale (`.docx`, `.xlsx`, `.pptx`) con extra `office`.
- Strip metadati base Office, disattivabile con `--keep-metadata`.
- Audit log JSON senza valori PII originali.

## Esempi

```bash
privacy-anonymizer documento.txt
privacy-anonymizer documento.txt --dry-run
privacy-anonymizer documento.txt --mode redact
privacy-anonymizer ./documenti --output ./documenti_clean
privacy-anonymizer documento.docx --output documento_clean.docx
privacy-anonymizer --supported-formats
privacy-anonymizer --text "Mario, CF RSSMRA80A01L219X, tel 3401234567"
```

## Installazione extra

```bash
python -m pip install -e .[office]
python -m pip install -e .[ml]
python -m pip install -e .[all]
```

## Sviluppo

```bash
python -m pip install -e .[dev,office]
pytest
```
