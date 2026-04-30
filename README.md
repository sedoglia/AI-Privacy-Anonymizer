# AI Privacy Anonymizer

Implementazione iniziale del progetto descritto in `PRD_PrivacyAnonymizer_v2.md`.

Questo primo sprint include:

- Layer 3 deterministico per identificatori italiani strutturati.
- Resolver degli span con merge di overlap e adiacenze.
- Masking con placeholder consistenti.
- API Python minimale.
- CLI per file di testo (`.txt`, `.md`, `.log`, `.csv`) e input diretto.
- Audit log JSON senza valori PII originali.

## Esempi

```bash
privacy-anonymizer documento.txt
privacy-anonymizer documento.txt --dry-run
privacy-anonymizer documento.txt --mode redact
privacy-anonymizer --text "Mario, CF RSSMRA80A01L219X, tel 3401234567"
```

## Sviluppo

```bash
python -m pip install -e .[dev]
pytest
```

