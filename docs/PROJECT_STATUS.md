# Project Status

AI Privacy Anonymizer now includes the full local application shell described in the PRD:

- CLI, Python API, Web UI entrypoint, REST API entrypoint, and MCP stdio entrypoint.
- Pattern layer for Italian structured identifiers.
- Optional GLiNER and OPF lazy integrations.
- Built-in and optional Docling parsing paths.
- Text, Office, PDF, image, email, RTF, XML/FatturaPA, and legacy read-only adapters.
- Coordinate redaction for selectable PDFs and OCR-aligned images, with explicit fallback warnings.
- Audit JSON and PDF compliance report.
- Synthetic dataset generation and evaluation metrics.
- GitHub Actions test workflow.

Known runtime caveats:

- OPF must be installed from its upstream package/repository.
- GLiNER downloads model weights at first use.
- OCR requires Tesseract installed on the host.
- Docling is optional and may download/initialize models depending on its configuration.
- Complex PDF/image layouts can still require manual QA; audit warnings are emitted when fallback paths are used.

