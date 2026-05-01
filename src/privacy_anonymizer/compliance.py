from __future__ import annotations

import json
from pathlib import Path

from privacy_anonymizer.errors import MissingOptionalDependencyError


def write_compliance_report(audit: dict, destination: str | Path) -> Path:
    destination = Path(destination)
    canvas, pagesizes = _import_reportlab()
    c = canvas.Canvas(str(destination), pagesize=pagesizes.A4)
    width, height = pagesizes.A4
    del width
    y = height - 48
    lines = [
        "AI Privacy Anonymizer - Report Compliance GDPR",
        f"File sorgente: {audit.get('source_file')}",
        f"File output: {audit.get('output_file')}",
        f"Processato: {audit.get('processed_at')}",
        f"Layer usati: {', '.join(audit.get('layers_used', []))}",
        f"Metadati rimossi: {audit.get('metadata_stripped')}",
        "",
        "Entità rilevate:",
    ]
    for category, count in sorted(audit.get("entities_found", {}).get("by_category", {}).items()):
        lines.append(f"- {category}: {count}")
    warnings = audit.get("warnings") or []
    if warnings:
        lines.extend(["", "Warning:"])
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(["", "Audit JSON sintetico:", json.dumps(audit, ensure_ascii=False)[:1500]])

    for line in lines:
        if y < 48:
            c.showPage()
            y = height - 48
        c.drawString(48, y, str(line)[:110])
        y -= 16
    c.save()
    return destination


def _import_reportlab():
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib import pagesizes
    except ImportError as exc:
        raise MissingOptionalDependencyError("reportlab", "documents") from exc
    return canvas, pagesizes

