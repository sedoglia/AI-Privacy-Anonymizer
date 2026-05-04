from __future__ import annotations

import re
from collections import Counter

from privacy_anonymizer.models import DetectionSpan

# Characters that may be appended to a name/entity by the ML model but are
# structural separators in CSV/tabular text, not part of the entity value.
_STRIP_PUNCT = frozenset(", ;\t")

SOURCE_PRIORITY = {"pattern": 3, "opf": 2, "gliner": 1}
LABEL_ALIASES = {
    "EMAIL": "EMAIL",
    "PEC": "PEC",
    "CODICE_FISCALE": "CODICE_FISCALE",
    "PARTITA_IVA": "PARTITA_IVA",
    "IBAN_IT": "IBAN_IT",
    "CELL_IT": "TELEFONO_IT",
    "TEL_IT": "TELEFONO_IT",
    "IP_ADDRESS": "IP_ADDRESS",
}


def resolve_spans(spans: list[DetectionSpan], max_gap: int = 3, text: str = "") -> list[DetectionSpan]:
    if not spans:
        return []

    # Split spans that cross cell boundaries (newlines) into per-line sub-spans,
    # so names like "Francesco\nRomano" become two separate PERSONA detections.
    if text:
        expanded: list[DetectionSpan] = []
        for s in spans:
            expanded.extend(_split_on_newlines(s, text))
        trimmed: list[DetectionSpan] = []
        for s in expanded:
            t = _trim_span_punctuation(s, text)
            if t is not None:
                trimmed.append(t)
        spans = [s for s in trimmed if not _is_false_positive(text[s.start:s.end])]

    ordered = sorted(spans, key=lambda span: (span.start, span.end, -_priority(span)))
    groups: list[list[DetectionSpan]] = []
    current = [ordered[0]]
    current_end = ordered[0].end

    for span in ordered[1:]:
        if span.start <= current_end + max_gap and _compatible(current, span):
            gap_text = text[current_end:span.start] if text else ""
            if "\n" not in gap_text:
                current.append(span)
                current_end = max(current_end, span.end)
            else:
                groups.append(current)
                current = [span]
                current_end = span.end
        else:
            groups.append(current)
            current = [span]
            current_end = span.end

    groups.append(current)
    merged = [_merge_group(group) for group in groups]

    # Second pass: resolve any remaining overlaps between incompatible spans.
    # Higher source priority wins; ties broken by span length (longer wins).
    by_priority = sorted(merged, key=lambda s: (-_priority(s), -s.length, s.start))
    accepted: list[DetectionSpan] = []
    for candidate in by_priority:
        if not any(candidate.start < kept.end and kept.start < candidate.end for kept in accepted):
            accepted.append(candidate)
    return sorted(accepted, key=lambda s: s.start)


def category_counts(spans: list[DetectionSpan]) -> dict[str, int]:
    return dict(Counter(span.label for span in spans))


def normalize_label(label: str) -> str:
    return LABEL_ALIASES.get(label.upper(), label.upper())


def _compatible(group: list[DetectionSpan], span: DetectionSpan) -> bool:
    candidate = normalize_label(span.label)
    labels = {normalize_label(item.label) for item in group}
    return candidate in labels or bool({"TEL_IT", "CELL_IT", "TELEFONO_IT"} & labels & {candidate})


def _merge_group(group: list[DetectionSpan]) -> DetectionSpan:
    start = min(span.start for span in group)
    end = max(span.end for span in group)
    winner = max(group, key=lambda span: (_priority(span), span.length, span.score))
    return DetectionSpan(start, end, normalize_label(winner.label), winner.source, winner.score)


def _priority(span: DetectionSpan) -> int:
    return SOURCE_PRIORITY.get(span.source, 0)


def _split_on_newlines(span: DetectionSpan, text: str) -> list[DetectionSpan]:
    """Split a span that crosses newlines into one sub-span per non-empty line."""
    span_text = text[span.start:span.end]
    if "\n" not in span_text:
        return [span]
    result = []
    pos = span.start
    for line in span_text.split("\n"):
        if line.strip():
            result.append(DetectionSpan(pos, pos + len(line), span.label, span.source, span.score))
        pos += len(line) + 1
    return result


def _trim_span_punctuation(span: DetectionSpan, text: str) -> DetectionSpan | None:
    """Strip leading/trailing CSV separators from ML-detected spans.

    OPF sometimes includes trailing commas or semicolons that are structural
    separators, not part of the entity value. Only applied to ML sources (opf,
    gliner) — regex-based patterns are already precise.
    """
    if span.source not in ("opf", "gliner"):
        return span
    start, end = span.start, span.end
    while start < end and text[start] in _STRIP_PUNCT:
        start += 1
    while end > start and text[end - 1] in _STRIP_PUNCT:
        end -= 1
    if start >= end:
        return None
    if start == span.start and end == span.end:
        return span
    return DetectionSpan(start, end, span.label, span.source, span.score)


_FALSE_POSITIVE_WORDS: frozenset[str] = frozenset({
    # Italian column/header names
    "Sesso", "Cognome", "Nome", "Ruolo", "Azienda", "Provincia", "Citta", "Stato",
    "Indirizzo", "CAP", "Data", "Nota", "Note", "Email", "Telefono", "Cellulare",
    # Common Italian locations
    "Roma", "Milano", "Napoli", "Torino", "Genova", "Palermo", "Bologna", "Firenze",
    "Venezia", "Verona", "Messina", "Catania", "Padova", "Trieste", "Brescia",
    "Parma", "Ravenna", "Perugia", "Modena", "Reggio", "Cagliari", "Lecce",
    # Common Italian job titles
    "Analista", "Tecnico", "Manager", "Impiegato", "Operaio", "Consulente",
    "Specialista", "Coordinatore", "Responsabile", "Direttore", "Supervisore",
    # Common product / device names that ML models mistake for person names
    "Mouse", "Monitor", "Tastiera", "Stampante", "Schermo", "Notebook", "Laptop",
    "Computer", "Tablet", "Server", "Router", "Webcam", "Cuffie", "Scanner",
    "Smartphone", "Telefono", "Cellulare", "Fotocamera", "Proiettore",
    # Generic commercial terms
    "Prodotto", "Articolo", "Servizio", "Ordine", "Fattura", "Prezzo", "Quantita",
    "Descrizione", "Categoria", "Marca", "Modello", "Colore", "Taglia",
})


_FALSE_POSITIVE_LOWER: frozenset[str] = frozenset(w.lower() for w in _FALSE_POSITIVE_WORDS)


def _is_false_positive(text: str) -> bool:
    return text in _FALSE_POSITIVE_WORDS or text.lower() in _FALSE_POSITIVE_LOWER

