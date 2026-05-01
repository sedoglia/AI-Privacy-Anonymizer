from __future__ import annotations

from collections import Counter

from privacy_anonymizer.models import DetectionSpan

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


def resolve_spans(spans: list[DetectionSpan], max_gap: int = 3) -> list[DetectionSpan]:
    if not spans:
        return []

    ordered = sorted(spans, key=lambda span: (span.start, span.end, -_priority(span)))
    groups: list[list[DetectionSpan]] = []
    current = [ordered[0]]
    current_end = ordered[0].end

    for span in ordered[1:]:
        if span.start <= current_end + max_gap and _compatible(current, span):
            current.append(span)
            current_end = max(current_end, span.end)
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

