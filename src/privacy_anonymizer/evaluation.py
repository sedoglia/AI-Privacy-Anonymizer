from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer


SYNTHETIC_CASES = [
    {
        "text": "Mario Rossi CF RSSMRA80A01L219X email mario.rossi@example.com tel 3401234567",
        "labels": ["CODICE_FISCALE", "EMAIL", "TELEFONO_IT"],
    },
    {
        "text": "P.IVA 01114601006 IBAN IT60X0542811101000000123456 targa AB123CD",
        "labels": ["PARTITA_IVA", "IBAN_IT", "TARGA_IT"],
    },
    {
        "text": "Server 192.168.1.10, PEC studio.rossi@legalmail.pec.it",
        "labels": ["IP_ADDRESS", "PEC"],
    },
]


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    documents: int
    expected_labels: int
    matched_labels: int
    extra_labels: int

    @property
    def recall(self) -> float:
        return self.matched_labels / self.expected_labels if self.expected_labels else 1.0

    @property
    def precision(self) -> float:
        detected = self.matched_labels + self.extra_labels
        return self.matched_labels / detected if detected else 1.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> dict:
        return {
            "documents": self.documents,
            "expected_labels": self.expected_labels,
            "matched_labels": self.matched_labels,
            "extra_labels": self.extra_labels,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def write_synthetic_dataset(destination: str | Path) -> Path:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        for item in SYNTHETIC_CASES:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    return destination


def evaluate_dataset(path: str | Path, anonymizer: Anonymizer | None = None) -> EvaluationResult:
    anonymizer = anonymizer or Anonymizer()
    documents = 0
    expected_total = 0
    matched_total = 0
    extra_total = 0
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            documents += 1
            item = json.loads(line)
            expected = set(item.get("labels", []))
            detected = {span.label for span in anonymizer.detect_text(item["text"])}
            expected_total += len(expected)
            matched_total += len(expected & detected)
            extra_total += len(detected - expected)
    return EvaluationResult(documents, expected_total, matched_total, extra_total)

