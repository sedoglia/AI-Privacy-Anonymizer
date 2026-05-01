from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer


SYNTHETIC_CASES = [
    # ── Cedolini paga / dipendenti ─────────────────────────────
    {
        "text": "Cedolino di Mario Rossi CF RSSMRA80A01L219M tel 3401234567",
        "labels": ["CODICE_FISCALE", "TELEFONO_IT"],
    },
    {
        "text": "Dipendente Anna Bianchi, CF BNCNNA75T41F205Y, IBAN IT60X0542811101000000123456",
        "labels": ["CODICE_FISCALE", "IBAN_IT"],
    },
    {
        "text": "Stipendio accreditato su IBAN IT28W0306905020100000017789, matricola INPS 12345678",
        "labels": ["IBAN_IT", "MATRICOLA_INPS"],
    },
    {
        "text": "Rif. cedolino #2024-04, dipendente: Luca Verdi, CF VRDLCU82M15H501J",
        "labels": ["CODICE_FISCALE"],
    },
    {
        "text": "Tessera sanitaria 80380030001234567890, ente: ASL Roma 1",
        "labels": ["TESSERA_SANITARIA"],
    },

    # ── Contratti di fornitura ─────────────────────────────────
    {
        "text": "Fornitore: ACME Srl, P.IVA 01114601006, sede legale via Roma 12, 10138 Torino",
        "labels": ["PARTITA_IVA"],
    },
    {
        "text": "Cliente Beta S.p.A. partita iva 12345678903, referente sig. Rossi tel 011 1234567",
        "labels": ["PARTITA_IVA", "TELEFONO_IT"],
    },
    {
        "text": "Coordinate bancarie: IBAN IT60X0542811101000000123456, intestatario Gamma SRL",
        "labels": ["IBAN_IT"],
    },
    {
        "text": "PEC studio.rossi@legalmail.pec.it, P.IVA IT 01234567890",
        "labels": ["PEC", "PARTITA_IVA"],
    },
    {
        "text": "Contratto firmato il 15/03/2024 da Giulia Neri, CF NRIGLI90E45L219P",
        "labels": ["CODICE_FISCALE"],
    },

    # ── Report di supporto IT / log ────────────────────────────
    {
        "text": "Server prod-db-01.acme.local IP 192.168.10.50, admin paolo.bianchi@acme.it",
        "labels": ["IP_ADDRESS", "EMAIL"],
    },
    {
        "text": "Errore SSH dall'host 10.0.0.42, utente: msmith, password rifiutata",
        "labels": ["IP_ADDRESS"],
    },
    {
        "text": "Log: 2024-04-30 12:34:56 - user mario@azienda.it failed login from 192.168.1.100",
        "labels": ["EMAIL", "IP_ADDRESS"],
    },
    {
        "text": "Connessione VPN dal 172.16.0.5 - account giulia.neri@cliente.it accettato",
        "labels": ["IP_ADDRESS", "EMAIL"],
    },
    {
        "text": "Backup completato: server 10.10.10.10, riferimento: ticket #4521 aperto da rossi@helpdesk.it",
        "labels": ["IP_ADDRESS", "EMAIL"],
    },

    # ── Email aziendali ────────────────────────────────────────
    {
        "text": "From: Mario Rossi <mario.rossi@cliente.it> To: support@acme.it Subject: Problema fattura",
        "labels": ["EMAIL"],
    },
    {
        "text": "Cordiali saluti, Anna Bianchi - anna@studio.it - tel +39 011 1234567",
        "labels": ["EMAIL", "TELEFONO_IT"],
    },
    {
        "text": "Per emergenze contattare il sig. Verdi al 3401234567 oppure scrivere a verdi@azienda.it",
        "labels": ["TELEFONO_IT", "EMAIL"],
    },
    {
        "text": "PEC: amministrazione@acme.pec.it - per comunicazioni ufficiali",
        "labels": ["PEC"],
    },

    # ── Documenti medici sintetici ─────────────────────────────
    {
        "text": "Paziente Rossi Mario, CF RSSMRA80A01L219M, tessera sanitaria 80380030001234567890",
        "labels": ["CODICE_FISCALE", "TESSERA_SANITARIA"],
    },
    {
        "text": "Referto medico per Bianchi Anna, CF BNCNNA75T41F205Y, contatto 3401234567",
        "labels": ["CODICE_FISCALE", "TELEFONO_IT"],
    },
    {
        "text": "Visita del 10/05/2024 presso ambulatorio, paziente con CF VRDLCU82M15H501J",
        "labels": ["CODICE_FISCALE"],
    },

    # ── Veicoli / immatricolazioni ─────────────────────────────
    {
        "text": "Veicolo targato AB123CD, proprietario Mario Rossi CF RSSMRA80A01L219M",
        "labels": ["TARGA_IT", "CODICE_FISCALE"],
    },
    {
        "text": "Targa moto FG12345 ritirata, contattare 011 1234567",
        "labels": ["TELEFONO_IT"],
    },
    {
        "text": "Autoveicolo XY987ZW intestato a Beta SRL, P.IVA 01114601006",
        "labels": ["TARGA_IT", "PARTITA_IVA"],
    },

    # ── Documenti di identità ──────────────────────────────────
    {
        "text": "Documento d'identità AX1234567 di Anna Bianchi",
        "labels": ["CARTA_IDENTITA"],
    },
    {
        "text": "Carta d'identità n. CA1234567AB rilasciata dal Comune di Torino",
        "labels": ["CARTA_IDENTITA"],
    },

    # ── PA / pratiche ──────────────────────────────────────────
    {
        "text": "Pratica n. 2024/IT/4521, richiedente CF RSSMRA80A01L219M, indirizzo PEC pratiche@comune.pec.it",
        "labels": ["CODICE_FISCALE", "PEC"],
    },
    {
        "text": "Iscrizione all'albo: matricola 12345678, P.IVA 01114601006",
        "labels": ["MATRICOLA_INPS", "PARTITA_IVA"],
    },

    # ── Mix / casi negativi positivi ───────────────────────────
    {
        "text": "Numero ordine 2024-12345 (non è un CF), prodotto codice ABC123",
        "labels": [],
    },
    {
        "text": "P.IVA 01114601006 valida, IBAN IT60X0542811101000000123456, IP 8.8.8.8",
        "labels": ["PARTITA_IVA", "IBAN_IT", "IP_ADDRESS"],
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

