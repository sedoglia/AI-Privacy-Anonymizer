"""Benchmark del rilevamento PII su testo sintetico (50+ pagine equivalenti).

Esecuzione:
    python scripts/benchmark.py
    python scripts/benchmark.py --layers hybrid --pages 100
"""
from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

from privacy_anonymizer import Anonymizer, LayerConfig

PAGE_TEMPLATE = """\
Sezione {n} - documento operativo

Cliente: Mario Rossi (CF RSSMRA80A01L219M), tel +39 011 1234567, email mario.rossi@example.com.
Coordinate bancarie: IBAN IT60X0542811101000000123456 intestato a Beta SRL, P.IVA 01114601006.
Pratica n. 2024/IT/{n}, indirizzo Via Roma {n}, 10138 Torino, riferimento PEC studio@legalmail.pec.it.
Tessera sanitaria 80380030001234567890, matricola INPS 12345678.
Server log: connessione dall'IP 192.168.10.{nmod}, utente: paolo.bianchi@acme.it.
Veicolo targato AB123CD intestato a Anna Bianchi (CF BNCNNA75T41F205Y).
Note: il referente del progetto e' Luca Verdi, contattabile al 3401234567 oppure verdi@cliente.it.
"""


def build_corpus(pages: int) -> str:
    return "\n".join(PAGE_TEMPLATE.format(n=i, nmod=(i % 250) + 1) for i in range(1, pages + 1))


def run_benchmark(pages: int, runs: int, layers: str) -> dict:
    text = build_corpus(pages)
    config = LayerConfig(
        pattern_enabled=True,
        gliner_enabled=(layers == "hybrid"),
        opf_enabled=False,
    )
    anonymizer = Anonymizer(config=config)

    timings: list[float] = []
    span_counts: list[int] = []
    for _ in range(runs):
        start = time.perf_counter()
        spans = anonymizer.detect_text(text)
        elapsed = time.perf_counter() - start
        timings.append(elapsed)
        span_counts.append(len(spans))

    return {
        "pages": pages,
        "runs": runs,
        "layers": layers,
        "characters": len(text),
        "spans_detected": span_counts[0],
        "min_seconds": round(min(timings), 4),
        "median_seconds": round(statistics.median(timings), 4),
        "max_seconds": round(max(timings), 4),
        "throughput_pages_per_second": round(pages / statistics.median(timings), 2) if timings else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark PII detection")
    parser.add_argument("--pages", type=int, default=50, help="Pagine sintetiche (~7 PII per pagina)")
    parser.add_argument("--runs", type=int, default=3, help="Numero di esecuzioni per la media")
    parser.add_argument("--layers", choices=["pattern-only", "hybrid"], default="pattern-only")
    parser.add_argument("--output", help="Salva risultati in JSON")
    args = parser.parse_args()

    print(f"Benchmark: {args.pages} pagine x {args.runs} run, layers={args.layers}")
    metrics = run_benchmark(args.pages, args.runs, args.layers)
    for key, value in metrics.items():
        print(f"  {key}: {value}")

    if args.output:
        import json
        Path(args.output).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"Risultati salvati in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
