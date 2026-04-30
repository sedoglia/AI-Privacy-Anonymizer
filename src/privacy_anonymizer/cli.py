from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig, MaskingMode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-anonymizer")
    parser.add_argument("input", nargs="?", help="File da anonimizzare")
    parser.add_argument("--text", help="Testo diretto da anonimizzare")
    parser.add_argument("--output", help="Directory o file di output")
    parser.add_argument("--mode", choices=[mode.value for mode in MaskingMode], default=MaskingMode.REPLACE.value)
    parser.add_argument("--dry-run", action="store_true", help="Mostra il report senza scrivere output")
    parser.add_argument("--show-map", action="store_true", help="Mostra solo categorie e conteggi, mai valori originali")
    parser.add_argument("--json", action="store_true", help="Stampa audit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.input and args.text is None:
        parser.error("specifica un file oppure --text")

    anonymizer = Anonymizer(LayerConfig(masking_mode=args.mode))

    try:
        if args.text is not None:
            result = anonymizer.analyze_text(args.text)
            if args.json:
                print(json.dumps(result.audit_report, indent=2, ensure_ascii=False))
            else:
                print(result.anonymized_text)
                _print_summary(result.audit_report)
            return 0

        input_path = Path(args.input)
        output = Path(args.output) if args.output else None
        output_dir = output if output and (output.suffix == "" or output.is_dir()) else None
        output_path = output if output and output_dir is None else None
        result = anonymizer.process_file(input_path, output_dir=output_dir, output_path=output_path, dry_run=args.dry_run)

        if args.json:
            print(json.dumps(result.audit_report, indent=2, ensure_ascii=False))
        else:
            _print_summary(result.audit_report)
            if args.dry_run:
                print("Dry-run completato: nessun file scritto.")
            elif result.output_path:
                print(f"Output: {result.output_path}")
        return 0
    except Exception as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1


def _print_summary(audit: dict) -> None:
    entities = audit["entities_found"]
    print(f"Span rilevati: {entities['merged_unique_spans']}")
    for category, count in sorted(entities["by_category"].items()):
        print(f"  {category}: {count}")


if __name__ == "__main__":
    raise SystemExit(main())
