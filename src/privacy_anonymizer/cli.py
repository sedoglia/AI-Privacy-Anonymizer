from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig, MaskingMode
from privacy_anonymizer.io import supported_extensions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-anonymizer")
    parser.add_argument("input", nargs="?", help="File da anonimizzare")
    parser.add_argument("--text", help="Testo diretto da anonimizzare")
    parser.add_argument("--output", help="Directory o file di output")
    parser.add_argument("--mode", choices=[mode.value for mode in MaskingMode], default=MaskingMode.REPLACE.value)
    parser.add_argument("--disable-layer", action="append", choices=["opf", "gliner", "pattern"], default=[])
    parser.add_argument("--layers", choices=["pattern-only", "hybrid"], default="pattern-only")
    parser.add_argument("--gliner-model", default="urchade/gliner_multi_pii-v1")
    parser.add_argument("--gliner-threshold", type=float, default=0.5)
    parser.add_argument("--device", default="cpu", help="Device previsto per i layer ML futuri")
    parser.add_argument("--keep-metadata", action="store_true", help="Non rimuove i metadati quando il formato lo supporta")
    parser.add_argument("--recursive", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true", help="Mostra il report senza scrivere output")
    parser.add_argument("--show-map", action="store_true", help="Mostra solo categorie e conteggi, mai valori originali")
    parser.add_argument("--json", action="store_true", help="Stampa audit JSON")
    parser.add_argument("--supported-formats", action="store_true", help="Mostra i formati supportati")
    parser.add_argument("--setup", action="store_true", help="Verifica setup locale disponibile")
    parser.add_argument("--download-models", action="store_true", help="Placeholder per download modelli ML futuri")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.supported_formats:
        print("\n".join(supported_extensions()))
        return 0

    if args.setup or args.download_models:
        _print_setup_status(args.download_models)
        return 0

    if not args.input and args.text is None:
        parser.error("specifica un file oppure --text")

    pattern_enabled = "pattern" not in args.disable_layer
    gliner_enabled = args.layers == "hybrid" and "gliner" not in args.disable_layer
    anonymizer = Anonymizer(
        LayerConfig(
            masking_mode=args.mode,
            gliner_enabled=gliner_enabled,
            gliner_model=args.gliner_model,
            gliner_threshold=args.gliner_threshold,
            pattern_enabled=pattern_enabled,
            keep_metadata=args.keep_metadata,
            recursive=args.recursive,
        ),
        device=args.device,
    )

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

        if input_path.is_dir():
            output_dir = output or input_path.with_name(f"{input_path.name}_anonymized")
            batch = anonymizer.process_folder(input_path, output_dir=output_dir, dry_run=args.dry_run, recursive=args.recursive)
            if args.json:
                print(json.dumps(_batch_audit(batch), indent=2, ensure_ascii=False))
            else:
                print(f"File processati: {batch.processed_count}")
                print(f"File saltati: {batch.skipped_count}")
                for skipped_path, reason in batch.skipped:
                    print(f"  SKIP {skipped_path}: {reason}")
                if args.dry_run:
                    print("Dry-run completato: nessun file scritto.")
                else:
                    print(f"Output directory: {output_dir}")
            return 0

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


def _batch_audit(batch) -> dict:
    return {
        "processed_count": batch.processed_count,
        "skipped_count": batch.skipped_count,
        "files": [result.audit_report for result in batch.results],
        "skipped": [{"path": str(path), "reason": reason} for path, reason in batch.skipped],
    }


def _print_setup_status(download_models: bool = False) -> None:
    print("Setup base disponibile.")
    print("Layer pattern italiano: pronto.")
    print("Layer Office opzionale: pronto se installato con extra [office].")
    print("Layer GLiNER opzionale: integrato, richiede extra [ml] e download modello al primo uso.")
    print("Layer OPF: non ancora implementato.")
    if download_models:
        print("Il download GLiNER avviene automaticamente al primo uso di --layers hybrid.")


if __name__ == "__main__":
    raise SystemExit(main())
