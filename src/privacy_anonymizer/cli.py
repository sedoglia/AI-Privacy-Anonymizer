from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.compliance import write_compliance_report
from privacy_anonymizer.config import LayerConfig, MaskingMode
from privacy_anonymizer.evaluation import evaluate_dataset, write_synthetic_dataset
from privacy_anonymizer.io import supported_extensions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-anonymizer")
    parser.add_argument("input", nargs="?", help="File da anonimizzare")
    parser.add_argument("--text", help="Testo diretto da anonimizzare")
    parser.add_argument("--output", help="Directory o file di output")
    parser.add_argument("--mode", choices=[mode.value for mode in MaskingMode], default=MaskingMode.REPLACE.value)
    parser.add_argument("--disable-layer", action="append", choices=["opf", "gliner", "pattern"], default=[])
    parser.add_argument("--layers", choices=["pattern-only", "hybrid"], default="pattern-only")
    parser.add_argument("--parser", choices=["built-in", "docling"], default="built-in")
    parser.add_argument("--recall-mode", choices=["conservative", "balanced", "aggressive"], default="balanced")
    parser.add_argument("--gliner-model", default="urchade/gliner_multi_pii-v1")
    parser.add_argument("--gliner-threshold", type=float, default=0.5)
    parser.add_argument("--device", default="cpu", help="Device previsto per i layer ML futuri")
    parser.add_argument("--keep-metadata", action="store_true", help="Non rimuove i metadati quando il formato lo supporta")
    parser.add_argument("--recursive", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true", help="Mostra il report senza scrivere output")
    parser.add_argument("--compliance-report", help="Scrive un report PDF GDPR per il file processato")
    parser.add_argument("--show-map", action="store_true", help="Mostra solo categorie e conteggi, mai valori originali")
    parser.add_argument("--json", action="store_true", help="Stampa audit JSON")
    parser.add_argument("--supported-formats", action="store_true", help="Mostra i formati supportati")
    parser.add_argument("--setup", action="store_true", help="Verifica setup locale disponibile")
    parser.add_argument("--download-models", action="store_true", help="Placeholder per download modelli ML futuri")
    parser.add_argument("--generate-synthetic-dataset", help="Scrive un dataset JSONL sintetico per evaluation")
    parser.add_argument("--evaluate", help="Valuta un dataset JSONL con campi text e labels")
    parser.add_argument("--webui", action="store_true", help="Avvia Web UI Gradio locale")
    parser.add_argument("--api", action="store_true", help="Avvia API REST locale FastAPI")
    parser.add_argument("--low-memory", action="store_true", help="Riduce l'uso di RAM elaborando i layer in sequenza")
    parser.add_argument("--wipe-cache", action="store_true", help="Cancella la cache locale dei modelli/parser")
    parser.add_argument("--export-vault", help="Scrive su file JSON il vault entity -> placeholder (per modalita' hash)")
    parser.add_argument(
        "--install-full",
        action="store_true",
        help="Installa tutti gli extra (office, documents, ml, docling, webui, api) e OPF in un unico passaggio",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.supported_formats:
        print("\n".join(supported_extensions()))
        return 0

    if args.wipe_cache:
        wiped = _wipe_cache()
        print(f"Cache cancellata: {wiped} elementi.")
        return 0

    if args.install_full:
        return _install_full()

    if args.setup or args.download_models:
        _print_setup_status(args.download_models)
        return 0

    if args.generate_synthetic_dataset:
        path = write_synthetic_dataset(args.generate_synthetic_dataset)
        print(f"Dataset sintetico scritto: {path}")
        return 0

    if args.webui:
        from privacy_anonymizer.webui import launch

        launch()
        return 0

    if args.api:
        _launch_api()
        return 0

    if not args.input and args.text is None:
        if args.evaluate:
            metrics = evaluate_dataset(args.evaluate)
            print(json.dumps(metrics.as_dict(), indent=2, ensure_ascii=False))
            return 0
        parser.error("specifica un file oppure --text")

    pattern_enabled = "pattern" not in args.disable_layer
    gliner_enabled = args.layers == "hybrid" and "gliner" not in args.disable_layer
    opf_enabled = args.layers == "hybrid" and "opf" not in args.disable_layer
    anonymizer = Anonymizer(
        LayerConfig(
            parser=args.parser,
            masking_mode=args.mode,
            opf_enabled=opf_enabled,
            opf_recall_mode=args.recall_mode,
            gliner_enabled=gliner_enabled,
            gliner_model=args.gliner_model,
            gliner_threshold=args.gliner_threshold,
            pattern_enabled=pattern_enabled,
            keep_metadata=args.keep_metadata,
            recursive=args.recursive,
            low_memory=args.low_memory,
        ),
        device=args.device,
    )

    try:
        if args.text is not None:
            result = anonymizer.analyze_text(args.text)
            _maybe_export_vault(args.export_vault, result.replacements or [])
            if args.json:
                print(json.dumps(result.audit_report, indent=2, ensure_ascii=False))
            else:
                print(result.anonymized_text)
                _print_summary(result.audit_report)
                if args.show_map:
                    _print_entity_map(result.replacements or [])
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
        _maybe_export_vault(args.export_vault, result.replacements or [])
        if args.compliance_report:
            write_compliance_report(result.audit_report, args.compliance_report)

        if args.json:
            print(json.dumps(result.audit_report, indent=2, ensure_ascii=False))
        else:
            _print_summary(result.audit_report)
            if args.show_map:
                _print_entity_map(result.replacements or [])
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
    _print_dependency_status("Office DOCX", "docx", "office")
    _print_dependency_status("Office XLSX", "openpyxl", "office")
    _print_dependency_status("Office PPTX", "pptx", "office")
    _print_dependency_status("PDF coordinate redaction", "fitz", "documents")
    _print_dependency_status("PDF read", "pypdf", "documents")
    _print_dependency_status("PDF write", "reportlab", "documents")
    _print_dependency_status("Image/OCR bridge", "pytesseract", "documents")
    _print_dependency_status("MSG", "extract_msg", "documents")
    _print_dependency_status("XLS legacy", "xlrd", "documents")
    _print_dependency_status("Docling parser", "docling", "docling")
    _print_dependency_status("GLiNER", "gliner", "ml")
    _print_dependency_status("OPF", "opf", "external")
    _print_dependency_status("Gradio Web UI", "gradio", "webui")
    _print_dependency_status("FastAPI", "fastapi", "api")
    if download_models:
        print("Il download GLiNER/OPF avviene automaticamente al primo uso dei rispettivi layer.")


def _print_dependency_status(label: str, module: str, extra: str) -> None:
    status = "ok" if importlib.util.find_spec(module) else f"mancante ({extra})"
    print(f"{label}: {status}")


def _print_entity_map(replacements) -> None:
    if not replacements:
        print("Mappa entità: nessuna entità rilevata.")
        return
    print("Mappa entità (categorie e placeholder, nessun valore originale):")
    seen: dict[str, str] = {}
    for replacement in replacements:
        seen.setdefault(replacement.replacement, replacement.label)
    for placeholder, label in sorted(seen.items()):
        print(f"  {placeholder}  ←  {label}")


def _maybe_export_vault(destination: str | None, replacements) -> None:
    if not destination:
        return
    vault = {
        replacement.replacement: {
            "label": replacement.label,
            "original": replacement.original,
        }
        for replacement in replacements
    }
    Path(destination).write_text(json.dumps(vault, indent=2, ensure_ascii=False), encoding="utf-8")


def _install_full() -> int:
    import subprocess

    print("Installazione completa: tutti gli extra + OPF.")
    print("Questo richiederà alcuni GB di download (OPF ~3GB, GLiNER ~300MB, Docling ~500MB).")
    extras_cmd = [sys.executable, "-m", "pip", "install", "ai-privacy-anonymizer[all]"]
    opf_cmd = [sys.executable, "-m", "pip", "install", "git+https://github.com/openai/privacy-filter"]
    print(f"  → {' '.join(extras_cmd)}")
    extras_result = subprocess.run(extras_cmd, check=False)
    if extras_result.returncode != 0:
        print("Errore: installazione extra fallita.", file=sys.stderr)
        return extras_result.returncode
    print(f"  → {' '.join(opf_cmd)}")
    opf_result = subprocess.run(opf_cmd, check=False)
    if opf_result.returncode != 0:
        print(
            "Attenzione: OPF non installato. Verifica connettività e disponibilità del repository "
            "https://github.com/openai/privacy-filter",
            file=sys.stderr,
        )
        return opf_result.returncode
    print("Installazione completa terminata.")
    return 0


def _wipe_cache() -> int:
    import shutil

    candidates = [
        Path.home() / ".cache" / "privacy_anonymizer",
        Path.cwd() / ".privacy_anonymizer_cache",
    ]
    removed = 0
    for path in candidates:
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
    return removed


def _launch_api() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Uvicorn non installato: installa con `python -m pip install -e .[api]`.") from exc
    uvicorn.run("privacy_anonymizer.api:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    raise SystemExit(main())
