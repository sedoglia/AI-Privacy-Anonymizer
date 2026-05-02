from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from datetime import datetime
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
    parser.add_argument("--pattern-only", action="store_true", help="Usa solo il layer pattern, disabilitando GLiNER e OPF")

    parser.add_argument("--recall-mode", choices=["conservative", "balanced", "aggressive"], default="aggressive")
    parser.add_argument("--gliner-model", default="urchade/gliner_multi_pii-v1")
    parser.add_argument("--gliner-threshold", type=float, default=0.3)
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
    parser.add_argument("--restore", help="Ricostruisce il testo originale da un vault JSON precedentemente esportato")
    parser.add_argument("--parallel", action=argparse.BooleanOptionalAction, default=True, help="Esegue i layer in parallelo su thread separati (default attivo; usa --no-parallel per sequenziale; incompatibile con --low-memory)")
    parser.add_argument(
        "--install-full",
        action="store_true",
        help="Installa tutti gli extra (office, documents, ml, webui, api) e OPF in un unico passaggio",
    )
    parser.add_argument(
        "--log",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help="Abilita log verboso su file. Senza argomento usa privacy_anonymizer_YYYYMMDD_HHMMSS.log nella directory corrente",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.log is not None:
        log_file = args.log or _default_log_path()
        _configure_verbose_logging(log_file)
        print(f"Log verboso: {log_file}", file=sys.stderr)
    else:
        _suppress_external_loggers()

    if args.supported_formats:
        print("\n".join(supported_extensions()))
        return 0

    if args.wipe_cache:
        wiped = _wipe_cache()
        print(f"Cache cancellata: {wiped} elementi.")
        return 0

    if args.install_full:
        return _install_full()

    if args.restore:
        return _restore_from_vault(args.restore, args.input, args.output)

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
    gliner_enabled = not args.pattern_only and "gliner" not in args.disable_layer
    opf_enabled = not args.pattern_only and "opf" not in args.disable_layer
    anonymizer = Anonymizer(
        LayerConfig(
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
            parallel=args.parallel and not args.low_memory,
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
            batch = anonymizer.process_folder(
                input_path,
                output_dir=output_dir,
                dry_run=args.dry_run,
                recursive=args.recursive,
                progress=not args.json,
            )
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
    _print_dependency_status("Image/OCR engine", "rapidocr", "documents")
    _print_dependency_status("MSG", "extract_msg", "documents")
    _print_dependency_status("XLS legacy", "xlrd", "documents")
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


def _restore_from_vault(vault_path: str, input_path: str | None, output_path: str | None) -> int:
    if not input_path:
        print("Errore: --restore richiede un file di testo anonimizzato come argomento posizionale.", file=sys.stderr)
        return 1
    vault = json.loads(Path(vault_path).read_text(encoding="utf-8"))
    text = Path(input_path).read_text(encoding="utf-8")
    for placeholder, entry in sorted(vault.items(), key=lambda item: -len(item[0])):
        original = entry.get("original")
        if isinstance(original, str):
            text = text.replace(placeholder, original)
    destination = Path(output_path) if output_path else Path(input_path).with_name(
        Path(input_path).stem + "_restored" + Path(input_path).suffix
    )
    destination.write_text(text, encoding="utf-8")
    print(f"Testo ripristinato: {destination}")
    return 0


def _install_full() -> int:
    import subprocess

    print("Installazione completa: tutti gli extra + OPF.")
    print("Questo richiederà alcuni GB di download (OPF ~3GB, GLiNER ~300MB).")
    extras_cmd = [sys.executable, "-m", "pip", "install", "ai-privacy-anonymizer[recommended]"]
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


def _default_log_path() -> str:
    return f"privacy_anonymizer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


def _suppress_external_loggers() -> None:
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.NullHandler())
    root.setLevel(logging.WARNING)
    for name in ("RapidOCR", "rapidocr", "transformers", "PIL", "onnxruntime", "httpx", "urllib3", "filelock", "huggingface_hub"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.propagate = False


def _configure_verbose_logging(log_file: str) -> None:
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        "[%(levelname)s] %(asctime)s [%(name)s] %(filename)s:%(lineno)d: %(message)s"
    ))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    for name in ("transformers", "transformers.tokenization_utils_base", "huggingface_hub", "RapidOCR", "rapidocr"):
        logging.getLogger(name).setLevel(logging.DEBUG)


def _launch_api() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Uvicorn non installato: installa con `python -m pip install -e .[api]`.") from exc
    uvicorn.run("privacy_anonymizer.api:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    raise SystemExit(main())
