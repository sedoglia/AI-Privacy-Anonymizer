from __future__ import annotations

import tempfile
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig


def create_app():
    try:
        import gradio as gr
    except ImportError as exc:
        raise RuntimeError("Gradio non installato: installa con `python -m pip install -e .[webui]`.") from exc

    def anonymize_text(text: str, mode: str, hybrid: bool):
        anonymizer = Anonymizer(LayerConfig(masking_mode=mode, gliner_enabled=hybrid, pattern_enabled=True))
        result = anonymizer.analyze_text(text)
        return result.anonymized_text, result.audit_report

    def anonymize_file(file_obj, mode: str, hybrid: bool):
        if file_obj is None:
            return None, {"warnings": ["Nessun file caricato."]}
        anonymizer = Anonymizer(LayerConfig(masking_mode=mode, gliner_enabled=hybrid, pattern_enabled=True))
        source = Path(file_obj.name)
        output_dir = tempfile.mkdtemp(prefix="privacy-anonymizer-")
        result = anonymizer.process_file(source, output_dir=output_dir)
        return str(result.output_path), result.audit_report

    with gr.Blocks(title="AI Privacy Anonymizer") as demo:
        gr.Markdown("# AI Privacy Anonymizer")
        with gr.Tab("Testo"):
            text = gr.Textbox(lines=12, label="Input")
            mode = gr.Dropdown(["replace", "redact", "generalize", "hash"], value="replace", label="Modalità")
            hybrid = gr.Checkbox(value=False, label="Abilita GLiNER")
            btn = gr.Button("Anonimizza")
            output = gr.Textbox(lines=12, label="Output")
            audit = gr.JSON(label="Audit")
            btn.click(anonymize_text, inputs=[text, mode, hybrid], outputs=[output, audit])
        with gr.Tab("File"):
            file_input = gr.File(label="File")
            file_mode = gr.Dropdown(["replace", "redact", "generalize", "hash"], value="replace", label="Modalità")
            file_hybrid = gr.Checkbox(value=False, label="Abilita GLiNER")
            file_btn = gr.Button("Anonimizza file")
            file_output = gr.File(label="Output")
            file_audit = gr.JSON(label="Audit")
            file_btn.click(anonymize_file, inputs=[file_input, file_mode, file_hybrid], outputs=[file_output, file_audit])
    return demo


def launch() -> None:
    create_app().launch()
