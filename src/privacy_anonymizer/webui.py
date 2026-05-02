from __future__ import annotations

import html
import tempfile
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig
from privacy_anonymizer.models import DetectionSpan


LAYER_COLORS = {
    "pattern": "#ffd54f",
    "opf": "#90caf9",
    "gliner": "#a5d6a7",
}

LEGEND_HTML = (
    '<div style="margin-bottom:8px;font-size:0.9em">'
    '<span style="background:#ffd54f;padding:2px 6px;border-radius:3px;margin-right:6px">Layer 3 pattern</span>'
    '<span style="background:#90caf9;padding:2px 6px;border-radius:3px;margin-right:6px">Layer 1 OPF</span>'
    '<span style="background:#a5d6a7;padding:2px 6px;border-radius:3px">Layer 2 GLiNER</span>'
    "</div>"
)


def render_highlighted_html(text: str, spans: list[DetectionSpan]) -> str:
    if not text:
        return LEGEND_HTML + "<em>Nessun testo</em>"
    ordered = sorted(spans, key=lambda span: span.start)
    pieces: list[str] = [LEGEND_HTML, "<pre style='white-space:pre-wrap;font-family:monospace'>"]
    cursor = 0
    for span in ordered:
        if span.start < cursor:
            continue
        pieces.append(html.escape(text[cursor : span.start]))
        color = LAYER_COLORS.get(span.source, "#e0e0e0")
        original = html.escape(text[span.start : span.end])
        title = f"{span.label} via {span.source}"
        pieces.append(
            f'<span style="background:{color};padding:1px 3px;border-radius:3px" title="{title}">{original}</span>'
        )
        cursor = span.end
    pieces.append(html.escape(text[cursor:]))
    pieces.append("</pre>")
    return "".join(pieces)


def create_app():
    try:
        import gradio as gr
    except ImportError as exc:
        raise RuntimeError("Gradio non installato: installa con `python -m pip install -e .[webui]`.") from exc

    def anonymize_text(text: str, mode: str, hybrid: bool):
        anonymizer = Anonymizer(LayerConfig(
            masking_mode=mode,
            opf_enabled=hybrid,
            opf_recall_mode="aggressive",
            gliner_enabled=hybrid,
            gliner_threshold=0.3,
            pattern_enabled=True,
            parallel=hybrid,
        ))
        result = anonymizer.analyze_text(text)
        highlighted = render_highlighted_html(text, result.spans)
        return result.anonymized_text, highlighted, result.audit_report

    def anonymize_file(file_obj, mode: str, hybrid: bool):
        if file_obj is None:
            return None, {"warnings": ["Nessun file caricato."]}
        anonymizer = Anonymizer(LayerConfig(
            masking_mode=mode,
            opf_enabled=hybrid,
            opf_recall_mode="aggressive",
            gliner_enabled=hybrid,
            gliner_threshold=0.3,
            pattern_enabled=True,
            parallel=hybrid,
        ))
        source = Path(file_obj.name)
        output_dir = tempfile.mkdtemp(prefix="privacy-anonymizer-")
        result = anonymizer.process_file(source, output_dir=output_dir)
        return str(result.output_path), result.audit_report

    with gr.Blocks(title="AI Privacy Anonymizer") as demo:
        gr.Markdown("# AI Privacy Anonymizer")
        with gr.Tab("Testo"):
            text = gr.Textbox(lines=12, label="Input")
            mode = gr.Dropdown(["replace", "redact", "generalize", "hash"], value="replace", label="Modalità")
            hybrid = gr.Checkbox(value=True, label="Modalità Hybrid (OPF + GLiNER)")
            btn = gr.Button("Anonimizza")
            output = gr.Textbox(lines=12, label="Output anonimizzato")
            highlight = gr.HTML(label="Highlight per layer sorgente")
            audit = gr.JSON(label="Audit")
            btn.click(anonymize_text, inputs=[text, mode, hybrid], outputs=[output, highlight, audit])
        with gr.Tab("File"):
            file_input = gr.File(label="File")
            file_mode = gr.Dropdown(["replace", "redact", "generalize", "hash"], value="replace", label="Modalità")
            file_hybrid = gr.Checkbox(value=True, label="Modalità Hybrid (OPF + GLiNER)")
            file_btn = gr.Button("Anonimizza file")
            file_output = gr.File(label="Output")
            file_audit = gr.JSON(label="Audit")
            file_btn.click(anonymize_file, inputs=[file_input, file_mode, file_hybrid], outputs=[file_output, file_audit])
    return demo


def launch() -> None:
    create_app().launch(inbrowser=True)
