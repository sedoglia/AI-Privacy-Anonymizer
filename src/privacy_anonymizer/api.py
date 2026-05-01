from __future__ import annotations

import tempfile
from pathlib import Path

from privacy_anonymizer.anonymizer import Anonymizer
from privacy_anonymizer.config import LayerConfig


def create_app():
    try:
        from fastapi import FastAPI, File, Form, UploadFile
        from fastapi.responses import FileResponse
    except ImportError as exc:
        raise RuntimeError("FastAPI non installato: installa con `python -m pip install -e .[api]`.") from exc

    app = FastAPI(title="AI Privacy Anonymizer", version="0.1.0")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/anonymize/text")
    def anonymize_text(text: str = Form(...), mode: str = Form("replace"), hybrid: bool = Form(True)):
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
        return {"text": result.anonymized_text, "audit": result.audit_report}

    @app.post("/anonymize/file")
    async def anonymize_file(file: UploadFile = File(...), mode: str = Form("replace"), hybrid: bool = Form(True)):
        tmp_path = Path(tempfile.mkdtemp(prefix="privacy-anonymizer-api-"))
        source = tmp_path / (file.filename or "upload.txt")
        source.write_bytes(await file.read())
        anonymizer = Anonymizer(LayerConfig(
            masking_mode=mode,
            opf_enabled=hybrid,
            opf_recall_mode="aggressive",
            gliner_enabled=hybrid,
            gliner_threshold=0.3,
            pattern_enabled=True,
            parallel=hybrid,
        ))
        result = anonymizer.process_file(source, output_dir=tmp_path / "out")
        return FileResponse(result.output_path, filename=result.output_path.name)

    return app


app = create_app()
