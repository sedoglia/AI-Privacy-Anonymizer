from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class EmlAdapter(FileAdapter):
    extensions = {".eml"}

    def read_text(self, path: Path) -> FileContent:
        message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        parts = [
            f"From: {message.get('from', '')}",
            f"To: {message.get('to', '')}",
            f"Cc: {message.get('cc', '')}",
            f"Subject: {message.get('subject', '')}",
            "",
            _message_body(message),
        ]
        warnings = []
        attachment_count = sum(1 for part in message.iter_attachments())
        if attachment_count:
            warnings.append(f"Allegati non processati ricorsivamente in questo adapter: {attachment_count}.")
        return FileContent("\n".join(parts), warnings=warnings)

    def write_anonymized(self, source: Path, destination: Path, anonymized_text: str, keep_metadata: bool) -> WriteResult:
        del source, keep_metadata
        message = EmailMessage()
        message["Subject"] = "Messaggio anonimizzato"
        message["From"] = "anonimo@example.local"
        message["To"] = "anonimo@example.local"
        message.set_content(anonymized_text)
        destination.write_bytes(message.as_bytes(policy=policy.default))
        return WriteResult(
            warnings=["EML MVP: messaggio ricostruito come plain text anonimizzato, allegati esclusi."],
            metadata_stripped=True,
        )


def _message_body(message) -> str:
    if message.is_multipart():
        bodies = []
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() in {"text/plain", "text/html"}:
                bodies.append(part.get_content())
        return "\n".join(str(body) for body in bodies)
    return str(message.get_content())

