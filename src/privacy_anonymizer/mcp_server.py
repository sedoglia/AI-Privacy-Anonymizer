from __future__ import annotations

import json
import sys

from privacy_anonymizer import Anonymizer


def handle_request(request: dict) -> dict:
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "ai-privacy-anonymizer", "version": "0.1.0"},
            "capabilities": {"tools": {}},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "anonymize_text",
                    "description": "Anonimizza testo usando i detector locali configurati.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                }
            ]
        }
    elif method == "tools/call":
        params = request.get("params", {})
        if params.get("name") != "anonymize_text":
            return _error(request_id, -32601, "Tool non disponibile")
        text = params.get("arguments", {}).get("text", "")
        anonymized, counts = Anonymizer().process_text(text)
        result = {"content": [{"type": "text", "text": anonymized}], "structuredContent": {"counts": counts}}
    else:
        return _error(request_id, -32601, f"Metodo non supportato: {method}")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        response = handle_request(json.loads(line))
        print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    raise SystemExit(main())
