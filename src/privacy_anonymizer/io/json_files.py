from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class JsonAdapter(FileAdapter):
    extensions = {".json"}

    def read_text(self, path: Path) -> FileContent:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        values: list[str] = []
        _collect_strings(data, values)
        return FileContent(
            "\n".join(values),
            warnings=["JSON: valori stringa estratti preservando la struttura in scrittura."],
        )

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements=None,
        original_text: str | None = None,
        source_content=None,
    ) -> WriteResult:
        del keep_metadata, replacements, original_text, source_content
        with source.open(encoding="utf-8") as f:
            data = json.load(f)
        lines = iter(anonymized_text.splitlines())
        data = _replace_strings(data, lines)
        with destination.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return WriteResult()


def _collect_strings(node: Any, out: list[str]) -> None:
    """DFS traversal collecting single-line string values (dict values and array items)."""
    if isinstance(node, dict):
        for value in node.values():
            _collect_strings(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_strings(item, out)
    elif isinstance(node, str) and "\n" not in node:
        out.append(node)


def _replace_strings(node: Any, lines) -> Any:
    """DFS traversal replacing single-line strings with values from the iterator."""
    if isinstance(node, dict):
        return {k: _replace_strings(v, lines) for k, v in node.items()}
    if isinstance(node, list):
        return [_replace_strings(item, lines) for item in node]
    if isinstance(node, str) and "\n" not in node:
        return next(lines, node)
    return node
