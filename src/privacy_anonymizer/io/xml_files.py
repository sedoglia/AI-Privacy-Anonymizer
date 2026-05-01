from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


class XmlAdapter(FileAdapter):
    extensions = {".xml"}

    def read_text(self, path: Path) -> FileContent:
        root = ET.parse(path).getroot()
        values: list[str] = []
        for element in root.iter():
            if element.text and element.text.strip():
                values.append(element.text.strip())
            for value in element.attrib.values():
                if value.strip():
                    values.append(value.strip())
        warnings = ["XML/FatturaPA: testo e attributi estratti preservando la struttura in scrittura."]
        return FileContent("\n".join(values), warnings=warnings)

    def write_anonymized(
        self,
        source: Path,
        destination: Path,
        anonymized_text: str,
        keep_metadata: bool,
        replacements=None,
        original_text: str | None = None,
    ) -> WriteResult:
        del keep_metadata, replacements, original_text
        tree = ET.parse(source)
        root = tree.getroot()
        replacements_by_line = iter(anonymized_text.splitlines())
        for element in root.iter():
            if element.text and element.text.strip():
                element.text = next(replacements_by_line, element.text)
            for key, value in list(element.attrib.items()):
                if value.strip():
                    element.attrib[key] = next(replacements_by_line, value)
        tree.write(destination, encoding="utf-8", xml_declaration=True)
        return WriteResult(metadata_stripped=True)
