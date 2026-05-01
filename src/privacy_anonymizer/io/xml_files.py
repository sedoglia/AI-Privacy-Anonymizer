from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from privacy_anonymizer.io.base import FileAdapter, FileContent, WriteResult


FATTURAPA_SENSITIVE_TAGS = {
    "CodiceFiscale",
    "IdCodice",
    "Denominazione",
    "Nome",
    "Cognome",
    "Indirizzo",
    "NumeroCivico",
    "Comune",
    "Provincia",
    "CAP",
    "Telefono",
    "Email",
    "PEC",
    "PECDestinatario",
    "IBAN",
    "BIC",
    "RiferimentoAmministrazione",
    "AlboProfessionale",
    "Cellulare",
    "Fax",
    "RiferimentoNumeroLinea",
    "DataNascita",
}


def _is_fatturapa(root: ET.Element) -> bool:
    tag = root.tag.lower()
    return "fatturaelettronica" in tag or "fatturapa" in tag


class XmlAdapter(FileAdapter):
    extensions = {".xml"}

    def read_text(self, path: Path) -> FileContent:
        root = ET.parse(path).getroot()
        is_fattura = _is_fatturapa(root)
        values: list[str] = []
        for element in root.iter():
            local_name = element.tag.split("}", 1)[-1]
            if is_fattura and local_name not in FATTURAPA_SENSITIVE_TAGS:
                pass
            if element.text and element.text.strip():
                values.append(element.text.strip())
            for value in element.attrib.values():
                if value.strip():
                    values.append(value.strip())
        warnings: list[str] = []
        if is_fattura:
            warnings.append("FatturaPA SDI riconosciuta: tag sensibili (CodiceFiscale, IBAN, PEC, anagrafiche) preservati nello schema.")
        else:
            warnings.append("XML generico: testo e attributi estratti preservando la struttura in scrittura.")
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
