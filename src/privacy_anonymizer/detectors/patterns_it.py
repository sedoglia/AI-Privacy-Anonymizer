from __future__ import annotations

import re
from collections.abc import Iterable

from privacy_anonymizer.models import DetectionSpan


CF_PATTERN = re.compile(r"\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b", re.I)
PIVA_PATTERN = re.compile(
    r"\b(?:p\.?\s*iva|partita\s+iva|vat)\s*[:#]?\s*(IT\s*)?([0-9]{11})\b",
    re.I,
)
IBAN_IT_PATTERN = re.compile(r"\bIT[0-9]{2}[A-Z][0-9A-Z]{22}\b", re.I)
TARGA_PATTERN = re.compile(r"\b[A-Z]{2}\s?[0-9]{3}\s?[A-Z]{2}\b", re.I)
CARTA_IDENTITA_PATTERN = re.compile(r"\b(?:[A-Z]{2}[0-9]{7}|CA[0-9]{7}[A-Z]{2})\b", re.I)
CELL_IT_PATTERN = re.compile(r"(?<!\d)(?:(?:\+39|0039)[\s.-]?)?3[0-9]{2}[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}(?!\d)")
TEL_IT_PATTERN = re.compile(
    r"(?<!\d)(?:(?:\+39|0039)[\s.-]?)?0[0-9]{1,4}[\s.-]?[0-9]{4,8}(?!\d)"
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
TESSERA_SANITARIA_PATTERN = re.compile(r"(?<!\d)80[0-9]{18}(?!\d)")
MATRICOLA_INPS_PATTERN = re.compile(
    r"\b(?:matricola(?:\s+inps)?|inps)\s*[:#]?\s*([0-9]{8,9})\b",
    re.I,
)
DOCUMENTO_ID_PATTERN = re.compile(r"\bID-[A-Z0-9]{6,12}\b", re.I)
INDIRIZZO_IT_PATTERN = re.compile(
    r"\b(?:via|viale|piazza|piazzale|corso|largo|vicolo|lungarno|borgo|contrada|strada)"
    r"(?:\s+[\w'.]+)+"
    r"\s+\d+"
    r"(?:\s+(?:int\.?\s*[\w/]+|scala\s+\w+|piano\s+\d+))?",
    re.I,
)


CF_ODD = {
    **dict.fromkeys("0A", 1),
    **dict.fromkeys("1B", 0),
    **dict.fromkeys("2C", 5),
    **dict.fromkeys("3D", 7),
    **dict.fromkeys("4E", 9),
    **dict.fromkeys("5F", 13),
    **dict.fromkeys("6G", 15),
    **dict.fromkeys("7H", 17),
    **dict.fromkeys("8I", 19),
    **dict.fromkeys("9J", 21),
    "K": 2,
    "L": 4,
    "M": 18,
    "N": 20,
    "O": 11,
    "P": 3,
    "Q": 6,
    "R": 8,
    "S": 12,
    "T": 14,
    "U": 16,
    "V": 10,
    "W": 22,
    "X": 25,
    "Y": 24,
    "Z": 23,
}
CF_EVEN = {str(i): i for i in range(10)} | {chr(ord("A") + i): i for i in range(26)}


class ItalianPatternDetector:
    source = "pattern"

    def detect(self, text: str) -> list[DetectionSpan]:
        spans: list[DetectionSpan] = []
        spans.extend(self._detect_codice_fiscale(text))
        spans.extend(self._detect_partita_iva(text))
        spans.extend(self._detect_iban_it(text))
        spans.extend(self._detect_simple(text, TARGA_PATTERN, "TARGA_IT"))
        spans.extend(self._detect_simple(text, CARTA_IDENTITA_PATTERN, "CARTA_IDENTITA"))
        spans.extend(self._detect_simple(text, CELL_IT_PATTERN, "CELL_IT"))
        spans.extend(self._detect_simple(text, TEL_IT_PATTERN, "TEL_IT"))
        spans.extend(self._detect_email(text))
        spans.extend(self._detect_ipv4(text))
        spans.extend(self._detect_simple(text, TESSERA_SANITARIA_PATTERN, "TESSERA_SANITARIA"))
        spans.extend(self._detect_matricola_inps(text))
        spans.extend(self._detect_simple(text, DOCUMENTO_ID_PATTERN, "DOCUMENTO_ID"))
        spans.extend(self._detect_simple(text, INDIRIZZO_IT_PATTERN, "INDIRIZZO"))
        return sorted(spans, key=lambda span: (span.start, span.end))

    def _detect_simple(self, text: str, pattern: re.Pattern[str], label: str) -> Iterable[DetectionSpan]:
        for match in pattern.finditer(text):
            yield DetectionSpan(match.start(), match.end(), label, self.source)

    def _detect_codice_fiscale(self, text: str) -> Iterable[DetectionSpan]:
        for match in CF_PATTERN.finditer(text):
            value = match.group(0).upper()
            yield DetectionSpan(
                match.start(),
                match.end(),
                "CODICE_FISCALE",
                self.source,
                metadata={"checksum_valid": str(validate_codice_fiscale(value)).lower()},
            )

    def _detect_partita_iva(self, text: str) -> Iterable[DetectionSpan]:
        for match in PIVA_PATTERN.finditer(text):
            value = match.group(2)
            if validate_partita_iva(value):
                yield DetectionSpan(match.start(2), match.end(2), "PARTITA_IVA", self.source)

    def _detect_iban_it(self, text: str) -> Iterable[DetectionSpan]:
        for match in IBAN_IT_PATTERN.finditer(text):
            value = re.sub(r"\s+", "", match.group(0).upper())
            if validate_iban(value):
                yield DetectionSpan(match.start(), match.end(), "IBAN_IT", self.source)

    def _detect_email(self, text: str) -> Iterable[DetectionSpan]:
        for match in EMAIL_PATTERN.finditer(text):
            value = match.group(0).lower()
            label = "PEC" if ".pec." in value or value.endswith(".pec.it") else "EMAIL"
            yield DetectionSpan(match.start(), match.end(), label, self.source)

    def _detect_matricola_inps(self, text: str) -> Iterable[DetectionSpan]:
        for match in MATRICOLA_INPS_PATTERN.finditer(text):
            yield DetectionSpan(match.start(1), match.end(1), "MATRICOLA_INPS", self.source)

    def _detect_ipv4(self, text: str) -> Iterable[DetectionSpan]:
        for match in IPV4_PATTERN.finditer(text):
            octets = match.group(0).split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                yield DetectionSpan(match.start(), match.end(), "IP_ADDRESS", self.source)


def validate_codice_fiscale(value: str) -> bool:
    value = value.strip().upper()
    if not CF_PATTERN.fullmatch(value):
        return False
    total = 0
    for index, char in enumerate(value[:15], start=1):
        total += CF_ODD[char] if index % 2 else CF_EVEN[char]
    return chr(ord("A") + total % 26) == value[-1]


def validate_partita_iva(value: str) -> bool:
    value = re.sub(r"\D", "", value)
    if len(value) != 11:
        return False
    total = 0
    for index, char in enumerate(value[:10], start=1):
        digit = int(char)
        if index % 2:
            total += digit
        else:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
    return (10 - total % 10) % 10 == int(value[-1])


def validate_iban(value: str) -> bool:
    value = re.sub(r"\s+", "", value).upper()
    if not IBAN_IT_PATTERN.fullmatch(value):
        return False
    rearranged = value[4:] + value[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    remainder = 0
    for char in numeric:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder == 1
