from __future__ import annotations


class PrivacyAnonymizerError(Exception):
    """Base exception for user-facing anonymizer errors."""


class MissingOptionalDependencyError(PrivacyAnonymizerError):
    def __init__(self, package: str, extra: str) -> None:
        super().__init__(f"Dipendenza opzionale mancante: installa con `python -m pip install -e .[{extra}]` ({package}).")

