"""Project-wide pytest fixtures and hooks."""
from __future__ import annotations

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Esegui test contro server live (http://127.0.0.1:8000)",
    )


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient — nessun server HTTP necessario."""
    from fastapi.testclient import TestClient
    from privacy_anonymizer.api import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def sample_dir():
    """Percorso alla cartella dei file campione."""
    import pathlib
    return pathlib.Path(__file__).parent / "sample_files"


@pytest.fixture(scope="session")
def live(pytestconfig):
    """Fixture di guardia: salta i test live se --live non è specificato o il server non risponde."""
    if not pytestconfig.getoption("--live"):
        pytest.skip("Usa --live per eseguire i test contro il server reale")
    import socket
    with socket.socket() as s:
        s.settimeout(2)
        try:
            s.connect(("127.0.0.1", 8000))
        except OSError:
            pytest.skip("Server non raggiungibile su http://127.0.0.1:8000. Avvialo prima.")
