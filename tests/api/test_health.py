"""Tests for GET /health endpoint."""
from __future__ import annotations


def test_health_returns_200(client):
    assert client.get("/health").status_code == 200


def test_health_returns_ok(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_health_content_type_is_json(client):
    assert "application/json" in client.get("/health").headers["content-type"]


def test_health_no_auth_required(client):
    resp = client.get("/health")
    assert resp.status_code not in (401, 403)


def test_health_wrong_path_is_404(client):
    assert client.get("/healthz").status_code == 404
