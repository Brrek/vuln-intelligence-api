"""No tests may open a network socket; upstream behavior uses HTTPX MockTransport."""

import socket
from datetime import date

import pytest

from vuln_intelligence.db import Database
from vuln_intelligence.enrichment import SyntheticIntel
from vuln_intelligence.ingest import ingest
from vuln_intelligence.providers import SyntheticScanner, fixture

AS_OF = date(2026, 1, 15)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setenv("VULN_ENABLE_LIVE", "false")
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "data.db")
    database.setup()
    return database


@pytest.fixture
def populated(db):
    run = ingest(db, SyntheticScanner(), SyntheticIntel(), AS_OF)
    assert run.status == "partial"  # Two non-CVE findings intentionally lack intelligence.
    return db


@pytest.fixture
def raw():
    return fixture("findings.json")[0]


@pytest.fixture
def tenable_raw():
    return {
        "asset": {"uuid": "asset-123", "hostname": "demo.example.test"},
        "plugin": {
            "id": 100,
            "name": "Demo plugin",
            "cve": ["CVE-2021-44228"],
            "cvss3_base_score": 9.8,
            "solution": "Apply vendor updates.",
        },
        "port": {"port": 443, "protocol": "TCP"},
        "first_found": "2025-11-01T12:00:00Z",
        "last_found": "2026-01-15T12:00:00Z",
    }
