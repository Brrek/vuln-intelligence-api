import json
from datetime import date
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from vuln_intelligence.api import create_app
from vuln_intelligence.cli import main
from vuln_intelligence.db import Database
from vuln_intelligence.reports import build_report, safe_cell, write_report

from .conftest import AS_OF


@pytest.fixture
def client(populated):
    with TestClient(create_app(populated)) as test_client:
        yield test_client


def test_api_health_schema_read_only_and_summary(client):
    assert client.get("/health").json() == {"status": "ok", "schema_version": 1}
    stats = client.get("/stats").json()
    assert stats["findings"] == 7 and stats["kev_matches"] == 3
    assert stats["incomplete_enrichment"] == 2
    paths = client.get("/openapi.json").json()["paths"]
    assert all(set(operations) == {"get"} for operations in paths.values())
    assert client.post("/findings", json={}).status_code == 405
    assert client.get("/docs").status_code == 200


def test_api_pagination_filtering_details_and_priority_order(client):
    first = client.get("/findings?limit=2&offset=0").json()
    second = client.get("/findings?limit=2&offset=2").json()
    assert first["total"] == 7
    assert {f["id"] for f in first["items"]}.isdisjoint({f["id"] for f in second["items"]})
    assert first["items"][0]["priority"]["score"] == 99.55
    detail = client.get(f"/findings/{first['items'][0]['id']}").json()
    assert detail == first["items"][0]
    filtered = client.get("/findings?severity=critical&asset=payments-prod&min_priority=90").json()
    assert filtered["total"] == 1
    assert client.get("/priorities?limit=1").json()["items"] == first["items"][:1]
    assert client.get("/vulnerabilities?limit=2&offset=2").json()["total"] == 5
    assert client.get("/findings?offset=999").json()["items"] == []
    assert client.get(f"/findings/{uuid4()}").status_code == 404
    assert client.get("/ingestions").json()["total"] == 1
    assert client.get("/ingestions/latest").json()["status"] == "partial"


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "offset=-1",
        "severity=urgent",
        "min_priority=101",
        "min_priority=nan",
        "min_priority=inf",
        "limit=secret-token",
    ],
)
def test_invalid_queries_have_sanitized_errors(client, query):
    response = client.get(f"/findings?{query}")
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid path or query parameters."}


def test_api_missing_database_and_empty_history(tmp_path, db):
    with TestClient(create_app(Database(tmp_path / "missing.db"))) as client:
        assert client.get("/health").status_code == 503
        assert client.get("/stats").status_code == 503
    with TestClient(create_app(db)) as client:
        assert client.get("/ingestions/latest").status_code == 404
        assert client.get("/findings/not-uuid").status_code == 422
    with db.connect() as connection:
        connection.execute("PRAGMA user_version=2")
    with TestClient(create_app(db)) as client:
        assert client.get("/health").status_code == 503


def test_factory_uses_environment_database(monkeypatch, db):
    monkeypatch.setenv("VULN_DB", str(db.path))
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200


def test_reports_are_reproducible_and_match_database(populated, tmp_path):
    first_json, first_md = write_report(populated, tmp_path / "first", AS_OF)
    second_json, second_md = write_report(populated, tmp_path / "second", AS_OF)
    assert first_json.read_bytes() == second_json.read_bytes()
    assert first_md.read_bytes() == second_md.read_bytes()
    report = json.loads(first_json.read_text())
    assert report["summary"] == populated.summary().model_dump()
    assert report["asset_exposure"][0]["asset_id"] == "payments-prod"
    assert len(report["kev_matches"]) == 3
    assert len(report["incomplete_enrichment"]) == 2
    assert "99.55" in first_md.read_text()
    assert "synthetic" in first_md.read_text()
    assert safe_cell("<script>|\n`hello`") == "&lt;script&gt;&#124; &#96;hello&#96;"
    with pytest.raises(ValueError, match="report date"):
        build_report(populated, date(2026, 1, 16))


def test_example_report_matches_actual_program_output(populated):
    example = Path(__file__).parents[1] / "examples" / "report.json"
    assert json.loads(example.read_text()) == build_report(populated, AS_OF)


def test_cli_ingest_report_exit_codes_and_custom_config(tmp_path, capsys):
    dbpath = str(tmp_path / "cli.db")
    weights = tmp_path / "weights.json"
    weights.write_text('{"cvss":30,"kev":25,"epss":15,"criticality":15,"environment":10,"age":5}')
    context = tmp_path / "context.json"
    context.write_text("{}")
    assert main(["--db", dbpath, "init"]) == 0
    assert (
        main(
            [
                "--db",
                dbpath,
                "ingest",
                "--as-of",
                str(AS_OF),
                "--weights",
                str(weights),
                "--context",
                str(context),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["status"] == "partial"
    assert (
        main(["--db", dbpath, "report", "--as-of", str(AS_OF), "--out", str(tmp_path / "out")]) == 0
    )
    assert (tmp_path / "out/report.md").is_file()
    assert main(["--db", dbpath, "ingest", "--intel", "live"]) == 1
    assert main(["--db", dbpath, "ingest", "--scanner", "tenable"]) == 1
    assert main(["--db", dbpath, "ingest", "--weights", str(tmp_path / "missing.json")]) == 1


def test_cli_serve_binds_only_localhost(monkeypatch, tmp_path):
    server = Mock()
    monkeypatch.setattr("vuln_intelligence.cli.uvicorn.run", server)
    assert main(["--db", str(tmp_path / "server.db"), "serve"]) == 0
    assert server.call_args.kwargs["host"] == "127.0.0.1"
    assert server.call_args.kwargs["access_log"] is False
    assert main(["serve", "--port", "70000"]) == 1


def test_cli_configuration_errors_do_not_echo_secrets(monkeypatch, capsys):
    monkeypatch.setenv("VULN_ENABLE_LIVE", "secret-that-is-not-a-boolean")
    assert main(["init"]) == 1
    assert "secret-that" not in capsys.readouterr().err
