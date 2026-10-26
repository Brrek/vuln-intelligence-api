import json
import sqlite3
from datetime import date

import pytest

from vuln_intelligence.db import Database
from vuln_intelligence.enrichment import SyntheticIntel
from vuln_intelligence.http import ProviderError
from vuln_intelligence.ingest import ingest
from vuln_intelligence.models import Observation
from vuln_intelligence.providers import SyntheticScanner

from .conftest import AS_OF


class Records:
    name = "synthetic"

    def __init__(self, rows):
        self.rows = rows

    def records(self):
        yield from self.rows


def test_repeat_ingestion_is_idempotent_and_history_persists(populated):
    before = populated.findings().model_dump()
    second = ingest(populated, SyntheticScanner(), SyntheticIntel(), AS_OF)
    reopened = Database(populated.path)
    assert reopened.findings().model_dump() == before
    assert second.received == 8 and second.duplicates == 1
    assert second.inserted == 0 and second.updated == 7
    assert reopened.summary().findings == 7
    assert reopened.summary().assets == 4
    assert reopened.summary().vulnerabilities == 5
    assert reopened.runs().total == 2
    with reopened.connect(readonly=True) as connection:
        assert connection.execute("SELECT count(*) FROM enrichment").fetchone()[0] == 7
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM findings")


def test_invalid_missing_future_and_source_mismatch(db, raw):
    invalid = json.loads(json.dumps(raw))
    invalid["last_seen"] = "2099-01-01"
    wrong_source = {**raw, "source": "other"}
    run = ingest(db, Records([{}, invalid, wrong_source, raw]), SyntheticIntel(), AS_OF)
    assert run.status == "partial"
    assert run.rejected == 3 and run.inserted == 1
    assert db.summary().findings == 1
    assert "records rejected" in run.errors[0]


def test_provider_failure_rolls_back_staged_findings(populated, raw, caplog):
    class FailingScanner:
        name = "synthetic"

        def records(self):
            raw["port"] = 9999
            yield raw
            raise ProviderError("controlled transport failure")

    with caplog.at_level("INFO"):
        run = ingest(populated, FailingScanner(), SyntheticIntel(), AS_OF)
    assert run.status == "failed"
    assert run.inserted == 0 and run.updated == 0
    assert populated.summary().findings == 7
    assert populated.runs(1).items[0].status == "failed"
    message = json.loads(caplog.records[-1].message)
    assert message["status"] == "failed"
    assert "secret" not in message


def test_failure_inside_transaction_rolls_back_inventory(db, raw):
    class BrokenIntel:
        calls = 0

        def lookup(self, cve, as_of):
            self.calls += 1
            if self.calls == 2:
                raise ValueError("fake-secret-in-error")
            return SyntheticIntel().lookup(cve, as_of)

    run = ingest(db, Records([raw]), BrokenIntel(), AS_OF)
    assert run.status == "failed"
    assert "fake-secret" not in run.model_dump_json()
    assert db.summary().assets == 0
    assert db.summary().findings == 0


def test_record_bound_fails_without_partial_data(db, raw):
    run = ingest(db, Records([raw, raw]), SyntheticIntel(), AS_OF, max_records=1)
    assert run.status == "failed" and db.summary().findings == 0


def test_older_observation_keeps_newer_cvss_and_earliest_first_seen(db, raw):
    ingest(db, Records([raw]), SyntheticIntel(), AS_OF)
    raw["first_seen"] = "2025-01-01"
    raw["last_seen"] = "2025-12-01"
    raw["cvss"] = 2.0
    ingest(db, Records([raw]), SyntheticIntel(), AS_OF)
    observation = db.findings().items[0].observation
    assert observation.first_seen == date(2025, 1, 1)
    assert observation.last_seen == AS_OF
    assert observation.cvss == 10


def test_shared_asset_context_refreshes_existing_findings(db, raw):
    second = json.loads(json.dumps(raw))
    second["port"] = 8443
    ingest(db, Records([raw, second]), SyntheticIntel(), AS_OF)
    raw["asset"]["criticality"] = 1
    raw["asset"]["environment"] = "development"
    ingest(db, Records([raw]), SyntheticIntel(), AS_OF)
    findings = db.findings().items
    assert all(f.observation.asset.criticality == 1 for f in findings)
    assert all(f.priority.score == 79.55 for f in findings)


def test_non_regressing_assessment_and_empty_snapshot(populated):
    failed = ingest(populated, Records([]), SyntheticIntel(), date(2026, 1, 14))
    assert failed.status == "failed"
    assert populated.findings().items[0].priority.assessed_on == AS_OF
    # Absence from an export does not imply remediation or delete retained evidence.
    ingest(populated, Records([]), SyntheticIntel(), AS_OF)
    assert populated.summary().findings == 7


def test_setup_idempotent_newer_schema_and_escaped_path(tmp_path):
    db = Database(tmp_path / "hash#question?.db")
    db.setup()
    db.setup()
    assert db.health()
    with db.connect() as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(ValueError, match="newer"):
        db.setup()


def test_sql_injection_is_literal_filter(populated):
    page = populated.findings(asset="x' OR 1=1 --")
    assert page.total == 0
    assert populated.summary().findings == 7


def test_finding_detail_missing_and_inventory_page(populated, raw):
    finding_id = Observation.model_validate(raw).id
    assert populated.finding(finding_id).priority.score == 99.55
    assert populated.finding("missing") is None
    page = populated.vulnerabilities(limit=2, offset=1)
    assert page.total == 5 and len(page.items) == 2
