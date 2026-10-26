"""SQLite repository: versioned setup, parameterized queries, atomic publication."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from .models import Finding, IngestionRun, Page, Severity, Summary, Vulnerability

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY, payload TEXT NOT NULL, observed_on TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY, payload TEXT NOT NULL, observed_on TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
    severity TEXT NOT NULL,
    priority REAL NOT NULL CHECK(priority >= 0 AND priority <= 100),
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_priority ON findings(priority DESC, id);
CREATE INDEX IF NOT EXISTS findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS enrichment (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id), payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingestion_runs (
    id TEXT PRIMARY KEY, started_at TEXT NOT NULL, payload TEXT NOT NULL
);
PRAGMA user_version = 1;
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    @contextmanager
    def connect(self, readonly: bool = False):
        uri = f"file:{quote(str(self.path.resolve()), safe='/')}?mode=ro"
        connection = sqlite3.connect(uri if readonly else self.path, uri=readonly, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if readonly:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def setup(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        self.path.chmod(0o600)
        with self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise ValueError("database schema is newer than this application")
            connection.execute("PRAGMA journal_mode=WAL")
            if version == 0:
                connection.executescript(SCHEMA)

    @staticmethod
    def save_run(connection: sqlite3.Connection, run: IngestionRun) -> None:
        connection.execute(
            "INSERT INTO ingestion_runs VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            (run.id, run.started_at.isoformat(), run.model_dump_json()),
        )

    @staticmethod
    def save_finding(connection: sqlite3.Connection, finding: Finding) -> None:
        observation = finding.observation
        connection.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, "
            "priority=excluded.priority, payload=excluded.payload",
            (
                finding.id,
                observation.asset.id,
                observation.vulnerability.id,
                finding.severity,
                finding.priority.score,
                finding.model_dump_json(),
            ),
        )
        connection.execute(
            "INSERT INTO enrichment VALUES (?, ?) ON CONFLICT(finding_id) "
            "DO UPDATE SET payload=excluded.payload",
            (finding.id, finding.intelligence.model_dump_json()),
        )

    @staticmethod
    def all_findings(connection: sqlite3.Connection) -> dict[str, Finding]:
        return {
            row["id"]: Finding.model_validate_json(row["payload"])
            for row in connection.execute("SELECT id, payload FROM findings")
        }

    def health(self) -> bool:
        with self.connect(readonly=True) as connection:
            return connection.execute("PRAGMA user_version").fetchone()[0] == 1

    def findings(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Severity | None = None,
        asset: str | None = None,
        min_priority: float = 0,
    ) -> Page[Finding]:
        # SQL structure is static; every untrusted value is bound separately.
        values = (min_priority, severity, severity, asset, asset)
        with self.connect(readonly=True) as connection:
            total = connection.execute(
                "SELECT count(*) FROM findings WHERE priority >= ? "
                "AND (? IS NULL OR severity=?) AND (? IS NULL OR asset_id=?)",
                values,
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT payload FROM findings WHERE priority >= ? "
                "AND (? IS NULL OR severity=?) AND (? IS NULL OR asset_id=?) "
                "ORDER BY priority DESC, id LIMIT ? OFFSET ?",
                (*values, limit, offset),
            )
            return Page[Finding](
                items=[Finding.model_validate_json(row[0]) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def finding(self, finding_id: str) -> Finding | None:
        with self.connect(readonly=True) as connection:
            row = connection.execute(
                "SELECT payload FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            return Finding.model_validate_json(row[0]) if row else None

    def vulnerabilities(self, limit: int = 50, offset: int = 0) -> Page[Vulnerability]:
        with self.connect(readonly=True) as connection:
            total = connection.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0]
            rows = connection.execute(
                "SELECT payload FROM vulnerabilities ORDER BY id LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return Page[Vulnerability](
                items=[Vulnerability.model_validate_json(row[0]) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def runs(self, limit: int = 50, offset: int = 0) -> Page[IngestionRun]:
        with self.connect(readonly=True) as connection:
            total = connection.execute("SELECT count(*) FROM ingestion_runs").fetchone()[0]
            rows = connection.execute(
                "SELECT payload FROM ingestion_runs ORDER BY started_at DESC, id LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return Page[IngestionRun](
                items=[IngestionRun.model_validate_json(row[0]) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def summary(self) -> Summary:
        with self.connect(readonly=True) as connection:
            return self.summary_in(connection)

    @staticmethod
    def summary_in(connection: sqlite3.Connection) -> Summary:
        findings = list(Database.all_findings(connection).values())
        return Summary(
            assets=connection.execute("SELECT count(*) FROM assets").fetchone()[0],
            vulnerabilities=connection.execute("SELECT count(*) FROM vulnerabilities").fetchone()[
                0
            ],
            findings=len(findings),
            kev_matches=sum(f.intelligence.kev is True for f in findings),
            incomplete_enrichment=sum(
                f.intelligence.kev is None or f.intelligence.epss is None for f in findings
            ),
            by_severity={
                level.value: sum(f.severity == level for f in findings) for level in Severity
            },
        )


def upsert_inventory(connection: sqlite3.Connection, finding: Finding) -> None:
    observation = finding.observation
    for statement, record in (
        (
            "INSERT INTO assets VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "payload=excluded.payload, observed_on=excluded.observed_on "
            "WHERE excluded.observed_on >= assets.observed_on",
            observation.asset,
        ),
        (
            "INSERT INTO vulnerabilities VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "payload=excluded.payload, observed_on=excluded.observed_on "
            "WHERE excluded.observed_on >= vulnerabilities.observed_on",
            observation.vulnerability,
        ),
    ):
        connection.execute(
            statement, (record.id, record.model_dump_json(), str(observation.last_seen))
        )


def current_inventory(connection: sqlite3.Connection) -> tuple[dict, dict]:
    assets = {
        row[0]: json.loads(row[1]) for row in connection.execute("SELECT id, payload FROM assets")
    }
    vulns = {
        row[0]: json.loads(row[1])
        for row in connection.execute("SELECT id, payload FROM vulnerabilities")
    }
    return assets, vulns
