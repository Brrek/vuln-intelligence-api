"""Stage a bounded scanner snapshot, validate, then publish atomically."""

import json
import logging
import sqlite3
from datetime import UTC, date, datetime
from uuid import uuid4

from pydantic import ValidationError

from .db import Database, current_inventory, upsert_inventory
from .enrichment import Enricher
from .http import ProviderError
from .models import Asset, Finding, IngestionRun, Observation, Vulnerability, Weights, severity_for
from .providers import Scanner
from .risk import prioritize

logger = logging.getLogger(__name__)


def merge(old: Observation, new: Observation) -> Observation:
    # An older scan cannot overwrite newer evidence. Equal-date conflicts use higher CVSS.
    winner = max((new, old), key=lambda item: (item.last_seen, item.cvss or 0))
    return winner.model_copy(update={"first_seen": min(old.first_seen, new.first_seen)})


def ingest(
    db: Database,
    scanner: Scanner,
    enricher: Enricher,
    as_of: date,
    weights: Weights | None = None,
    max_records: int = 100_000,
) -> IngestionRun:
    weights = weights or Weights()
    run = IngestionRun(
        id=str(uuid4()), source=scanner.name, started_at=datetime.now(UTC), status="running"
    )
    with db.connect() as connection:
        Database.save_run(connection, run)
    staged: dict[str, Observation] = {}
    try:
        for raw in scanner.records():
            run.received += 1
            if run.received > max_records:
                raise ProviderError("ingestion record limit exceeded")
            try:
                observation = Observation.model_validate(raw)
                if observation.source != scanner.name or observation.last_seen > as_of:
                    raise ValueError("source or date mismatch")
            except (ValidationError, ValueError):
                run.rejected += 1
                continue
            run.accepted += 1
            if observation.id in staged:
                run.duplicates += 1
                observation = merge(staged[observation.id], observation)
            staged[observation.id] = observation
        with db.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = Database.all_findings(connection)
            if any(f.priority.assessed_on > as_of for f in existing.values()):
                raise ProviderError("assessment date predates stored assessment")
            for finding_id, observation in staged.items():
                previous = existing.get(finding_id)
                if previous:
                    observation = merge(previous.observation, observation)
                    run.updated += 1
                else:
                    run.inserted += 1
                intel = enricher.lookup(observation.vulnerability.cve, as_of)
                finding = Finding(
                    id=finding_id,
                    observation=observation,
                    intelligence=intel,
                    severity=severity_for(observation.cvss),
                    priority=prioritize(observation, intel, as_of, weights),
                )
                upsert_inventory(connection, finding)
                existing[finding_id] = finding
            assets, vulns = current_inventory(connection)
            # Refresh shared metadata and age on every stored finding, including retained evidence.
            for finding in existing.values():
                observation = finding.observation.model_copy(
                    update={
                        "asset": Asset.model_validate(assets[finding.observation.asset.id]),
                        "vulnerability": Vulnerability.model_validate(
                            vulns[finding.observation.vulnerability.id]
                        ),
                    }
                )
                intel = enricher.lookup(observation.vulnerability.cve, as_of)
                finding = finding.model_copy(
                    update={
                        "observation": observation,
                        "intelligence": intel,
                        "priority": prioritize(observation, intel, as_of, weights),
                    }
                )
                if intel.kev is None or intel.epss is None:
                    run.incomplete_enrichment += 1
                Database.save_finding(connection, finding)
            run.status = "partial" if run.rejected or run.incomplete_enrichment else "completed"
            if run.rejected:
                run.errors.append(
                    f"{run.rejected} records rejected by schema/source/date validation."
                )
            run.finished_at = datetime.now(UTC)
            Database.save_run(connection, run)
    except (ProviderError, sqlite3.Error, ValueError) as exc:
        # Do not log raw provider responses, validation inputs, URLs, or exception messages.
        run.status, run.inserted, run.updated = "failed", 0, 0
        run.errors.append(f"Ingestion failed ({type(exc).__name__}); staged changes rolled back.")
        run.finished_at = datetime.now(UTC)
        with db.connect() as connection:
            Database.save_run(connection, run)
    logger.info(
        json.dumps(
            {
                "event": "ingestion_finished",
                "run_id": run.id,
                "status": run.status,
                "received": run.received,
                "rejected": run.rejected,
            }
        )
    )
    return run
