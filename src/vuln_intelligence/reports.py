"""Reproducible JSON/Markdown reports with freshness, limitations, and actionable evidence."""

import html
import json
from collections import defaultdict
from datetime import date
from pathlib import Path

from .db import Database
from .models import IngestionRun


def build_report(db: Database, as_of: date) -> dict:
    with db.connect(readonly=True) as connection:
        findings = sorted(
            Database.all_findings(connection).values(), key=lambda f: (-f.priority.score, f.id)
        )
        summary = Database.summary_in(connection)
        history = [
            IngestionRun.model_validate_json(row[0])
            for row in connection.execute("SELECT payload FROM ingestion_runs")
        ]
    if any(f.priority.assessed_on != as_of for f in findings):
        raise ValueError("report date must match stored assessments; ingest for the requested date")
    assets = defaultdict(
        lambda: {"finding_count": 0, "total_priority": 0.0, "highest_priority": 0.0}
    )
    for finding in findings:
        item = assets[finding.observation.asset.id]
        item["finding_count"] += 1
        item["total_priority"] = round(item["total_priority"] + finding.priority.score, 2)
        item["highest_priority"] = max(item["highest_priority"], finding.priority.score)
    return {
        "as_of": str(as_of),
        "model_notice": (
            "Demonstration prioritization only; not a validated enterprise risk standard."
        ),
        "summary": summary.model_dump(),
        "urgent_findings": [f.model_dump(mode="json") for f in findings[:10]],
        "asset_exposure": [
            {"asset_id": key, **value}
            for key, value in sorted(
                assets.items(), key=lambda kv: (-kv[1]["total_priority"], kv[0])
            )
        ],
        "kev_matches": [f.id for f in findings if f.intelligence.kev is True],
        "recommendations": [
            {"finding_id": f.id, "action": f.observation.vulnerability.remediation}
            for f in findings
        ],
        "freshness": [
            {
                "finding_id": f.id,
                "last_seen": str(f.observation.last_seen),
                "observation_age_days": (as_of - f.observation.last_seen).days,
                "kev_date": str(f.intelligence.kev_date) if f.intelligence.kev_date else None,
                "epss_date": str(f.intelligence.epss_date) if f.intelligence.epss_date else None,
                "kev_source": f.intelligence.kev_source,
                "epss_source": f.intelligence.epss_source,
                "retrieved_on": str(f.intelligence.retrieved_on),
                "warnings": f.intelligence.warnings,
            }
            for f in findings
        ],
        "incomplete_enrichment": [
            f.id for f in findings if f.intelligence.kev is None or f.intelligence.epss is None
        ],
        # Audit timestamps and random run IDs remain in the API, not reproducible reports.
        "ingestion": {
            "runs": len(history),
            "failed_runs": sum(r.status == "failed" for r in history),
            "rejected_records": sum(r.rejected for r in history),
            "errors": sorted({error for run in history for error in run.errors}),
        },
    }


def safe_cell(value) -> str:
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("`", "&#96;")


def markdown(report: dict) -> str:
    lines = [
        "# Vulnerability intelligence report",
        "",
        f"As of: {report['as_of']}",
        "",
        report["model_notice"],
        "",
        "## Most urgent findings",
        "",
        "| Vulnerability | Asset | Severity | Score | KEV | EPSS |",
        "|---|---|---|---:|---|---:|",
    ]
    for finding in report["urgent_findings"]:
        observation, intel = finding["observation"], finding["intelligence"]
        cells = [
            observation["vulnerability"]["id"],
            observation["asset"]["id"],
            finding["severity"],
            finding["priority"]["score"],
            intel["kev"],
            intel["epss"],
        ]
        lines.append("| " + " | ".join(safe_cell(c) for c in cells) + " |")
    lines += ["", "## Asset exposure", "", "Sum of demonstration scores; not loss expectancy.", ""]
    for asset in report["asset_exposure"]:
        lines.append(
            f"- {safe_cell(asset['asset_id'])}: {asset['finding_count']} findings; "
            f"total {asset['total_priority']}; highest {asset['highest_priority']}."
        )
    lines += ["", "## KEV matches", ""] + [f"- {key}" for key in report["kev_matches"]]
    lines += ["", "## Remediation recommendations", ""]
    for item in report["recommendations"]:
        lines.append(f"- {item['finding_id']}: {safe_cell(item['action'])}")
    lines += ["", "## Freshness and provenance", ""]
    for item in report["freshness"]:
        lines.append(
            f"- {item['finding_id']}: last seen {item['last_seen']}; "
            f"observation age {item['observation_age_days']} days; "
            f"KEV {item['kev_source']} ({item['kev_date']}); "
            f"EPSS {item['epss_source']} ({item['epss_date']})."
        )
        lines.extend(f"  - {safe_cell(warning)}" for warning in item["warnings"])
    lines += [
        "",
        "## Ingestion errors and incomplete enrichment",
        "",
        f"Runs: {report['ingestion']['runs']}; failed: {report['ingestion']['failed_runs']}; "
        f"rejected records: {report['ingestion']['rejected_records']}.",
        "",
        f"Incomplete findings: {len(report['incomplete_enrichment'])}.",
    ]
    lines.extend(f"- {safe_cell(error)}" for error in report["ingestion"]["errors"])
    return "\n".join(lines) + "\n"


def write_report(db: Database, directory: Path, as_of: date) -> tuple[Path, Path]:
    report = build_report(db, as_of)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path, md_path = directory / "report.json", directory / "report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    md_path.write_text(markdown(report))
    return json_path, md_path
