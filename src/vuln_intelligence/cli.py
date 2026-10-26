"""Scheduled ingestion entry point and localhost-only demonstration server."""

import argparse
import json
import logging
import sqlite3
import sys
from datetime import date
from pathlib import Path

import httpx
import uvicorn
from pydantic import TypeAdapter, ValidationError

from .api import create_app
from .config import Settings
from .db import Database
from .enrichment import LiveIntel, SyntheticIntel
from .http import JsonHTTP
from .ingest import ingest
from .models import Context, Weights
from .providers import SyntheticScanner, TenableScanner
from .reports import write_report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Offline-first vulnerability intelligence demo")
    result.add_argument("--db", type=Path, help="SQLite path; defaults to VULN_DB or data/vuln.db")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create or migrate schema")
    ingestion = sub.add_parser("ingest", help="Ingest once; schedule this command externally")
    ingestion.add_argument("--scanner", choices=["synthetic", "tenable"], default="synthetic")
    ingestion.add_argument("--intel", choices=["synthetic", "live"], default="synthetic")
    ingestion.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    ingestion.add_argument("--weights", type=Path, help="JSON object; weights must sum to 100")
    ingestion.add_argument(
        "--context", type=Path, help="JSON asset UUID -> criticality/environment"
    )
    report = sub.add_parser("report")
    report.add_argument("--as-of", type=date.fromisoformat, required=True)
    report.add_argument("--out", type=Path, default=Path("reports"))
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # HTTPX's default INFO records include request URLs; keep provider traffic out of logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = Settings.from_env()
        db = Database(args.db or settings.database)
        if args.command == "init":
            db.setup()
        elif args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("invalid port")
            uvicorn.run(create_app(db), host="127.0.0.1", port=args.port, access_log=False)
        elif args.command == "report":
            paths = write_report(db, args.out, args.as_of)
            print(json.dumps({"reports": [str(path) for path in paths]}))
        else:
            weights = (
                Weights.model_validate_json(args.weights.read_text()) if args.weights else Weights()
            )
            contexts = (
                TypeAdapter(dict[str, Context]).validate_json(args.context.read_text())
                if args.context
                else {}
            )
            if args.scanner == "tenable" and args.intel == "synthetic":
                raise ValueError(
                    "Tenable ingestion requires --intel live to avoid mixing synthetic intelligence"
                )
            with httpx.Client(trust_env=False) as client:
                http = JsonHTTP(client)
                scanner = (
                    TenableScanner(settings, http, contexts)
                    if args.scanner == "tenable"
                    else SyntheticScanner()
                )
                intel = LiveIntel(settings, http) if args.intel == "live" else SyntheticIntel()
                db.setup()
                run = ingest(db, scanner, intel, args.as_of, weights)
                print(run.model_dump_json())
                return {"completed": 0, "partial": 2, "failed": 1}[run.status]
        return 0
    except (ValueError, ValidationError, OSError, sqlite3.Error) as exc:
        # Validation errors may contain secret-bearing inputs. Display only the exception class.
        print(
            json.dumps(
                {"error": "Invalid configuration or unavailable file", "type": type(exc).__name__}
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
