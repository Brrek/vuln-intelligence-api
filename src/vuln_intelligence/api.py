"""Read-only analysis API. Run setup/ingestion separately through the CLI."""

import sqlite3
from typing import Annotated
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import Settings
from .db import Database
from .models import Finding, IngestionRun, Model, Page, Severity, Summary, Vulnerability

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


class Health(Model):
    status: str
    schema_version: int


class Error(Model):
    detail: str


def create_app(database: Database | None = None) -> FastAPI:
    db = database or Database(Settings.from_env().database)
    app = FastAPI(
        title="Vulnerability Intelligence API",
        version="0.1.0",
        description="Offline-first portfolio demonstration. Read-only; not production hardened.",
        responses={503: {"model": Error}, 422: {"model": Error}},
    )

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return JSONResponse(
            status_code=503, content={"detail": "Database unavailable; run init/ingest."}
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            status_code=422, content={"detail": "Invalid path or query parameters."}
        )

    @app.get("/health", response_model=Health)
    def health():
        if not db.health():
            raise HTTPException(503, "Unsupported database schema; run setup.")
        return Health(status="ok", schema_version=1)

    @app.get("/findings", response_model=Page[Finding])
    def findings(
        limit: Limit = 50,
        offset: Offset = 0,
        severity: Severity | None = None,
        asset: Annotated[str | None, Query(max_length=200)] = None,
        min_priority: Annotated[float, Query(ge=0, le=100, allow_inf_nan=False)] = 0,
    ):
        return db.findings(limit, offset, severity, asset, min_priority)

    @app.get("/findings/{finding_id}", response_model=Finding, responses={404: {"model": Error}})
    def finding(finding_id: UUID):
        result = db.finding(str(finding_id))
        if result is None:
            raise HTTPException(404, "Finding not found.")
        return result

    @app.get("/vulnerabilities", response_model=Page[Vulnerability])
    def vulnerabilities(limit: Limit = 50, offset: Offset = 0):
        return db.vulnerabilities(limit, offset)

    @app.get("/priorities", response_model=Page[Finding])
    def priorities(limit: Limit = 10, offset: Offset = 0):
        return db.findings(limit, offset)

    @app.get("/ingestions", response_model=Page[IngestionRun])
    def ingestions(limit: Limit = 50, offset: Offset = 0):
        return db.runs(limit, offset)

    @app.get("/ingestions/latest", response_model=IngestionRun, responses={404: {"model": Error}})
    def latest_ingestion():
        runs = db.runs(1)
        if not runs.items:
            raise HTTPException(404, "No ingestions recorded.")
        return runs.items[0]

    @app.get("/stats", response_model=Summary)
    def stats():
        return db.summary()

    return app
