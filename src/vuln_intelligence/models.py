"""Validated boundaries shared by scanner adapters, persistence, and the API."""

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")]
CVE = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,19}$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def severity_for(cvss: float | None) -> Severity:
    if cvss is None:
        return Severity.UNKNOWN
    if cvss >= 9:
        return Severity.CRITICAL
    if cvss >= 7:
        return Severity.HIGH
    if cvss >= 4:
        return Severity.MEDIUM
    return Severity.LOW if cvss > 0 else Severity.INFO


class Asset(Model):
    id: Identifier
    hostname: str = Field(min_length=1, max_length=253)
    criticality: int = Field(default=3, ge=1, le=5)
    environment: str = Field(
        default="unknown", pattern="^(production|staging|development|unknown)$"
    )
    context_source: str = Field(default="scanner", max_length=100)


class Vulnerability(Model):
    id: Identifier
    cve: CVE | None = None
    title: str = Field(min_length=1, max_length=500)
    remediation: str = Field(min_length=1, max_length=4000)


class Observation(Model):
    source: Identifier
    asset: Asset
    vulnerability: Vulnerability
    cvss: float | None = Field(default=None, ge=0, le=10)
    port: int = Field(default=0, ge=0, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|udp|none)$")
    first_seen: date
    last_seen: date

    @model_validator(mode="after")
    def ordered_dates(self):
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must not follow last_seen")
        return self

    @property
    def id(self) -> str:
        # UUID5 provides a deterministic identity, not a security or secrecy boundary.
        key = f"{self.source}/{self.asset.id}/{self.vulnerability.id}/{self.port}/{self.protocol}"
        return str(uuid5(NAMESPACE_URL, key))


class Intel(Model):
    kev: bool | None = None
    epss: float | None = Field(default=None, ge=0, le=1)
    kev_source: str
    epss_source: str
    kev_date: date | None = None
    epss_date: date | None = None
    retrieved_on: date
    warnings: list[str] = Field(default_factory=list)


class Risk(Model):
    score: float = Field(ge=0, le=100)
    assessed_on: date
    model: str = "demo-weighted-v1"
    contributions: dict[str, float]
    explanation: list[str]
    weights: dict[str, float]


class Finding(Model):
    id: str
    observation: Observation
    severity: Severity
    intelligence: Intel
    priority: Risk


class IngestionRun(Model):
    id: str
    source: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str = Field(pattern="^(running|completed|partial|failed)$")
    received: int = 0
    accepted: int = 0
    inserted: int = 0
    updated: int = 0
    duplicates: int = 0
    rejected: int = 0
    incomplete_enrichment: int = 0
    errors: list[str] = Field(default_factory=list)


class Page[T](Model):
    items: list[T]
    total: int
    limit: int
    offset: int


class Summary(Model):
    assets: int
    vulnerabilities: int
    findings: int
    kev_matches: int
    incomplete_enrichment: int
    by_severity: dict[str, int]


class Weights(Model):
    cvss: float = Field(default=30, ge=0)
    kev: float = Field(default=25, ge=0)
    epss: float = Field(default=15, ge=0)
    criticality: float = Field(default=15, ge=0)
    environment: float = Field(default=10, ge=0)
    age: float = Field(default=5, ge=0)

    @model_validator(mode="after")
    def total(self):
        if abs(sum(self.model_dump().values()) - 100) > 0.000001:
            raise ValueError("risk weights must sum to 100")
        return self


class Context(Model):
    criticality: int = Field(ge=1, le=5)
    environment: str = Field(pattern="^(production|staging|development|unknown)$")

    @field_validator("environment")
    @classmethod
    def strip_environment(cls, value: str) -> str:
        return value.strip()
