"""Scanner protocol, deterministic fixture provider, and optional Tenable VM export adapter."""

import json
import time
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime
from importlib.resources import files
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, Field, ValidationError

from .config import Settings
from .http import JsonHTTP, ProviderError
from .models import Asset, Context, Observation, Vulnerability


class Scanner(Protocol):
    name: str

    def records(self) -> Iterable[dict]: ...


def fixture(name: str):
    return json.loads(files("vuln_intelligence.data").joinpath(name).read_text())


class SyntheticScanner:
    name = "synthetic"

    def __init__(self, page_size: int = 2):
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        self.page_size = page_size

    def records(self) -> Iterable[dict]:
        records = fixture("findings.json")
        for offset in range(0, len(records), self.page_size):
            yield from records[offset : offset + self.page_size]


class ExportJob(BaseModel):
    export_uuid: UUID


class ExportStatus(BaseModel):
    status: str
    chunks_available: list[int] = Field(default_factory=list, max_length=1000)


def scanner_date(value) -> date:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC).date()
    return datetime.fromisoformat(value.replace("Z", "+00:00")).date()


def normalize_tenable(record: dict, contexts: dict[str, Context]) -> list[dict]:
    """One normalized observation per CVE; non-CVE plugins retain a plugin identifier."""
    asset, plugin = record["asset"], record["plugin"]
    asset_id = str(asset["uuid"])
    context = contexts.get(asset_id)
    normalized_asset = Asset(
        id=asset_id,
        hostname=asset.get("hostname") or asset_id,
        criticality=context.criticality if context else 3,
        environment=context.environment if context else "unknown",
        context_source="inventory" if context else "default-unclassified",
    )
    cves = plugin.get("cve") or [None]
    if not isinstance(cves, list) or len(cves) > 1000:
        raise ValueError("invalid CVE list")
    cvss = plugin.get("cvss3_base_score")
    if cvss is None:
        cvss = plugin.get("cvss_base_score")
    return [
        Observation(
            source="tenable",
            asset=normalized_asset,
            vulnerability=Vulnerability(
                id=cve or f"tenable-plugin-{plugin['id']}",
                cve=cve,
                title=plugin["name"],
                remediation=plugin.get("solution")
                or "Review vendor guidance and validate remediation.",
            ),
            cvss=cvss,
            port=record.get("port", {}).get("port", 0),
            protocol=record.get("port", {}).get("protocol", "tcp").lower(),
            first_seen=scanner_date(record["first_found"]),
            last_seen=scanner_date(record["last_found"]),
        ).model_dump(mode="json")
        for cve in sorted(set(cves), key=str)
    ]


class TenableScanner:
    name = "tenable"

    def __init__(
        self,
        settings: Settings,
        http: JsonHTTP,
        contexts: dict[str, Context] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_polls: int = 30,
    ):
        settings.require_live()
        if not settings.tenable_access_key or not settings.tenable_secret_key:
            raise ValueError("Tenable access and secret keys are required")
        if not 1 <= max_polls <= 120:
            raise ValueError("invalid poll limit")
        self.http, self.contexts, self.sleep, self.max_polls = (
            http,
            contexts or {},
            sleep,
            max_polls,
        )
        self.headers = {
            "X-ApiKeys": (
                f"accessKey={settings.tenable_access_key.get_secret_value()};"
                f"secretKey={settings.tenable_secret_key.get_secret_value()}"
            )
        }

    def records(self) -> Iterable[dict]:
        base = "https://cloud.tenable.com/vulns/export"
        try:
            job = ExportJob.model_validate(
                self.http.request(
                    "POST",
                    base,
                    headers=self.headers,
                    json={"num_assets": 500, "filters": {"state": ["OPEN", "REOPENED"]}},
                )
            )
            for _ in range(self.max_polls):
                status = ExportStatus.model_validate(
                    self.http.request(
                        "GET",
                        f"{base}/{job.export_uuid}/status",
                        headers=self.headers,
                    )
                )
                if status.status == "FINISHED":
                    break
                if status.status not in {"PROCESSING", "QUEUED"}:
                    raise ProviderError("Tenable export did not complete successfully")
                self.sleep(2)
            else:
                raise ProviderError("Tenable export polling limit exceeded")
            for chunk in sorted(set(status.chunks_available)):
                if chunk < 1:
                    raise ProviderError("invalid Tenable chunk identifier")
                rows = self.http.request(
                    "GET",
                    f"{base}/{job.export_uuid}/chunks/{chunk}",
                    headers=self.headers,
                )
                if not isinstance(rows, list) or len(rows) > 100_000:
                    raise ProviderError("invalid Tenable chunk")
                for row in rows:
                    try:
                        yield from normalize_tenable(row, self.contexts)
                    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
                        # Count rejected records without persisting raw data.
                        yield {"invalid_record": True}
        except (ValidationError, TypeError) as exc:
            raise ProviderError("invalid Tenable export response") from exc
