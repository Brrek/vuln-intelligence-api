"""Independent KEV and EPSS enrichment with explicit provenance and unknown states."""

from datetime import date
from typing import Protocol

from pydantic import BaseModel, Field, ValidationError

from .config import Settings
from .http import JsonHTTP, ProviderError
from .models import CVE, Intel
from .providers import fixture


class Enricher(Protocol):
    def lookup(self, cve: str | None, as_of: date) -> Intel: ...


class SyntheticIntel:
    def __init__(self):
        self.data = fixture("intelligence.json")

    def lookup(self, cve: str | None, as_of: date) -> Intel:
        record = self.data["records"].get(cve, {})
        known = bool(record)
        return Intel(
            kev=record.get("kev"),
            epss=record.get("epss"),
            kev_source="synthetic",
            epss_source="synthetic",
            kev_date=self.data["date"] if known else None,
            epss_date=self.data["date"] if known else None,
            retrieved_on=as_of,
            warnings=[] if known else ["No synthetic intelligence for this vulnerability."],
        )


class KevEntry(BaseModel):
    cveID: CVE


class KevCatalog(BaseModel):
    dateReleased: str
    vulnerabilities: list[KevEntry]


class EpssEntry(BaseModel):
    cve: CVE
    epss: float = Field(ge=0, le=1, allow_inf_nan=False)
    date: date


class EpssResponse(BaseModel):
    data: list[EpssEntry]


class LiveIntel:
    def __init__(self, settings: Settings, http: JsonHTTP):
        settings.require_live()
        self.http = http
        self.kev: set[str] | None = None
        self.kev_date: date | None = None
        self.kev_loaded = False
        self.epss: dict[str, tuple[float | None, date | None]] = {}

    def lookup(self, cve: str | None, as_of: date) -> Intel:
        warnings = []
        if not self.kev_loaded:
            self.kev_loaded = True
            try:
                catalog = KevCatalog.model_validate(
                    self.http.request(
                        "GET",
                        "https://www.cisa.gov/sites/default/files/feeds/"
                        "known_exploited_vulnerabilities.json",
                    )
                )
                self.kev_date = date.fromisoformat(catalog.dateReleased[:10])
                if self.kev_date > as_of:
                    raise ValueError("future catalog")
                self.kev = {entry.cveID for entry in catalog.vulnerabilities}
            except (ProviderError, ValidationError, ValueError):
                self.kev = None
                self.kev_date = None
        if cve and cve not in self.epss:
            try:
                response = EpssResponse.model_validate(
                    self.http.request(
                        "GET",
                        "https://api.first.org/data/v1/epss",
                        params={"cve": cve},
                    )
                )
                match = next((entry for entry in response.data if entry.cve == cve), None)
                if match and match.date <= as_of:
                    self.epss[cve] = (match.epss, match.date)
                else:
                    self.epss[cve] = (None, None)
            except (ProviderError, ValidationError):
                self.epss[cve] = (None, None)
        epss, epss_date = self.epss.get(cve, (None, None))
        kev = cve in self.kev if cve and self.kev is not None else None
        if kev is None:
            warnings.append("KEV membership unavailable; not evidence of absence.")
        if epss is None:
            warnings.append("EPSS unavailable; not a zero probability.")
        for source, day in (("KEV", self.kev_date), ("EPSS", epss_date)):
            if day and (as_of - day).days > 7:
                warnings.append(f"{source} data is older than seven days.")
        return Intel(
            kev=kev,
            epss=epss,
            kev_source="cisa",
            epss_source="first",
            kev_date=self.kev_date,
            epss_date=epss_date,
            retrieved_on=as_of,
            warnings=warnings,
        )
