from datetime import date

import httpx
import pytest

from vuln_intelligence.config import Settings
from vuln_intelligence.enrichment import LiveIntel, SyntheticIntel
from vuln_intelligence.http import JsonHTTP

from .conftest import AS_OF


def test_synthetic_membership_probability_and_unknown():
    provider = SyntheticIntel()
    assert provider.lookup("CVE-2021-44228", AS_OF).kev is True
    assert provider.lookup("CVE-2022-0778", AS_OF).kev is False
    assert provider.lookup("CVE-2021-44228", AS_OF).epss == 0.97
    assert provider.lookup("CVE-2000-0000", AS_OF).epss is None
    assert provider.lookup(None, AS_OF).warnings


def test_live_provenance_cache_and_absence():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.host == "www.cisa.gov":
            return httpx.Response(
                200,
                json={
                    "dateReleased": "2026-01-15T00:00:00Z",
                    "vulnerabilities": [{"cveID": "CVE-2021-44228"}],
                },
            )
        cve = request.url.params["cve"]
        return httpx.Response(
            200, json={"data": [{"cve": cve, "epss": "0.42", "date": "2026-01-14"}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = LiveIntel(Settings(live_enabled=True), JsonHTTP(client))
        first = provider.lookup("CVE-2021-44228", AS_OF)
        assert provider.lookup("CVE-2021-44228", AS_OF) == first
        other = provider.lookup("CVE-2022-0778", AS_OF)
    assert len(paths) == 3
    assert first.kev and first.epss == 0.42
    assert first.kev_source == "cisa" and first.epss_source == "first"
    assert other.kev is False
    assert first.warnings == []


def test_independent_provider_failure_and_stale_dates():
    def handler(request):
        if request.url.host == "www.cisa.gov":
            return httpx.Response(503)
        return httpx.Response(
            200, json={"data": [{"cve": "CVE-2021-44228", "epss": 0.8, "date": "2025-12-01"}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = LiveIntel(Settings(live_enabled=True), JsonHTTP(client, sleep=lambda _: None))
        intel = provider.lookup("CVE-2021-44228", AS_OF)
    assert intel.kev is None and intel.epss == 0.8
    assert len(intel.warnings) == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"data": []},
        {"data": [{"cve": "bad", "epss": 2}]},
        {"data": [{"cve": "CVE-2021-44228", "epss": 0.4, "date": "2099-01-01"}]},
    ],
)
def test_missing_malformed_and_future_intelligence(payload):
    def handler(request):
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"dateReleased": "2099-01-01", "vulnerabilities": []})
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        intel = LiveIntel(Settings(live_enabled=True), JsonHTTP(client)).lookup(
            "CVE-2021-44228", AS_OF
        )
    assert intel.kev is None and intel.epss is None
    assert intel.kev_date is None


def test_non_cve_never_calls_epss():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"dateReleased": "2025-12-01", "vulnerabilities": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        intel = LiveIntel(Settings(live_enabled=True), JsonHTTP(client)).lookup(None, AS_OF)
    assert len(requests) == 1
    assert len(intel.warnings) == 3
    assert intel.kev_date == date(2025, 12, 1)


def test_live_gate():
    with httpx.Client() as client, pytest.raises(ValueError):
        LiveIntel(Settings(), JsonHTTP(client))
