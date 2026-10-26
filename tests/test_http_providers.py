from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from vuln_intelligence.config import Settings
from vuln_intelligence.http import JsonHTTP, ProviderError, retry_delay
from vuln_intelligence.providers import TenableScanner

JOB = "12345678-1234-5678-1234-567812345678"


def test_rate_limit_then_server_failure_then_success():
    statuses, sleeps, requests = iter([429, 503, 200]), [], []

    def handler(request):
        requests.append(request)
        return httpx.Response(next(statuses), headers={"Retry-After": "2"}, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert JsonHTTP(client, sleep=sleeps.append).request(
            "GET", "https://api.first.org/test"
        ) == {"ok": True}
    assert sleeps == [2, 2]
    assert len(requests) == 3
    assert requests[0].extensions["timeout"]["connect"] == 5


@pytest.mark.parametrize("header", ["garbage", "nan", "inf", "", None])
def test_retry_header_fallback(header):
    assert retry_delay(header, 1) == 2


def test_retry_delay_bounds_and_http_date():
    assert retry_delay("99999", 0) == 30
    assert retry_delay("-4", 0) == 0
    assert 0 <= retry_delay(format_datetime(datetime.now(UTC) + timedelta(seconds=10)), 0) <= 10


@pytest.mark.parametrize("method,expected", [("GET", 3), ("POST", 1)])
def test_network_retries_are_bounded_and_post_not_replayed(method, expected):
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("secret should never escape", request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ProviderError, match="^upstream network request failed$"),
    ):
        JsonHTTP(client, sleep=lambda _: None).request(method, "https://cloud.tenable.com/test")
    assert len(calls) == expected


@pytest.mark.parametrize("status", [401, 403, 429, 500, 302])
def test_errors_are_sanitized(status):
    with (
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    status, text="SECRET", headers={"Location": "https://evil.test"}
                )
            )
        ) as client,
        pytest.raises(ProviderError, match=f"^upstream HTTP {status}$"),
    ):
        JsonHTTP(client, sleep=lambda _: None).request("GET", "https://api.first.org/test")


@pytest.mark.parametrize(
    "url", ["http://api.first.org/test", "https://evil.test", "https://user:pass@api.first.org"]
)
def test_disallowed_urls(url):
    with httpx.Client() as client, pytest.raises(ProviderError, match="allowlisted"):
        JsonHTTP(client).request("GET", url)


def test_invalid_json_oversize_and_bounds():
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="invalid"))
    ) as client:
        with pytest.raises(ProviderError, match="invalid JSON"):
            JsonHTTP(client).request("GET", "https://api.first.org")
        with pytest.raises(ProviderError, match="byte limit"):
            JsonHTTP(client, max_bytes=2).request("GET", "https://api.first.org")
        with pytest.raises(ValueError):
            JsonHTTP(client, attempts=10)


def live_settings():
    return Settings(
        live_enabled=True, tenable_access_key="fake-access", tenable_secret_key="fake-secret"
    )


def test_tenable_export_chunk_pagination_and_malformed_record(tenable_raw):
    paths, polls = [], []

    def handler(request):
        paths.append(request.url.path)
        assert "accessKey=fake-access" in request.headers["X-ApiKeys"]
        if request.method == "POST":
            return httpx.Response(200, json={"export_uuid": JOB})
        if request.url.path.endswith("status"):
            polls.append(1)
            return httpx.Response(
                200,
                json={
                    "status": "PROCESSING" if len(polls) == 1 else "FINISHED",
                    "chunks_available": [3, 1, 3],
                },
            )
        return httpx.Response(200, json=[tenable_raw, {}])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        scanner = TenableScanner(live_settings(), JsonHTTP(client), sleep=lambda _: None)
        records = list(scanner.records())
    assert len(records) == 4
    assert records[1] == {"invalid_record": True}
    assert paths[-2:] == [f"/vulns/export/{JOB}/chunks/1", f"/vulns/export/{JOB}/chunks/3"]


@pytest.mark.parametrize(
    "payload,match",
    [
        ({"status": "ERROR"}, "did not complete"),
        ({"status": "PROCESSING"}, "polling limit"),
        ({"status": "FINISHED", "chunks_available": [-1]}, "chunk identifier"),
        ({"oops": True}, "invalid Tenable export response"),
    ],
)
def test_tenable_export_failures(payload, match):
    def handler(request):
        return httpx.Response(
            200, json={"export_uuid": JOB} if request.method == "POST" else payload
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        scanner = TenableScanner(
            live_settings(), JsonHTTP(client), sleep=lambda _: None, max_polls=1
        )
        with pytest.raises(ProviderError, match=match):
            list(scanner.records())


def test_invalid_tenable_chunk():
    def handler(request):
        if request.method == "POST":
            payload = {"export_uuid": JOB}
        elif request.url.path.endswith("status"):
            payload = {"status": "FINISHED", "chunks_available": [1]}
        else:
            payload = {"invalid": True}
        return httpx.Response(200, json=payload)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ProviderError, match="invalid Tenable chunk"),
    ):
        list(TenableScanner(live_settings(), JsonHTTP(client)).records())


def test_tenable_configuration_gates():
    with httpx.Client() as client:
        with pytest.raises(ValueError, match="live integrations"):
            TenableScanner(Settings(), JsonHTTP(client))
        with pytest.raises(ValueError, match="keys are required"):
            TenableScanner(Settings(live_enabled=True), JsonHTTP(client))
        with pytest.raises(ValueError, match="poll limit"):
            TenableScanner(live_settings(), JsonHTTP(client), max_polls=0)
