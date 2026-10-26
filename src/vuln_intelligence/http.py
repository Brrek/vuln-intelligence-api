"""Bounded HTTP, fixed allowed origins, sanitized failures, and Retry-After support."""

import json
import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

ALLOWED_HOSTS = {"cloud.tenable.com", "www.cisa.gov", "api.first.org"}


class ProviderError(RuntimeError):
    """A sanitized upstream failure safe to persist or display."""


def retry_delay(value: str | None, attempt: int) -> float:
    delay = min(2**attempt, 30)
    if value:
        try:
            seconds = float(value)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                return delay
        if math.isfinite(seconds):
            return max(0, min(seconds, 30))
    return delay


class JsonHTTP:
    def __init__(
        self,
        client: httpx.Client,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = 3,
        max_bytes: int = 16_000_000,
    ):
        if not 1 <= attempts <= 5 or max_bytes < 1:
            raise ValueError("invalid HTTP bounds")
        self.client, self.sleep, self.attempts, self.max_bytes = client, sleep, attempts, max_bytes

    def request(self, method: str, url: str, **kwargs):
        target = httpx.URL(url)
        if target.scheme != "https" or target.host not in ALLOWED_HOSTS or target.userinfo:
            raise ProviderError("external URL is not allowlisted")
        for attempt in range(self.attempts):
            try:
                with self.client.stream(
                    method,
                    url,
                    timeout=httpx.Timeout(15, connect=5),
                    follow_redirects=False,
                    **kwargs,
                ) as response:
                    retryable = response.status_code == 429 or (
                        method == "GET" and response.status_code in {500, 502, 503, 504}
                    )
                    if retryable and attempt + 1 < self.attempts:
                        self.sleep(retry_delay(response.headers.get("Retry-After"), attempt))
                        continue
                    if not 200 <= response.status_code < 300:
                        raise ProviderError(f"upstream HTTP {response.status_code}")
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > self.max_bytes:
                            raise ProviderError("upstream response exceeds byte limit")
                    try:
                        return json.loads(data)
                    except (ValueError, UnicodeError) as exc:
                        raise ProviderError("upstream returned invalid JSON") from exc
            except httpx.RequestError as exc:
                # POST export creation is not retried after ambiguous network failures.
                if method == "POST" or attempt + 1 == self.attempts:
                    raise ProviderError("upstream network request failed") from exc
                self.sleep(retry_delay(None, attempt))
        raise ProviderError("upstream retries exhausted")  # pragma: no cover
