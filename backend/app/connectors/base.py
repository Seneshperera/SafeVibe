"""Connector framework: timeout, cache, rate limit, provenance, safe failure (SRS F6).

Rule: a failure is NEVER evidence. Timeouts, quota errors, bad responses and missing
keys all produce status != "ok" and no verdict (FR-06-005).
"""
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import httpx

from app.connectors.privacy import SCOPE, privacy_filter_url

OK, UNAVAILABLE, NOT_CONFIGURED = "ok", "unavailable", "not_configured"
MALICIOUS, SUSPICIOUS, NO_MATCH = "malicious", "suspicious", "no_match"


@dataclass
class ConnectorResult:
    name: str
    status: str                      # ok | unavailable | not_configured
    verdict: Optional[str] = None    # malicious | suspicious | no_match (only when status == ok)
    note: Optional[str] = None
    details: dict = field(default_factory=dict)
    query_scope: str = SCOPE
    queried_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    from_cache: bool = False


class Connector(ABC):
    name: str = "base"

    def __init__(self, api_key: str = "", *, client: Optional[httpx.Client] = None,
                 timeout: float = 5.0, cache_ttl: int = 3600, requests_per_minute: int = 60,
                 clock: Callable[[], float] = time.monotonic):
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.rpm = requests_per_minute
        self._clock = clock
        self._client = client
        self._cache: dict[str, tuple[float, ConnectorResult]] = {}
        self._calls: deque[float] = deque()

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, follow_redirects=False)
        return self._client

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _rate_limited(self) -> bool:
        now = self._clock()
        while self._calls and now - self._calls[0] >= 60:
            self._calls.popleft()
        if len(self._calls) >= self.rpm:
            return True
        self._calls.append(now)
        return False

    def check_url(self, canonical_url: str) -> ConnectorResult:
        if not self.configured:
            return ConnectorResult(self.name, NOT_CONFIGURED, note="No API key configured.")
        url = privacy_filter_url(canonical_url)          # only the filtered URL leaves the server
        hit = self._cache.get(url)
        if hit and self._clock() - hit[0] < self.cache_ttl:
            r = hit[1]
            return ConnectorResult(r.name, r.status, r.verdict, r.note, r.details,
                                   r.query_scope, r.queried_at, from_cache=True)
        if self._rate_limited():
            return ConnectorResult(self.name, UNAVAILABLE, note="Local rate limit reached.")
        try:
            result = self._query(url)
        except httpx.TimeoutException:
            return ConnectorResult(self.name, UNAVAILABLE, note="Request timed out.")
        except httpx.HTTPError as e:
            return ConnectorResult(self.name, UNAVAILABLE, note=f"Network error ({type(e).__name__}).")
        except (ValueError, KeyError, TypeError, AttributeError):
            return ConnectorResult(self.name, UNAVAILABLE, note="Unexpected response format.")
        if result.status == OK:                          # only cache real answers
            self._cache[url] = (self._clock(), result)
        return result

    @abstractmethod
    def _query(self, filtered_url: str) -> ConnectorResult:
        """Call the provider. May raise httpx errors / ValueError; base class handles them."""

    def _http_failure(self, resp: httpx.Response) -> Optional[ConnectorResult]:
        if resp.status_code == 429:
            return ConnectorResult(self.name, UNAVAILABLE, note="Provider quota exhausted.")
        if resp.status_code in (401, 403):
            return ConnectorResult(self.name, UNAVAILABLE, note="Provider rejected the API key.")
        if resp.status_code >= 400:
            return ConnectorResult(self.name, UNAVAILABLE, note=f"Provider error (HTTP {resp.status_code}).")
        return None
