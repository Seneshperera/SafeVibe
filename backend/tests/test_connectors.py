"""Failure-injection tests: a connector failure must never become a verdict (FR-06-005)."""
import httpx
import pytest

from app.connectors.base import MALICIOUS, NO_MATCH, NOT_CONFIGURED, OK, SUSPICIOUS, UNAVAILABLE
from app.connectors.privacy import privacy_filter_url
from app.connectors.safebrowsing import SafeBrowsingConnector
from app.connectors.virustotal import VirusTotalConnector

URL = "https://evil.example.com/login?token=SECRET123"


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def sb(handler, **kw):
    return SafeBrowsingConnector("key", client=client(handler), **kw)


def vt(handler, **kw):
    return VirusTotalConnector("key", client=client(handler), **kw)


def test_privacy_filter_removes_query_and_userinfo():  # FR-01-007
    assert privacy_filter_url("https://user:pw@a.com:8443/p?token=1#f") == "https://a.com:8443/p"


def test_not_configured_makes_no_call():  # FR-06-001
    def boom(req): raise AssertionError("must not call")
    r = SafeBrowsingConnector("", client=client(boom)).check_url(URL)
    assert r.status == NOT_CONFIGURED and r.verdict is None


def test_secret_query_never_sent():
    seen = {}
    def h(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={})
    sb(h).check_url(URL)
    assert "SECRET123" not in seen["body"]


def test_sb_match_and_no_match():
    r = sb(lambda q: httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})).check_url(URL)
    assert (r.status, r.verdict) == (OK, MALICIOUS) and r.details["threat_types"] == ["SOCIAL_ENGINEERING"]
    r = sb(lambda q: httpx.Response(200, json={})).check_url(URL)
    assert (r.status, r.verdict) == (OK, NO_MATCH)


def _raise(exc):
    def h(req): raise exc
    return h


@pytest.mark.parametrize("handler,expected", [
    (_raise(httpx.ConnectTimeout("t")), "timed out"),
    (_raise(httpx.ConnectError("down")), "Network error"),
    (lambda q: httpx.Response(500), "HTTP 500"),
    (lambda q: httpx.Response(429), "quota"),
    (lambda q: httpx.Response(403), "API key"),
    (lambda q: httpx.Response(200, text="<html>not json"), "Unexpected response"),
    (lambda q: httpx.Response(200, json=["weird"]), "Unexpected response"),
])
@pytest.mark.parametrize("make", [sb, vt])
def test_failures_are_unavailable_never_a_verdict(make, handler, expected):
    r = make(handler).check_url(URL)
    assert r.status == UNAVAILABLE and r.verdict is None and expected in r.note


def test_vt_verdict_levels():
    def stats(m, s):
        return lambda q: httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats":
                                        {"malicious": m, "suspicious": s, "harmless": 50}}}})
    assert vt(stats(5, 0)).check_url(URL).verdict == MALICIOUS
    assert vt(stats(1, 0)).check_url(URL).verdict == SUSPICIOUS
    assert vt(stats(0, 0)).check_url(URL).verdict == NO_MATCH


def test_vt_404_is_unknown_not_clean_or_bad():
    r = vt(lambda q: httpx.Response(404)).check_url(URL)
    assert r.status == OK and r.verdict == NO_MATCH and "not previously" in r.note


def test_cache_prevents_second_call():  # FR-06-004
    calls = []
    def h(req):
        calls.append(1); return httpx.Response(200, json={})
    c = sb(h)
    c.check_url(URL); r2 = c.check_url(URL)
    assert len(calls) == 1 and r2.from_cache


def test_failures_are_not_cached():
    calls = []
    def h(req):
        calls.append(1); return httpx.Response(500)
    c = sb(h)
    c.check_url(URL); c.check_url(URL)
    assert len(calls) == 2


def test_rate_limit():  # FR-06-004
    t = [0.0]
    c = sb(lambda q: httpx.Response(200, json={}), requests_per_minute=2, cache_ttl=0, clock=lambda: t[0])
    assert c.check_url("https://a.com/1").status == OK
    assert c.check_url("https://a.com/2").status == OK
    r = c.check_url("https://a.com/3")
    assert r.status == UNAVAILABLE and "rate limit" in r.note
    t[0] = 61
    assert c.check_url("https://a.com/4").status == OK
