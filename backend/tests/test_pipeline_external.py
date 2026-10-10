import httpx
from fastapi.testclient import TestClient

from app.connectors.safebrowsing import SafeBrowsingConnector
from app.core.config import Settings
from app.models.schemas import AnalysisRequestIn
from app.services.pipeline import Pipeline

cfg = Settings()
URL = "https://example.org/page"


def pipe(handler):
    c = SafeBrowsingConnector("key", client=httpx.Client(transport=httpx.MockTransport(handler)))
    return Pipeline(cfg, connectors=[c])


def req(**kw):
    return AnalysisRequestIn(urls=[URL], allow_external=True, **kw)


def test_external_off_by_default_no_call():  # IR-COM-004
    def boom(r): raise AssertionError("no data may leave without opt-in")
    res = pipe(boom).run(AnalysisRequestIn(urls=[URL]))
    assert res.connectors[0].status == "skipped"


def test_malicious_hit_adds_provenance_and_floor():  # FR-06-003
    res = pipe(lambda r: httpx.Response(200, json={"matches": [{"threatType": "MALWARE"}]})).run(req())
    ext = [e for e in res.evidence if e.source_type == "external"]
    assert ext and {"source", "query_scope", "response_status", "queried_at"} <= set(ext[0].details)
    assert res.assessment.score >= 75 and res.assessment.tier.value == "Critical"
    assert res.assessment.adjustments or res.assessment.score >= 75


def test_timeout_does_not_change_verdict():  # FR-06-005 / FR-06-006
    def timeout(r): raise httpx.ConnectTimeout("t")
    base = pipe(timeout).run(AnalysisRequestIn(urls=[URL]))           # external not requested
    down = pipe(timeout).run(req())                                    # external requested but fails
    assert down.assessment.score == base.assessment.score
    assert not [e for e in down.evidence if e.source_type == "external"]
    assert down.connectors[0].status == "unavailable"
    assert down.status.value == "partial"
    assert any("NOT treated as safe or unsafe" in l for l in down.assessment.limitations)


def test_no_match_is_not_reassurance():
    res = pipe(lambda r: httpx.Response(200, json={})).run(req())
    assert res.connectors[0].status == "ok"
    assert any("not evidence of safety" in l for l in res.assessment.limitations)


def test_disclosure_endpoint():  # FR-06-002
    from app.main import app
    j = TestClient(app).get("/api/v1/disclosure").json()
    assert j["external_sharing_default"] == "off" and "query string" in j["what_is_shared"]
