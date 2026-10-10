import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.connectors.safebrowsing import SafeBrowsingConnector
from app.core.config import Settings
from app.db import models as m
from app.db.models import Base
from app.db.session import make_engine, normalize_url
from app.main import app
from app.models.schemas import AnalysisRequestIn, FeedbackIn
from app.services.pipeline import Pipeline
from app.services.store import SqlStore, scrub

cfg = Settings()
TEXT = "URGENT: your account is suspended, verify your password at http://paypal.verify-now.example.top/login"


def fresh():
    e = make_engine("sqlite://")
    Base.metadata.create_all(e)
    return SqlStore(e)


def count(store, table):
    with store.Session() as s:
        return s.scalar(select(func.count()).select_from(table))


def analysis(**kw):
    return Pipeline(cfg, connectors=[]).run(AnalysisRequestIn(text=TEXT, urls=["HTTP://Example.COM/a#x"], **kw))


def test_url_normalisation_for_hosted_postgres():
    assert normalize_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_url("postgresql://u:p@h/db?sslmode=require") == "postgresql+psycopg://u:p@h/db?sslmode=require"
    assert normalize_url("sqlite:///x.db") == "sqlite:///x.db"


def test_roundtrip_is_lossless():  # FR-09-001: result can be reconstructed
    st, r = fresh(), analysis()
    st.save(r, duration_ms=12.3)
    got = st.get(r.request_id)
    assert got.model_dump(mode="json") == r.model_dump(mode="json")
    assert got.artefacts[1].original == "HTTP://Example.COM/a#x"      # original kept (FR-01-002)
    assert got.artefacts[1].canonical == "http://example.com/a"


def test_trace_tables_populated():
    st, r = fresh(), analysis()
    st.save(r)
    assert count(st, m.EvidenceItemRow) == len(r.evidence)
    assert count(st, m.ExplanationRow) == 2 * len(r.evidence)          # technical + plain
    assert count(st, m.SafeActionRow) == len(r.safe_actions)


def test_audit_event_records_versions_status_and_timing():
    st, r = fresh(), analysis()
    st.save(r, duration_ms=5.0)
    ev = st.audit_events()[0]
    assert ev["event_type"] == "analysis_created" and ev["rule_version"] == "rules_v1/weights_v1"
    assert ev["detail"]["duration_ms"] == 5.0 and ev["detail"]["score"] == r.assessment.score


def test_connector_failure_is_audited_not_turned_into_result():  # FR-09-005
    def boom(req): raise httpx.ConnectTimeout("t")
    c = SafeBrowsingConnector("key", client=httpx.Client(transport=httpx.MockTransport(boom)))
    r = Pipeline(cfg, connectors=[c]).run(AnalysisRequestIn(urls=["https://example.org"], allow_external=True))
    st = fresh(); st.save(r)
    fails = st.audit_events(event_type="connector_failure")
    assert len(fails) == 1 and fails[0]["detail"]["connector"] == "safe_browsing"


def test_delete_removes_everything_but_content_free_audit():  # FR-09-003
    st, r = fresh(), analysis()
    st.save(r)
    st.add_feedback(r.request_id, FeedbackIn(rating=4, comment="clear"))
    assert st.delete(r.request_id) is True
    for t in (m.AnalysisRequestRow, m.InputArtefactRow, m.RiskAssessmentRow, m.EvidenceItemRow,
              m.ExplanationRow, m.SafeActionRow, m.FeedbackRow):
        assert count(st, t) == 0, t.__tablename__
    assert st.get(r.request_id) is None and st.delete(r.request_id) is False
    audit = st.audit_events()
    assert {"analysis_created", "analysis_deleted"} <= {e["event_type"] for e in audit}
    assert "verify your password" not in str(audit)                   # no submitted content in audit


def test_feedback_scrubs_identifiers():  # FR-09-002
    assert scrub("mail me at bob@example.com or +94 77 123 4567, saw http://x.com/a") == \
        "mail me at [email] or [number], saw [link]"
    st, r = fresh(), analysis()
    st.save(r)
    assert st.add_feedback(r.request_id, FeedbackIn(comment="call 0771234567", evaluation_context="task-1"))
    with st.Session() as s:
        fb = s.scalars(select(m.FeedbackRow)).one()
        assert fb.deidentified_response["comment"] == "call [number]" and fb.evaluation_context == "task-1"
    assert st.add_feedback("missing-id", FeedbackIn(rating=3)) is False


c = TestClient(app)


def test_feedback_endpoint_and_validation():
    rid = c.post("/api/v1/analyses", json={"text": "hello"}).json()["request_id"]
    assert c.post(f"/api/v1/analyses/{rid}/feedback", json={"rating": 5}).status_code == 201
    assert c.post(f"/api/v1/analyses/{rid}/feedback", json={}).status_code == 422
    assert c.post(f"/api/v1/analyses/{rid}/feedback", json={"rating": 9}).status_code == 422
    assert c.post("/api/v1/analyses/nope/feedback", json={"rating": 3}).status_code == 404


def test_get_returns_stored_analysis():
    j = c.post("/api/v1/analyses", json={"text": TEXT}).json()
    assert c.get(f"/api/v1/analyses/{j['request_id']}").json() == j


def test_audit_endpoint_access_control(monkeypatch):
    assert c.get("/api/v1/audit").status_code == 403                  # disabled until key is set
    monkeypatch.setattr(app.state.cfg, "operator_key", "s3cret")
    assert c.get("/api/v1/audit").status_code == 401
    assert c.get("/api/v1/audit", headers={"X-Operator-Key": "wrong"}).status_code == 401
    r = c.get("/api/v1/audit", headers={"X-Operator-Key": "s3cret"})
    assert r.status_code == 200 and isinstance(r.json(), list)
