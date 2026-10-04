from fastapi.testclient import TestClient
from app.main import app

c = TestClient(app)


def test_health():
    assert c.get("/health").json()["status"] == "ok"


def test_scam_scores_high_and_has_disclaimer():
    r = c.post("/api/v1/analyses", json={
        "text": "URGENT: your bank account is suspended. Verify your password within 24 hours.",
        "urls": ["http://paypal.verify-account.example.top/login"]})
    assert r.status_code == 200
    j = r.json()
    assert j["assessment"]["score"] >= 50
    assert "not proof" in j["disclaimer"]
    assert j["evidence"][0]["contribution"] >= j["evidence"][-1]["contribution"]  # ranked


def test_benign_low_but_never_called_safe():  # FR-07-006
    j = c.post("/api/v1/analyses", json={"text": "Lunch at 1pm?", "urls": ["https://www.wikipedia.org"]}).json()
    assert j["assessment"]["tier"] == "Low Risk"
    assert any("not evidence of safety" in l for l in j["assessment"]["limitations"])


def test_validation_error_is_field_level():
    r = c.post("/api/v1/analyses", json={"urls": ["javascript:alert(1)"]})
    assert r.status_code == 422 and r.json()["errors"][0]["field"] == "urls[0]"


def test_delete_flow():  # FR-09-003
    rid = c.post("/api/v1/analyses", json={"text": "hello"}).json()["request_id"]
    assert c.delete(f"/api/v1/analyses/{rid}").status_code == 204
    assert c.get(f"/api/v1/analyses/{rid}").status_code == 404
