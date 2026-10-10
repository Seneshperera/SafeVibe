from fastapi.testclient import TestClient

from app.analyzers.conversation import ConversationAnalyzer
from app.analyzers.message import MessageAnalyzer
from app.analyzers.sender import SenderAnalyzer
from app.main import app
from app.models.schemas import Artefact, ArtefactType

SPOOFED = """From: "PayPal Support" <help@secure-pay-login.top>
Return-Path: <bounce@mailer.example.net>
Reply-To: <collect@gmail.com>
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=secure-pay-login.top; dkim=fail; dmarc=fail
Subject: Verify now
"""
GOOD = """From: PayPal <service@paypal.com>
Return-Path: <bounce@paypal.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
"""
NO_AUTH = "From: Alice <alice@example.org>\nSubject: hi\n"


def hdr(t): return Artefact(type=ArtefactType.EMAIL_HEADERS, original=t, canonical=t)
def ids(ev): return {e.rule_id for e in ev}


def convo(msgs):
    return [Artefact(type=ArtefactType.CONVERSATION, original=m, canonical=m, index=i) for i, m in enumerate(msgs)]


A = ConversationAnalyzer(MessageAnalyzer())
S = SenderAnalyzer()


def test_spoofed_headers_detected():  # FR-03-003
    got = ids(S.analyze(hdr(SPOOFED)))
    assert {"S-DISPLAY-01", "S-RETPATH-01", "S-REPLYTO-01", "S-AUTH-SPF-01", "S-AUTH-DKIM-01", "S-AUTH-DMARC-01"} <= got


def test_legit_headers_no_evidence():
    assert S.analyze(hdr(GOOD)) == []


def test_missing_auth_is_unknown_not_evidence():  # FR-03-004
    assert S.analyze(hdr(NO_AUTH)) == []
    assert S.auth_results(NO_AUTH) == {}


def test_garbage_headers_do_not_crash():
    assert S.analyze(hdr("\x01\x02 not headers ::: @@")) == []


def test_job_scam_conversation_sequence():  # FR-05-001/002/003
    ev = A.analyze_sequence(convo([
        "Hi! We saw your CV and have a remote task job for you.",
        "Great, it's easy work, you earn daily.",
        "To start you must make a deposit of 50 USDT. Please do it today.",
        "Hurry, do it right away or you lose the slot. Don't tell anyone about this.",
        "Send another deposit now, this is urgent.",
    ]))
    got = ids(ev)
    assert {"CV-ESCALATE-01", "CV-REPAY-01", "CV-URGENCY-01", "CV-SECRECY-01"} <= got
    esc = next(e for e in ev if e.rule_id == "CV-ESCALATE-01")
    assert esc.details["scope"] == "sequence" and esc.details["message_indexes"] == [2]


def test_payment_and_identity_change():
    ev = A.analyze_sequence(convo(["hello", "how are you", "our account details have changed, use this account instead"]))
    assert "CV-PAYCHANGE-01" in ids(ev)
    ev = A.analyze_sequence(convo(["hello", "how are you", "this is my new number, save it"]))
    assert "CV-IDCHANGE-01" in ids(ev)


def test_benign_conversation_no_evidence():
    assert A.analyze_sequence(convo(["see you at 5?", "yes, bring the notes", "ok thanks", "bye"])) == []


def test_too_short_returns_nothing():  # FR-05-004 (limitation added by pipeline)
    assert A.analyze_sequence(convo(["pay the fee now", "urgent"])) == []


c = TestClient(app)


def test_api_conversation_scores_and_short_limitation():
    j = c.post("/api/v1/analyses", json={"conversation": [
        "hello", "nice to meet you", "please pay the processing fee now, it is urgent", "act now, keep this secret"]}).json()
    assert j["assessment"]["score"] > 0 and any(f["family"] == "conversation" for f in j["assessment"]["family_scores"])
    j = c.post("/api/v1/analyses", json={"conversation": ["pay the fee now", "urgent"]}).json()
    assert any("not a sign that it is safe" in l for l in j["assessment"]["limitations"])
    assert j["assessment"]["family_scores"] == []


def test_api_headers_scored_and_missing_auth_limitation():
    j = c.post("/api/v1/analyses", json={"email_headers": SPOOFED}).json()
    assert j["assessment"]["score"] >= 50
    j = c.post("/api/v1/analyses", json={"email_headers": NO_AUTH}).json()
    assert any("SPF/DKIM/DMARC" in l for l in j["assessment"]["limitations"])
