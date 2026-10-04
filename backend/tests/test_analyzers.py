from app.analyzers.message import MessageAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.models.schemas import Artefact, ArtefactType


def _t(s): return Artefact(type=ArtefactType.TEXT, original=s, canonical=s)
def _u(s): return Artefact(type=ArtefactType.URL, original=s, canonical=s)
def ids(ev): return {e.rule_id for e in ev}


def test_message_detects_indicators_with_spans():  # FR-02-001/002
    text = "URGENT: your account is suspended. Verify your account password now."
    ev = MessageAnalyzer().analyze(_t(text))
    assert {"C-URGENCY-01", "C-FEAR-01", "C-CRED-01"} <= ids(ev)
    e = next(x for x in ev if x.rule_id == "C-URGENCY-01")
    assert text[e.span[0]:e.span[1]].lower() == e.matched_text.lower()
    assert e.rule_version == "rules_v1"


def test_benign_message_no_match():
    assert MessageAnalyzer().analyze(_t("See you at lunch tomorrow, bring the notes.")) == []


def test_url_brand_mismatch():  # FR-03-002
    assert "U-BRAND-01" in ids(UrlAnalyzer().analyze(_u("https://paypal.secure-login.example-pay.top/verify")))


def test_url_legit_brand_not_flagged():
    assert "U-BRAND-01" not in ids(UrlAnalyzer().analyze(_u("https://www.paypal.com/signin")))


def test_url_signals():
    assert "U-IP-01" in ids(UrlAnalyzer().analyze(_u("http://192.168.1.5/login")))
    assert "U-SHORT-01" in ids(UrlAnalyzer().analyze(_u("https://bit.ly/abc")))
    assert "U-AT-01" in ids(UrlAnalyzer().analyze(_u("https://google.com@evil.example/x")))
    assert "U-PUNY-01" in ids(UrlAnalyzer().analyze(_u("https://xn--pypal-4ve.com")))
    assert "U-NOHTTPS-01" in ids(UrlAnalyzer().analyze(_u("http://example.com")))
