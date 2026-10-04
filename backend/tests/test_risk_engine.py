import pytest
from app.models.schemas import RiskTier, EvidenceItem, SignalFamily
from app.risk.engine import RiskEngine, tier_for


@pytest.mark.parametrize("score,tier", [
    (0, RiskTier.LOW), (24, RiskTier.LOW), (25, RiskTier.SUSPICIOUS), (49, RiskTier.SUSPICIOUS),
    (50, RiskTier.HIGH), (74, RiskTier.HIGH), (75, RiskTier.CRITICAL), (100, RiskTier.CRITICAL),
])
def test_tier_boundaries(score, tier):   # FR-07-003
    assert tier_for(score) == tier


def _ev(fam, c):
    return EvidenceItem(signal_family=fam, rule_id="T", rule_version="t", contribution=c,
                        artefact_id="a", technical="t", plain="p")


def test_no_evidence_scores_zero():
    assert RiskEngine().score([], {SignalFamily.CONTENT})[0] == 0


def test_family_score_capped_at_one():
    s, fam = RiskEngine().score([_ev(SignalFamily.CONTENT, 0.9), _ev(SignalFamily.CONTENT, 0.9)],
                                {SignalFamily.CONTENT})
    assert s == 100 and fam[0].score == 1.0


def test_reproducible_from_weights():  # FR-07-001
    ev = [_ev(SignalFamily.CONTENT, 0.5), _ev(SignalFamily.URL, 1.0)]
    s, fam = RiskEngine().score(ev, {SignalFamily.CONTENT, SignalFamily.URL})
    assert s == round(100 * sum(f.weight * f.score for f in fam))


def test_weight_sensitivity_changes_score():  # FR-07-005
    ev = [_ev(SignalFamily.CONTENT, 1.0)]
    both = {SignalFamily.CONTENT, SignalFamily.URL}
    a, _ = RiskEngine().score(ev, both, {"content": 0.5, "url": 0.5})
    b, _ = RiskEngine().score(ev, both, {"content": 0.8, "url": 0.2})
    assert b > a
