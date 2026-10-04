"""Multi-signal risk engine (SRS F7): R = 100 * sum(w_i * s_i), weights renormalised
over the signal families that were actually evaluated."""
from pathlib import Path

import yaml

from app.models.schemas import EvidenceItem, FamilyScore, RiskTier, SignalFamily

WEIGHTS_PATH = Path(__file__).parent / "weights_v1.yaml"


def tier_for(score: int) -> RiskTier:
    """FR-07-003 boundaries: 0-24 / 25-49 / 50-74 / 75-100."""
    if score < 25:
        return RiskTier.LOW
    if score < 50:
        return RiskTier.SUSPICIOUS
    if score < 75:
        return RiskTier.HIGH
    return RiskTier.CRITICAL


class RiskEngine:
    def __init__(self, weights_path: Path = WEIGHTS_PATH):
        data = yaml.safe_load(weights_path.read_text(encoding="utf-8"))
        self.version: str = data["version"]
        self.weights: dict[str, float] = data["weights"]

    def score(self, evidence: list[EvidenceItem], evaluated: set[SignalFamily],
              weights: dict[str, float] | None = None) -> tuple[int, list[FamilyScore]]:
        w = weights or self.weights
        active = [f for f in evaluated if w.get(f.value, 0) > 0]
        total_w = sum(w[f.value] for f in active)
        if total_w == 0:
            return 0, []
        fam_scores: list[FamilyScore] = []
        r = 0.0
        for fam in sorted(active, key=lambda f: f.value):
            s = min(1.0, sum(e.contribution for e in evidence if e.signal_family == fam))
            nw = w[fam.value] / total_w
            r += nw * s
            fam_scores.append(FamilyScore(family=fam, score=round(s, 3), weight=round(nw, 3)))
        return max(0, min(100, round(100 * r))), fam_scores
