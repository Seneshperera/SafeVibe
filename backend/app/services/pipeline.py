"""Orchestrates: artefacts -> analyzers -> evidence -> score -> result."""
from app.analyzers.message import MessageAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.core.config import Settings
from app.models.schemas import (
    AnalysisRequestIn, AnalysisResult, AnalysisStatus, ArtefactType, ConnectorStatus,
    EvidenceItem, RiskAssessment, RiskTier, SafeAction, SignalFamily,
)
from app.input_manager.manager import build_artefacts
from app.risk.engine import RiskEngine, tier_for

DISCLAIMER = ("SafeVibe is a decision-support tool and does not guarantee safety. "
              "A Low Risk result is not proof that content is safe. "
              "Always verify through a trusted site, app or phone number, never by opening the suspicious link.")

# FR-08-004 / FR-08-007: cautious, reversible, never "open the link to check"
ACTIONS = {
    RiskTier.LOW: ["Proceed cautiously.", "If the request was unexpected, verify it through the official app, website or phone number you already trust."],
    RiskTier.SUSPICIOUS: ["Pause. Do not click links or share information yet.", "Verify independently using an official app, website or phone number you already know."],
    RiskTier.HIGH: ["Stop interacting and do not pay or sign in.", "Contact the organisation through a channel you trust.", "Report and block the sender if appropriate."],
    RiskTier.CRITICAL: ["Do not open, reply, pay or provide credentials.", "Keep a copy of the message as evidence and report it to the organisation or authorities.", "If you already shared details, contact your bank or provider right away."],
}


class Pipeline:
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.message = MessageAnalyzer()
        self.url = UrlAnalyzer()
        self.engine = RiskEngine()

    def run(self, req: AnalysisRequestIn) -> AnalysisResult:
        artefacts = build_artefacts(req, self.cfg)  # raises InputValidationError
        evidence: list[EvidenceItem] = []
        evaluated: set[SignalFamily] = set()
        limitations: list[str] = []

        for a in artefacts:
            if a.type == ArtefactType.TEXT:
                evaluated.add(SignalFamily.CONTENT)
                evidence += self.message.analyze(a)
            elif a.type == ArtefactType.URL:
                evaluated.add(SignalFamily.URL)
                evidence += self.url.analyze(a)
            else:
                limitations.append(f"'{a.type.value}' analysis is not implemented yet and was not scored.")

        present = {a.type for a in artefacts}
        if ArtefactType.URL not in present:
            limitations.append("No URL supplied: URL signals were not evaluated.")
        if ArtefactType.TEXT not in present:
            limitations.append("No message text supplied: content signals were not evaluated.")
        limitations.append("No external threat-intelligence check was performed (not configured). "
                           "Absence of a match is not evidence of safety.")

        score, fam = self.engine.score(evidence, evaluated)
        tier = tier_for(score)
        ranked = sorted(evidence, key=lambda e: e.contribution, reverse=True)
        partial = any("not implemented" in l for l in limitations)
        return AnalysisResult(
            status=AnalysisStatus.PARTIAL if partial else AnalysisStatus.COMPLETED,
            artefacts=artefacts,
            assessment=RiskAssessment(
                score=score, tier=tier, weights_version=self.engine.version,
                rules_version=self.message.version, family_scores=fam, limitations=limitations),
            evidence=ranked,
            safe_actions=[SafeAction(action_text=t) for t in ACTIONS[tier]],
            connectors=[ConnectorStatus(name="safe_browsing", status="not_configured"),
                        ConnectorStatus(name="virustotal", status="not_configured")],
            disclaimer=DISCLAIMER,
        )
