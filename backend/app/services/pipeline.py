"""Orchestrates: artefacts -> analyzers -> connectors -> evidence -> score -> result."""
from typing import Optional

from app.analyzers.conversation import MIN_MESSAGES, ConversationAnalyzer
from app.analyzers.message import MessageAnalyzer
from app.analyzers.sender import SenderAnalyzer
from app.analyzers.url import UrlAnalyzer
from app.connectors.base import (Connector, ConnectorResult, MALICIOUS, NOT_CONFIGURED, OK,
                                 SUSPICIOUS, UNAVAILABLE)
from app.connectors.privacy import SCOPE
from app.connectors.safebrowsing import SafeBrowsingConnector
from app.connectors.virustotal import VirusTotalConnector
from app.core.config import Settings
from app.input_manager.manager import build_artefacts
from app.models.schemas import (
    AnalysisRequestIn, AnalysisResult, AnalysisStatus, Artefact, ArtefactType, ConnectorStatus,
    EvidenceItem, RiskAssessment, RiskTier, SafeAction, SignalFamily,
)
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

# verdict -> (contribution, plain wording)
_VERDICTS = {MALICIOUS: 0.8, SUSPICIOUS: 0.4}


def build_connectors(cfg: Settings) -> list[Connector]:
    common = dict(timeout=cfg.connector_timeout_seconds, cache_ttl=cfg.connector_cache_ttl_seconds)
    return [
        SafeBrowsingConnector(cfg.safe_browsing_api_key,
                              requests_per_minute=cfg.safe_browsing_requests_per_minute, **common),
        VirusTotalConnector(cfg.virustotal_api_key,
                            requests_per_minute=cfg.virustotal_requests_per_minute, **common),
    ]


def _evidence_from(result: ConnectorResult, art: Artefact) -> Optional[EvidenceItem]:
    contrib = _VERDICTS.get(result.verdict or "")
    if result.status != OK or contrib is None:
        return None          # no match / failure is never evidence (FR-06-005)
    label = "flagged" if result.verdict == MALICIOUS else "weakly flagged"
    return EvidenceItem(
        signal_family=SignalFamily.DOMAIN, source_type="external",
        rule_id=f"X-{result.name.upper()}-01", rule_version=f"{result.name}_api",
        contribution=contrib, artefact_id=art.artefact_id,
        technical=f"External service '{result.name}' {label} this URL ({result.details}).",
        plain=f"A security service ({result.name.replace('_', ' ')}) reports this link as unsafe."
              if result.verdict == MALICIOUS else
              f"A security service ({result.name.replace('_', ' ')}) raised a possible concern about this link.",
        details={"hard_signal": result.verdict == MALICIOUS,
                 # provenance (FR-06-003)
                 "source": result.name, "query_scope": result.query_scope,
                 "response_status": result.status, "queried_at": result.queried_at.isoformat(),
                 "from_cache": result.from_cache, **result.details},
    )


class Pipeline:
    def __init__(self, cfg: Settings, connectors: Optional[list[Connector]] = None):
        self.cfg = cfg
        self.message = MessageAnalyzer()
        self.url = UrlAnalyzer()
        self.sender = SenderAnalyzer()
        self.conversation = ConversationAnalyzer(self.message)
        self.engine = RiskEngine()
        self.connectors = connectors if connectors is not None else build_connectors(cfg)

    def disclosure(self) -> dict:
        """FR-06-002: what would be shared, and with whom."""
        active = [c.name for c in self.connectors if c.configured]
        return {
            "external_sharing_default": "off",
            "enabled_services": active,
            "what_is_shared": SCOPE + ". Message text, screenshots and conversations are never sent.",
            "how_to_opt_in": "Set allow_external=true in the request.",
        }

    def _run_connectors(self, urls: list[Artefact], allow: bool):
        evidence: list[EvidenceItem] = []
        statuses: list[ConnectorStatus] = []
        for c in self.connectors:
            if not c.configured:
                statuses.append(ConnectorStatus(name=c.name, status=NOT_CONFIGURED, note="No API key configured."))
                continue
            if not allow or not urls:
                why = "External sharing not requested." if not allow else "No URL to check."
                statuses.append(ConnectorStatus(name=c.name, status="skipped", note=why))
                continue
            results = [(a, c.check_url(a.canonical)) for a in urls]
            for a, r in results:
                if (ev := _evidence_from(r, a)):
                    evidence.append(ev)
            bad = [r for _, r in results if r.status != OK]
            first = results[0][1]
            statuses.append(ConnectorStatus(
                name=c.name, status=UNAVAILABLE if bad else OK,
                note=bad[0].note if bad else first.note, query_scope=first.query_scope,
                queried_at=first.queried_at, from_cache=all(r.from_cache for _, r in results)))
        return evidence, statuses

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
            elif a.type == ArtefactType.EMAIL_HEADERS:
                evaluated.add(SignalFamily.SENDER)
                evidence += self.sender.analyze(a)
                text = a.canonical or a.original
                if not self.sender.has_from(text):
                    limitations.append("No 'From' header found in the supplied headers: sender consistency was not checked.")
                if not self.sender.auth_results(text):
                    limitations.append("SPF/DKIM/DMARC results are not present in the supplied headers (unknown, not treated as pass or fail).")
            elif a.type != ArtefactType.CONVERSATION:
                limitations.append(f"'{a.type.value}' analysis is not implemented yet and was not scored.")

        convo = [a for a in artefacts if a.type == ArtefactType.CONVERSATION]
        if convo:
            if len(convo) < MIN_MESSAGES:
                limitations.append(f"Conversation has {len(convo)} message(s); at least {MIN_MESSAGES} are needed for reliable "
                                   "sequence analysis. This is not a sign that it is safe.")
            else:
                evaluated.add(SignalFamily.CONVERSATION)
                evidence += self.conversation.analyze_sequence(convo)

        present = {a.type for a in artefacts}
        if ArtefactType.URL not in present:
            limitations.append("No URL supplied: URL signals were not evaluated.")
        if ArtefactType.TEXT not in present:
            limitations.append("No message text supplied: content signals were not evaluated.")

        # ---- external threat intelligence (opt-in, failure-safe)
        urls = [a for a in artefacts if a.type == ArtefactType.URL]
        ext_evidence, statuses = self._run_connectors(urls, req.allow_external)
        evidence += ext_evidence
        if ext_evidence:
            evaluated.add(SignalFamily.DOMAIN)

        ok = [s for s in statuses if s.status == OK]
        down = [s for s in statuses if s.status == UNAVAILABLE]
        if down:
            limitations.append("Unavailable external source(s): " + ", ".join(
                f"{s.name} ({s.note})" for s in down) + ". This was NOT treated as safe or unsafe.")
        if not ok:
            limitations.append("No external threat-intelligence check completed, so reputation evidence is "
                               "missing. Absence of a match is not evidence of safety.")
        elif not ext_evidence:
            limitations.append("External services reported no match. This is not evidence of safety: "
                               "new threats are often not listed yet.")

        score, fam = self.engine.score(evidence, evaluated)
        adjustments: list[str] = []
        if any(e.details.get("hard_signal") for e in evidence) and score < self.engine.external_floor:
            adjustments.append(f"Score raised from {score} to {self.engine.external_floor} because an "
                               "external threat-intelligence service flagged the URL as malicious.")
            score = self.engine.external_floor
        tier = tier_for(score)
        ranked = sorted(evidence, key=lambda e: e.contribution, reverse=True)
        partial = down or any("not implemented" in l for l in limitations)
        return AnalysisResult(
            status=AnalysisStatus.PARTIAL if partial else AnalysisStatus.COMPLETED,
            artefacts=artefacts,
            assessment=RiskAssessment(
                score=score, tier=tier, weights_version=self.engine.version,
                rules_version=self.message.version, family_scores=fam,
                limitations=limitations, adjustments=adjustments),
            evidence=ranked,
            safe_actions=[SafeAction(action_text=t) for t in ACTIONS[tier]],
            connectors=statuses,
            disclaimer=DISCLAIMER,
        )
