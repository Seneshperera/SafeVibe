"""SQL-backed store: persistence, audit trail, feedback, deletion (SRS F9 / FR-09-*)."""
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import models as m
from app.models.schemas import (AnalysisResult, AnalysisStatus, Artefact, ArtefactType, ConnectorStatus,
                                EvidenceItem, FamilyScore, FeedbackIn, RiskAssessment, RiskTier, SafeAction,
                                SignalFamily)

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_URL = re.compile(r"https?://\S+|www\.\S+")
_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def scrub(text: Optional[str]) -> Optional[str]:
    """Best-effort removal of direct identifiers from free-text feedback (FR-09-002)."""
    if not text:
        return text
    text = _EMAIL.sub("[email]", text)
    text = _URL.sub("[link]", text)
    return _PHONE.sub("[number]", text).strip()


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)   # SQLite drops tzinfo


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SqlStore:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.Session = sessionmaker(engine, expire_on_commit=False)

    # ------------------------------------------------------------ audit
    def _audit(self, s: Session, request_id: str, event_type: str, version: Optional[str], detail: dict):
        s.add(m.AuditEventRow(audit_id=str(uuid4()), request_id=request_id, event_type=event_type,
                              rule_version=version, created_at=_now(), detail=detail))

    # ------------------------------------------------------------ save
    def save(self, r: AnalysisResult, duration_ms: Optional[float] = None) -> None:
        a = r.assessment
        aid = str(uuid4())
        row = m.AnalysisRequestRow(request_id=r.request_id, created_at=r.created_at, status=r.status.value)
        row.artefacts = [m.InputArtefactRow(
            artefact_id=x.artefact_id, position=i, type=x.type.value, original=x.original,
            content_hash=hashlib.sha256(x.original.encode()).hexdigest(),
            normalized_reference=x.canonical, msg_index=x.index) for i, x in enumerate(r.artefacts)]
        row.assessment = m.RiskAssessmentRow(
            assessment_id=aid, score_0_100=a.score, severity_tier=a.tier.value,
            model_version=a.weights_version, rules_version=a.rules_version,
            family_scores=[f.model_dump(mode="json") for f in a.family_scores],
            limitations=a.limitations, adjustments=a.adjustments,
            connectors=[c.model_dump(mode="json") for c in r.connectors], disclaimer=r.disclaimer)
        row.assessment.evidence = [m.EvidenceItemRow(
            evidence_id=e.evidence_id, rank=i, signal_family=e.signal_family.value, source_type=e.source_type,
            rule_id=e.rule_id, rule_version=e.rule_version, contribution=e.contribution,
            artefact_id=e.artefact_id, span_start=e.span[0] if e.span else None,
            span_end=e.span[1] if e.span else None, matched_text=e.matched_text,
            technical=e.technical, plain=e.plain, details=e.model_dump(mode="json")["details"],
            observed_at=e.observed_at) for i, e in enumerate(r.evidence)]
        row.assessment.explanations = [
            m.ExplanationRow(explanation_id=str(uuid4()), evidence_id=e.evidence_id, level=lvl, text=txt)
            for e in r.evidence for lvl, txt in (("technical", e.technical), ("plain", e.plain))]
        row.assessment.actions = [m.SafeActionRow(action_id=str(uuid4()), position=i, action_text=x.action_text,
                                                  reversibility=x.reversibility) for i, x in enumerate(r.safe_actions)]
        version = f"{a.rules_version}/{a.weights_version}"
        with self.Session() as s, s.begin():
            s.add(row)
            self._audit(s, r.request_id, "analysis_created", version, {
                "input_types": sorted({x.type.value for x in r.artefacts}),
                "status": r.status.value, "score": a.score, "tier": a.tier.value,
                "evidence_count": len(r.evidence), "limitations_count": len(a.limitations),
                "connectors": [{"name": c.name, "status": c.status, "note": c.note} for c in r.connectors],
                "duration_ms": round(duration_ms, 1) if duration_ms is not None else None})
            for c in r.connectors:     # FR-09-005: failures visible, never turned into results
                if c.status == "unavailable":
                    self._audit(s, r.request_id, "connector_failure", version, {"connector": c.name, "note": c.note})

    # ------------------------------------------------------------ read
    def get(self, request_id: str) -> Optional[AnalysisResult]:
        with self.Session() as s:
            row = s.get(m.AnalysisRequestRow, request_id)
            if not row or not row.assessment:
                return None
            a = row.assessment
            return AnalysisResult(
                request_id=row.request_id, created_at=_utc(row.created_at), status=AnalysisStatus(row.status),
                artefacts=[Artefact(artefact_id=x.artefact_id, type=ArtefactType(x.type), original=x.original,
                                    canonical=x.normalized_reference, index=x.msg_index)
                           for x in sorted(row.artefacts, key=lambda x: x.position)],
                assessment=RiskAssessment(
                    score=a.score_0_100, tier=RiskTier(a.severity_tier), weights_version=a.model_version,
                    rules_version=a.rules_version, limitations=a.limitations, adjustments=a.adjustments,
                    family_scores=[FamilyScore(**f) for f in a.family_scores]),
                evidence=[EvidenceItem(
                    evidence_id=e.evidence_id, signal_family=SignalFamily(e.signal_family),
                    source_type=e.source_type, rule_id=e.rule_id, rule_version=e.rule_version,
                    contribution=e.contribution, artefact_id=e.artefact_id,
                    span=(e.span_start, e.span_end) if e.span_start is not None else None,
                    matched_text=e.matched_text, technical=e.technical, plain=e.plain,
                    details=e.details, observed_at=_utc(e.observed_at))
                    for e in sorted(a.evidence, key=lambda e: e.rank)],
                safe_actions=[SafeAction(action_text=x.action_text, reversibility=x.reversibility)
                              for x in sorted(a.actions, key=lambda x: x.position)],
                connectors=[ConnectorStatus(**c) for c in a.connectors], disclaimer=a.disclaimer)

    # ------------------------------------------------------------ delete
    def delete(self, request_id: str) -> bool:
        """Removes the request, artefacts, evidence, explanations, actions and feedback (FR-09-003).
        Only a content-free audit event remains."""
        with self.Session() as s, s.begin():
            row = s.get(m.AnalysisRequestRow, request_id)
            if not row:
                return False
            s.delete(row)
            self._audit(s, request_id, "analysis_deleted", None, {})
            return True

    # ------------------------------------------------------------ feedback
    def add_feedback(self, request_id: str, fb: FeedbackIn) -> bool:
        with self.Session() as s, s.begin():
            if not s.get(m.AnalysisRequestRow, request_id):
                return False
            s.add(m.FeedbackRow(
                feedback_id=str(uuid4()), request_id=request_id, created_at=_now(),
                evaluation_context=fb.evaluation_context,
                deidentified_response={"understood": fb.understood, "rating": fb.rating, "comment": scrub(fb.comment)}))
            self._audit(s, request_id, "feedback_received", None, {"has_comment": bool(fb.comment)})
            return True

    # ------------------------------------------------------------ audit view
    def audit_events(self, limit: int = 100, event_type: Optional[str] = None) -> list[dict]:
        q = select(m.AuditEventRow).order_by(m.AuditEventRow.created_at.desc()).limit(min(limit, 500))
        if event_type:
            q = q.where(m.AuditEventRow.event_type == event_type)
        with self.Session() as s:
            return [{"audit_id": e.audit_id, "request_id": e.request_id, "event_type": e.event_type,
                     "rule_version": e.rule_version, "created_at": _utc(e.created_at).isoformat(),
                     "detail": e.detail} for e in s.scalars(q)]
