"""SQLAlchemy tables mirroring SRS Figure B.5."""
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AnalysisRequestRow(Base):
    __tablename__ = "analysis_request"
    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    retention_state: Mapped[str] = mapped_column(String(20), default="active")
    artefacts: Mapped[list["InputArtefactRow"]] = relationship(cascade="all, delete-orphan")
    assessment: Mapped[Optional["RiskAssessmentRow"]] = relationship(cascade="all, delete-orphan", uselist=False)
    feedback: Mapped[list["FeedbackRow"]] = relationship(cascade="all, delete-orphan")


class InputArtefactRow(Base):
    __tablename__ = "input_artefact"
    artefact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("analysis_request.request_id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(20))
    content_hash: Mapped[str] = mapped_column(String(64))
    original: Mapped[str] = mapped_column(Text)           # removed on deletion
    normalized_reference: Mapped[Optional[str]] = mapped_column(Text)
    msg_index: Mapped[Optional[int]] = mapped_column(Integer)


class RiskAssessmentRow(Base):
    __tablename__ = "risk_assessment"
    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("analysis_request.request_id", ondelete="CASCADE"), unique=True)
    score_0_100: Mapped[int] = mapped_column(Integer)
    severity_tier: Mapped[str] = mapped_column(String(20))
    model_version: Mapped[str] = mapped_column(String(40))     # weights version
    rules_version: Mapped[str] = mapped_column(String(40))
    family_scores: Mapped[list] = mapped_column(JSON)
    limitations: Mapped[list] = mapped_column(JSON)            # uncertainty notes
    adjustments: Mapped[list] = mapped_column(JSON)
    connectors: Mapped[list] = mapped_column(JSON)
    disclaimer: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list["EvidenceItemRow"]] = relationship(cascade="all, delete-orphan")
    explanations: Mapped[list["ExplanationRow"]] = relationship(cascade="all, delete-orphan")
    actions: Mapped[list["SafeActionRow"]] = relationship(cascade="all, delete-orphan")


class EvidenceItemRow(Base):
    __tablename__ = "evidence_item"
    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("risk_assessment.assessment_id", ondelete="CASCADE"), index=True)
    rank: Mapped[int] = mapped_column(Integer)
    signal_family: Mapped[str] = mapped_column(String(20))
    source_type: Mapped[str] = mapped_column(String(20))
    rule_id: Mapped[str] = mapped_column(String(40))
    rule_version: Mapped[str] = mapped_column(String(40))
    contribution: Mapped[float] = mapped_column(Float)
    artefact_id: Mapped[str] = mapped_column(String(36))
    span_start: Mapped[Optional[int]] = mapped_column(Integer)
    span_end: Mapped[Optional[int]] = mapped_column(Integer)
    matched_text: Mapped[Optional[str]] = mapped_column(Text)
    technical: Mapped[str] = mapped_column(Text)
    plain: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ExplanationRow(Base):
    __tablename__ = "explanation"
    explanation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("risk_assessment.assessment_id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(36))
    level: Mapped[str] = mapped_column(String(20))            # technical | plain
    text: Mapped[str] = mapped_column(Text)


class SafeActionRow(Base):
    __tablename__ = "safe_action"
    action_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("risk_assessment.assessment_id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    action_text: Mapped[str] = mapped_column(Text)
    reversibility: Mapped[str] = mapped_column(String(20))


class AuditEventRow(Base):
    """Survives deletion of the analysis, but never holds submitted content."""
    __tablename__ = "audit_event"
    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(36), index=True)    # deliberately no FK
    event_type: Mapped[str] = mapped_column(String(40))
    rule_version: Mapped[Optional[str]] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detail: Mapped[dict] = mapped_column(JSON)


class FeedbackRow(Base):
    __tablename__ = "feedback_record"
    feedback_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("analysis_request.request_id", ondelete="CASCADE"), index=True)
    deidentified_response: Mapped[dict] = mapped_column(JSON)
    evaluation_context: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
