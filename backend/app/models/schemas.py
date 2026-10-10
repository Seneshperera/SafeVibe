"""Pydantic models mirroring SRS Figure B.5 (conceptual data model)."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ArtefactType(str, Enum):
    TEXT = "text"
    URL = "url"
    CONVERSATION = "conversation"
    EMAIL_HEADERS = "email_headers"
    SCREENSHOT = "screenshot"


class SignalFamily(str, Enum):
    CONTENT = "content"
    URL = "url"
    SENDER = "sender"
    DOMAIN = "domain"
    CONVERSATION = "conversation"
    IMAGE = "image"


class RiskTier(str, Enum):
    LOW = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH = "High Risk"
    CRITICAL = "Critical"


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


# ---------- request ----------
class AnalysisRequestIn(BaseModel):
    text: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    conversation: list[str] = Field(default_factory=list)
    email_headers: Optional[str] = None
    # Privacy opt-in (FR-06-002 / IR-COM-004): nothing is sent to third parties unless true
    allow_external: bool = False


# ---------- internal ----------
class Artefact(BaseModel):
    artefact_id: str = Field(default_factory=lambda: str(uuid4()))
    type: ArtefactType
    original: str                      # exactly what the user submitted (FR-01-002)
    canonical: Optional[str] = None    # normalised form used for analysis
    index: Optional[int] = None        # position, e.g. conversation turn


class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    signal_family: SignalFamily
    source_type: str = "rule"          # rule | external | derived
    rule_id: str
    rule_version: str
    contribution: float                # 0..1 contribution to its family
    artefact_id: str
    span: Optional[tuple[int, int]] = None
    matched_text: Optional[str] = None
    technical: str
    plain: str
    details: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=_now)


# ---------- response ----------
class FamilyScore(BaseModel):
    family: SignalFamily
    score: float          # 0..1
    weight: float         # normalised weight actually used


class ConnectorStatus(BaseModel):
    name: str
    status: str           # ok | unavailable | not_configured | skipped
    note: Optional[str] = None
    query_scope: Optional[str] = None
    queried_at: Optional[datetime] = None
    from_cache: bool = False


class SafeAction(BaseModel):
    action_text: str
    reversibility: str = "reversible"


class RiskAssessment(BaseModel):
    score: int
    tier: RiskTier
    weights_version: str
    rules_version: str
    family_scores: list[FamilyScore]
    limitations: list[str]
    adjustments: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=_now)
    status: AnalysisStatus
    artefacts: list[Artefact]
    assessment: RiskAssessment
    evidence: list[EvidenceItem]       # ranked by contribution, highest first
    safe_actions: list[SafeAction]
    connectors: list[ConnectorStatus]
    disclaimer: str


class FeedbackIn(BaseModel):
    """De-identified feedback (FR-09-002). Do not put personal data in the comment."""
    understood: Optional[bool] = None
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    comment: Optional[str] = Field(default=None, max_length=500)
    evaluation_context: Optional[str] = Field(default=None, max_length=100)  # e.g. scenario id

    @model_validator(mode="after")
    def _not_empty(self):
        if self.understood is None and self.rating is None and not (self.comment or "").strip():
            raise ValueError("Provide at least one of: understood, rating, comment.")
        return self
