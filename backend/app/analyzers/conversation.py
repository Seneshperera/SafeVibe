"""Conversation analyzer (SRS F5). Works on the ORDERED list of messages.

Sequence-level evidence is tagged details["scope"] = "sequence" so it can be told apart
from single-message evidence (FR-05-003) and always references message positions (FR-05-001).
"""
import re

from app.analyzers.message import MessageAnalyzer
from app.models.schemas import Artefact, ArtefactType, EvidenceItem, SignalFamily

RULES_VERSION = "conversation_rules_v1"
MIN_MESSAGES = 3   # FR-05-004: fewer than this is too short for reliable sequence analysis

_SECRECY = re.compile(r"\b(don'?t tell|do not tell|keep (this|it) (a )?(secret|between us|private|confidential)|between us|tell no ?one|nobody (needs|should) know)\b", re.I)
_PAYCHANGE = re.compile(r"\b(new|different|changed|updated) (bank )?(account|wallet|iban|number|payment details)|use this (account|wallet|number) instead|(account|bank) details (have )?changed\b", re.I)
_IDCHANGE = re.compile(r"\b(this is my new (number|account|email)|i('m| am) (now )?(using|on) a new (number|account)|i changed my (number|account))\b", re.I)


class ConversationAnalyzer:
    family = SignalFamily.CONVERSATION

    def __init__(self, message_analyzer: MessageAnalyzer):
        self.rules = {r["category"]: r["_re"] for r in message_analyzer.rules}

    def _has(self, category: str, text: str) -> bool:
        return bool(self.rules[category].search(text))

    def _ev(self, art: Artefact, rid: str, contrib: float, technical: str, plain: str, indexes: list[int]):
        return EvidenceItem(signal_family=self.family, rule_id=rid, rule_version=RULES_VERSION,
                            contribution=contrib, artefact_id=art.artefact_id,
                            technical=technical, plain=plain,
                            details={"scope": "sequence", "message_indexes": indexes})

    def analyze_sequence(self, artefacts: list[Artefact]) -> list[EvidenceItem]:
        msgs = sorted((a for a in artefacts if a.type == ArtefactType.CONVERSATION), key=lambda a: a.index or 0)
        if len(msgs) < MIN_MESSAGES:
            return []
        texts = [m.canonical or m.original for m in msgs]
        by_idx = {m.index: m for m in msgs}
        idxs = [m.index for m in msgs]
        ev: list[EvidenceItem] = []

        pay = [i for i, t in zip(idxs, texts) if self._has("financial_pressure", t) or self._has("credential_request", t)]
        urg = [i for i, t in zip(idxs, texts) if self._has("urgency", t)]
        sec = [i for i, t in zip(idxs, texts) if _SECRECY.search(t)]
        chg = [i for i, t in zip(idxs, texts) if _PAYCHANGE.search(t)]
        idc = [i for i, t in zip(idxs, texts) if _IDCHANGE.search(t)]

        if pay and idxs.index(pay[0]) >= 2:   # at least two earlier turns with no money/credential ask
            first = pay[0]
            ev.append(self._ev(by_idx[first], "CV-ESCALATE-01", 0.40,
                               f"Escalation: first payment/credential request appears at message {first}, "
                               f"after {idxs.index(first)} earlier messages without one.",
                               "The conversation started friendly and only later turned into a request for money or details.",
                               [first]))
        if len(pay) >= 2:
            ev.append(self._ev(by_idx[pay[1]], "CV-REPAY-01", 0.35,
                               f"Repeated payment/credential demands at messages {pay}.",
                               "You are being asked for money or details more than once.", pay))
        if len(urg) >= 2:
            ev.append(self._ev(by_idx[urg[1]], "CV-URGENCY-01", 0.30,
                               f"Repeated urgency language at messages {urg}.",
                               "The sender keeps pushing you to hurry.", urg))
        if sec:
            ev.append(self._ev(by_idx[sec[0]], "CV-SECRECY-01", 0.35,
                               f"Secrecy instruction at message(s) {sec}.",
                               "You are being asked to keep this secret. Scammers do this to stop others warning you.", sec))
        if chg:
            ev.append(self._ev(by_idx[chg[0]], "CV-PAYCHANGE-01", 0.40,
                               f"Payment details change mentioned at message(s) {chg}.",
                               "The payment details changed during the conversation. This is a common fraud pattern.", chg))
        if idc:
            ev.append(self._ev(by_idx[idc[0]], "CV-IDCHANGE-01", 0.30,
                               f"Identity/contact change claimed at message(s) {idc}.",
                               "The other person says they have a new number or account, which is a common impersonation trick.", idc))
        return ev
