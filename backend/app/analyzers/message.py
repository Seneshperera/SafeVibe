"""Message/content analyzer (SRS F2). Rule-driven so every reason is traceable."""
import re
from pathlib import Path

import yaml

from app.analyzers.base import Analyzer
from app.models.schemas import Artefact, ArtefactType, EvidenceItem, SignalFamily

RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "rules_v1.yaml"


class MessageAnalyzer(Analyzer):
    family = SignalFamily.CONTENT

    def __init__(self, rules_path: Path = RULES_PATH):
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        self.version: str = data["version"]
        self.rules = [
            {**r, "_re": re.compile(r["pattern"], re.IGNORECASE)} for r in data["rules"]
        ]

    def analyze(self, artefact: Artefact) -> list[EvidenceItem]:
        if artefact.type != ArtefactType.TEXT:
            return []
        text = artefact.canonical or artefact.original
        out: list[EvidenceItem] = []
        for rule in self.rules:
            m = rule["_re"].search(text)  # first match per rule: one reason per indicator
            if m:
                out.append(EvidenceItem(
                    signal_family=self.family,
                    rule_id=rule["id"],
                    rule_version=self.version,
                    contribution=float(rule["contribution"]),
                    artefact_id=artefact.artefact_id,
                    span=(m.start(), m.end()),
                    matched_text=m.group(0),
                    technical=rule["technical"],
                    plain=rule["plain"],
                    details={"category": rule["category"]},
                ))
        return out
