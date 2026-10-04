"""Common analyzer interface (IR-SW-005): independently testable."""
from abc import ABC, abstractmethod

from app.models.schemas import Artefact, EvidenceItem, SignalFamily


class Analyzer(ABC):
    family: SignalFamily

    @abstractmethod
    def analyze(self, artefact: Artefact) -> list[EvidenceItem]:
        """Return evidence items for one artefact (empty list = no match)."""
