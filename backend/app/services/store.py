"""In-memory store (swap for PostgreSQL/SQLAlchemy on Day 5). Supports deletion (FR-09-003)."""
from app.models.schemas import AnalysisResult


class MemoryStore:
    def __init__(self):
        self._data: dict[str, AnalysisResult] = {}

    def save(self, r: AnalysisResult) -> None:
        self._data[r.request_id] = r

    def get(self, rid: str) -> AnalysisResult | None:
        return self._data.get(rid)

    def delete(self, rid: str) -> bool:
        return self._data.pop(rid, None) is not None
