import secrets
import time

from fastapi import APIRouter, Header, HTTPException, Request

from app.models.schemas import AnalysisRequestIn, AnalysisResult, FeedbackIn

router = APIRouter(prefix="/api/v1")


@router.get("/disclosure")
def disclosure(request: Request):
    """Shown in the UI before submission (FR-06-002, IR-UI-003)."""
    return request.app.state.pipeline.disclosure()


@router.post("/analyses", response_model=AnalysisResult)
def create_analysis(body: AnalysisRequestIn, request: Request):
    t0 = time.perf_counter()
    result = request.app.state.pipeline.run(body)
    request.app.state.store.save(result, duration_ms=(time.perf_counter() - t0) * 1000)
    return result


@router.get("/analyses/{request_id}", response_model=AnalysisResult)
def get_analysis(request_id: str, request: Request):
    r = request.app.state.store.get(request_id)
    if not r:
        raise HTTPException(404, "Analysis not found (it may have been deleted).")
    return r


@router.delete("/analyses/{request_id}", status_code=204)
def delete_analysis(request_id: str, request: Request):
    if not request.app.state.store.delete(request_id):
        raise HTTPException(404, "Analysis not found.")


@router.post("/analyses/{request_id}/feedback", status_code=201)
def add_feedback(request_id: str, body: FeedbackIn, request: Request):
    if not request.app.state.store.add_feedback(request_id, body):
        raise HTTPException(404, "Analysis not found.")
    return {"status": "recorded"}


@router.get("/audit")
def audit(request: Request, limit: int = 100, event_type: str | None = None,
          x_operator_key: str = Header(default="")):
    """Operator/evaluator view of audit metadata (FR-09-005). Never contains submitted content."""
    key = request.app.state.cfg.operator_key
    if not key:
        raise HTTPException(403, "Audit view is disabled: OPERATOR_KEY is not set on the server.")
    if not secrets.compare_digest(x_operator_key.encode(), key.encode()):
        raise HTTPException(401, "Invalid operator key.")
    return request.app.state.store.audit_events(limit, event_type)
