from fastapi import APIRouter, HTTPException, Request

from app.models.schemas import AnalysisRequestIn, AnalysisResult

router = APIRouter(prefix="/api/v1")


@router.post("/analyses", response_model=AnalysisResult)
def create_analysis(body: AnalysisRequestIn, request: Request):
    result = request.app.state.pipeline.run(body)
    request.app.state.store.save(result)
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
