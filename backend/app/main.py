from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import get_settings
from app.input_manager.manager import InputValidationError
from app.services.pipeline import Pipeline
from app.services.store import MemoryStore

cfg = get_settings()
app = FastAPI(title="SafeVibe API", version="0.1.0")
app.state.pipeline = Pipeline(cfg)
app.state.store = MemoryStore()

app.add_middleware(CORSMiddleware, allow_origins=cfg.cors_list,
                   allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])


@app.exception_handler(InputValidationError)
async def validation_handler(_: Request, exc: InputValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid input", "errors": exc.errors})


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


app.include_router(router)
