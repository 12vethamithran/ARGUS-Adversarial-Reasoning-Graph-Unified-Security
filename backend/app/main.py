from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.config import settings
from app.routers import session, analyze, terminal, report

log = structlog.get_logger()

app = FastAPI(
    title="ARGUS API",
    description="Adversarial Reasoning & Graph-based Unified Security Framework",
    version="0.1.0",
)

# CORS — explicit allow-list plus a dev regex so any localhost / 127.0.0.1
# port works (Vite may pick 5174+, and 127.0.0.1 ≠ localhost for CORS).
_origins = settings.get_allowed_origins()
_wildcard = _origins == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?" if not _wildcard else None,
    allow_credentials=not _wildcard,  # credentials + wildcard is rejected by browsers
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Session-Id"],
)

# Routers
app.include_router(session.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(analyze.router, prefix="/api", tags=["analyze"])
app.include_router(terminal.router, prefix="/ws", tags=["terminal"])
app.include_router(report.router, prefix="/api/reports", tags=["reports"])


@app.get("/health", tags=["infra"])
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.on_event("startup")
async def startup():
    import os
    for d in ["sessions", "graphs", "logs", "reports", "cache"]:
        os.makedirs(f"{settings.data_dir}/{d}", exist_ok=True)
    log.info("argus.startup", data_dir=settings.data_dir)
