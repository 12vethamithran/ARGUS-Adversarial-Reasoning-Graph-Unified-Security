import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.config import settings
from app.routers import session, analyze, terminal, report
from app.storage.session_store import run_janitor_loop

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure the data subdirectories exist before serving.
    for d in ["sessions", "graphs", "logs", "reports", "cache"]:
        os.makedirs(f"{settings.data_dir}/{d}", exist_ok=True)
    log.info("argus.startup", data_dir=settings.data_dir)

    # Start the TTL janitor so expired sessions are actually reaped.
    janitor = asyncio.create_task(run_janitor_loop())
    try:
        yield
    finally:
        janitor.cancel()
        try:
            await janitor
        except asyncio.CancelledError:
            pass
        log.info("argus.shutdown")


app = FastAPI(
    title="ARGUS API",
    description="Adversarial Reasoning & Graph-based Unified Security Framework",
    version="0.1.0",
    lifespan=lifespan,
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
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["X-Session-Id"],
)

# Routers
app.include_router(session.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(analyze.router, prefix="/api", tags=["analyze"])
app.include_router(terminal.router, prefix="/ws", tags=["terminal"])
app.include_router(report.router, prefix="/api/reports", tags=["reports"])


@app.get("/", tags=["infra"])
async def root():
    return {
        "service": "ARGUS API",
        "description": "Adversarial Reasoning & Graph-based Unified Security Framework",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["infra"])
async def health():
    return {"status": "ok", "version": "0.1.0"}
