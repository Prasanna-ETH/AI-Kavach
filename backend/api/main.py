"""FastAPI application entry point for the LLM Sentinel Dashboard.

Run with:
    uv run uvicorn backend.api.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routers import scans as scans_router
from backend.api.routers import payloads as payloads_router
from backend.api.routers import datasets as datasets_router
from backend.api.routers import community as community_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

app = FastAPI(
    title="LLM Security Scanner API",
    description=(
        "REST + SSE API powering the LLM Security Scanner dashboard. "
        "Supports single-turn and multi-turn adversarial scanning with "
        "Playwright browser automation and a 3-tier hybrid evaluation engine."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

import os

# ---------------------------------------------------------------------------
# CORS — allow Vite dev server, configurable origins, and any Vercel domain
# ---------------------------------------------------------------------------
_default_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

_env_cors = os.environ.get("CORS_ORIGINS", "").strip()
if _env_cors == "*":
    _allowed_origins = ["*"]
elif _env_cors:
    _allowed_origins = list(set(_default_origins + [origin.strip() for origin in _env_cors.split(",") if origin.strip()]))
else:
    _allowed_origins = _default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=r"^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "X-Scan-Id"],
)

# ---------------------------------------------------------------------------
# Include routers
# ---------------------------------------------------------------------------
app.include_router(scans_router.router)
app.include_router(payloads_router.router)
app.include_router(datasets_router.router)
app.include_router(community_router.router)


# ---------------------------------------------------------------------------
# Health / root endpoints
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse({"service": "LLM Sentinel Dashboard API", "status": "ok"})


@app.get("/health", tags=["health"])
async def health():
    """Simple liveness check — also verifies scanner package is importable."""
    try:
        from scanner.engine import ScanEngine  # noqa: F401
        scanner_ok = True
        scanner_msg = "scanner package imported successfully"
    except Exception as exc:
        scanner_ok = False
        scanner_msg = str(exc)

    return {
        "status": "ok" if scanner_ok else "degraded",
        "scanner": {"ok": scanner_ok, "message": scanner_msg},
    }
