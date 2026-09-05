"""AIVARA FastAPI Application Entry Point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from aivara.core.config import settings
from aivara.core.logging import setup_logging, get_logger
from aivara.database.connection import init_db
from aivara.api.routers import api_v1_router
from aivara.api.errors import register_exception_handlers

# Initialize centralized logging
setup_logging()
logger = get_logger("aivara.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Starting AIVARA v%s (dev_mode=%s)", settings.app_version, settings.dev_mode)
    init_db()
    yield
    logger.info("Shutting down AIVARA")


# Disable public CDN docs by default per architecture review AR-003
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AIVARA — AI Verification & Assurance Platform",
    docs_url="/docs" if settings.dev_mode else None,
    redoc_url=None,
    lifespan=lifespan,
)

# CORS restricted to localhost origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register centralized error handling
register_exception_handlers(app)

# Include v1 modular API routers
app.include_router(api_v1_router)


@app.get("/health")
async def health_check():
    """Structured health check endpoint."""
    return {
        "status": "ok",
        "service": "aivara",
        "version": settings.app_version,
    }
