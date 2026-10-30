"""
AI DevSecOps Platform — FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import setup_logging

from sqlalchemy import text, select
from app.api.v1.router import api_router
from app.db.base import Base
from app.db.session import _get_async_engine, _get_async_session_local
from app.models.user import User
from app.core.security import get_password_hash

# Initialise structured logging before anything else
setup_logging()

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info(
        "Starting AI DevSecOps Platform",
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )
    # Ensure database schema is created
    engine = _get_async_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed initial admin user if not exists
    session_factory = _get_async_session_local()
    async with session_factory() as session:
        try:
            admin_check = await session.execute(
                select(User).where(User.email == settings.FIRST_ADMIN_EMAIL.lower())
            )
            if not admin_check.scalar_one_or_none():
                admin_user = User(
                    email=settings.FIRST_ADMIN_EMAIL.lower(),
                    hashed_password=get_password_hash(settings.FIRST_ADMIN_PASSWORD),
                    full_name="Platform Administrator",
                    role="admin",
                    is_active=True,
                )
                session.add(admin_user)
                await session.commit()
                logger.info("Default administrator seeded", email=settings.FIRST_ADMIN_EMAIL)
        except Exception as e:
            logger.warning("Could not seed default admin user", error=str(e))

    yield
    logger.info("Shutting down AI DevSecOps Platform")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI DevSecOps Platform API",
    description=(
        "AI-powered application security testing and DevSecOps platform. "
        "Integrates SAST, DAST, SCA, secret detection, IaC scanning, SBOM "
        "generation, and AI-assisted remediation."
    ),
    version="0.1.0",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every incoming request with method, path, and response status."""
    response = await call_next(request)
    logger.info(
        "Request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        client=request.client.host if request.client else "unknown",
    )
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app.include_router(api_router, prefix="/api")


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Liveness probe — returns 200 when the application is running."""
    return {"status": "ok", "version": "0.1.0", "environment": settings.ENVIRONMENT}


@app.get("/api/ready", tags=["Health"])
async def readiness_check():
    """
    Readiness probe — verifies database connectivity.
    """
    db_status = "ok"
    try:
        session_factory = _get_async_session_local()
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    is_ready = db_status == "ok"
    return {
        "status": "ready" if is_ready else "not_ready",
        "checks": {
            "database": db_status,
            "redis": "ok" if settings.ENVIRONMENT == "production" else "disabled_in_dev",
        },
    }
