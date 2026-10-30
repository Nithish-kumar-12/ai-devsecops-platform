"""
API v1 Router aggregator.
"""
from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.projects import router as projects_router
from app.api.v1.scans import router as scans_router
from app.api.v1.findings import router as findings_router
from app.api.v1.policies import router as policies_router
from app.api.v1.reports import router as reports_router

api_router = APIRouter(prefix="/v1")

api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(policies_router)
api_router.include_router(reports_router)

__all__ = ["api_router"]
