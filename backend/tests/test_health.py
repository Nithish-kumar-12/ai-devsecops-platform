"""
Phase 1 tests — health and readiness endpoints.
These are the first tests that must pass before moving to Phase 2.
"""
import pytest
from httpx import AsyncClient


class TestHealthEndpoints:
    """Tests for /api/health and /api/ready."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client: AsyncClient):
        response = await client.get("/api/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_response_shape(self, client: AsyncClient):
        response = await client.get("/api/health")
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "environment" in data

    @pytest.mark.asyncio
    async def test_health_version_format(self, client: AsyncClient):
        response = await client.get("/api/health")
        version = response.json()["version"]
        parts = version.split(".")
        assert len(parts) == 3, f"Expected semver, got: {version}"

    @pytest.mark.asyncio
    async def test_readiness_returns_200(self, client: AsyncClient):
        response = await client.get("/api/ready")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_readiness_response_shape(self, client: AsyncClient):
        response = await client.get("/api/ready")
        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert "database" in data["checks"]
        assert "redis" in data["checks"]

    @pytest.mark.asyncio
    async def test_unknown_route_returns_404(self, client: AsyncClient):
        response = await client.get("/api/nonexistent")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_openapi_schema_accessible_in_debug(self, client: AsyncClient):
        """OpenAPI schema should be available when DEBUG=True (default in tests)."""
        response = await client.get("/api/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "AI DevSecOps Platform API"
