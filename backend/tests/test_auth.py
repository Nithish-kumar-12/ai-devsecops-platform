"""
Automated tests for User Registration, Authentication, and JWT validation.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestAuthentication:
    async def test_register_user_success(self, client: AsyncClient):
        payload = {
            "email": "developer@example.com",
            "password": "SecurePassword123!",
            "full_name": "DevSecOps Engineer",
            "role": "developer",
        }
        res = await client.post("/api/v1/auth/register", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["email"] == "developer@example.com"
        assert data["full_name"] == "DevSecOps Engineer"
        assert "hashed_password" not in data
        assert "id" in data

    async def test_register_cannot_self_assign_admin_role(self, client: AsyncClient):
        payload = {
            "email": "selfpromotion@example.com",
            "password": "Password123!",
            "full_name": "Untrusted User",
            "role": "admin",
        }
        res = await client.post("/api/v1/auth/register", json=payload)
        assert res.status_code == 201
        assert res.json()["role"] == "developer"

    async def test_register_duplicate_email_fails(self, client: AsyncClient):
        payload = {
            "email": "duplicate@example.com",
            "password": "Password123!",
            "full_name": "First User",
        }
        res1 = await client.post("/api/v1/auth/register", json=payload)
        assert res1.status_code == 201

        res2 = await client.post("/api/v1/auth/register", json=payload)
        assert res2.status_code == 400
        assert "already exists" in res2.json()["detail"]

    async def test_login_success(self, client: AsyncClient):
        # Register user
        reg_payload = {
            "email": "loginuser@example.com",
            "password": "SecretPassword123!",
            "full_name": "Login User",
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        # Login
        login_payload = {
            "email": "loginuser@example.com",
            "password": "SecretPassword123!",
        }
        res = await client.post("/api/v1/auth/login", json=login_payload)
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "loginuser@example.com"

    async def test_refresh_access_token_requires_refresh_type(self, client: AsyncClient):
        await client.post(
            "/api/v1/auth/register",
            json={"email": "refresh@example.com", "password": "Password123!"},
        )
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "refresh@example.com", "password": "Password123!"},
        )
        login_data = login_res.json()

        refresh_res = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": login_data["refresh_token"]},
        )
        assert refresh_res.status_code == 200
        assert refresh_res.json()["access_token"]
        assert refresh_res.json()["refresh_token"]

        access_res = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": login_data["access_token"]},
        )
        assert access_res.status_code == 401

    async def test_login_invalid_password_fails(self, client: AsyncClient):
        reg_payload = {
            "email": "wrongpwd@example.com",
            "password": "CorrectPassword123!",
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        login_payload = {
            "email": "wrongpwd@example.com",
            "password": "WrongPassword123!",
        }
        res = await client.post("/api/v1/auth/login", json=login_payload)
        assert res.status_code == 401
        assert "Invalid email or password" in res.json()["detail"]

    async def test_get_me_with_bearer_token(self, client: AsyncClient):
        reg_payload = {
            "email": "me@example.com",
            "password": "Password123!",
            "full_name": "Me User",
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "me@example.com", "password": "Password123!"},
        )
        token = login_res.json()["access_token"]

        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "me@example.com"

    async def test_get_me_unauthorized_without_token(self, client: AsyncClient):
        res = await client.get("/api/v1/auth/me")
        assert res.status_code == 401
