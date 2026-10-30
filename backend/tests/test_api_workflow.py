"""
End-to-end integration test: User -> Project -> ZIP Upload & Scan -> Findings -> AI Remediation -> Export.
"""
import io
import zipfile
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
class TestApiWorkflow:
    async def test_complete_platform_workflow(self, client: AsyncClient):
        # 1. Register & Login
        reg_payload = {
            "email": "pipeline@example.com",
            "password": "Password123!",
            "full_name": "Pipeline User",
        }
        await client.post("/api/v1/auth/register", json=reg_payload)

        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "pipeline@example.com", "password": "Password123!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create Project
        proj_res = await client.post(
            "/api/v1/projects",
            json={
                "name": "E-Commerce App",
                "description": "Production shopping application",
                "target_url": "https://example.com",
            },
            headers=headers,
        )
        assert proj_res.status_code == 201
        project_id = proj_res.json()["id"]

        # 3. Create sample source zip in-memory containing a secret and a vulnerable requirement
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("app/config.py", 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n')
            zf.writestr("requirements.txt", "requests==2.28.1\n")
        zip_buffer.seek(0)

        # 4. Upload and Scan
        scan_res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "full", "confirm_authorization": "true"},
            files={"file": ("test_codebase.zip", zip_buffer.getvalue(), "application/zip")},
            headers=headers,
        )
        assert scan_res.status_code == 201
        scan_data = scan_res.json()
        assert scan_data["status"] == "completed"
        assert len(scan_data["findings"]) >= 2
        assert scan_data["gate_status"] == "failed"  # Failed because Critical secret was found

        finding_id = scan_data["findings"][0]["id"]

        # 5. Filter findings
        filter_res = await client.get(
            f"/api/v1/findings/project/{project_id}?category=secret",
            headers=headers,
        )
        assert filter_res.status_code == 200
        secret_findings = filter_res.json()
        assert len(secret_findings) >= 1
        assert secret_findings[0]["category"] == "secret"

        # 6. Request AI remediation
        ai_res = await client.post(
            f"/api/v1/findings/{finding_id}/ai-remediation",
            headers=headers,
        )
        assert ai_res.status_code == 200
        ai_data = ai_res.json()
        assert ai_data["ai_analysis"] is not None
        assert "verification" in ai_data["ai_analysis"].lower() or ai_data["ai_verification_steps"] is not None

        # 7. Update status to fixed
        status_res = await client.patch(
            f"/api/v1/findings/{finding_id}/status",
            json={"status": "fixed"},
            headers=headers,
        )
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "fixed"

        # 8. Export JSON report
        json_export = await client.get(
            f"/api/v1/reports/export/json/{scan_data['id']}",
            headers=headers,
        )
        assert json_export.status_code == 200
        assert json_export.json()["scan_id"] == scan_data["id"]

        # 9. Export CSV report
        csv_export = await client.get(
            f"/api/v1/reports/export/csv/{scan_data['id']}",
            headers=headers,
        )
        assert csv_export.status_code == 200
        assert "text/csv" in csv_export.headers.get("content-type", "")
        assert "Finding ID" in csv_export.text

        # 10. Fetch dashboard metrics
        metrics_res = await client.get("/api/v1/reports/metrics", headers=headers)
        assert metrics_res.status_code == 200
        metrics = metrics_res.json()
        assert metrics["total_projects"] >= 1
        assert metrics["total_scans"] >= 1

        # 11. Test GitHub Actions CI/CD gate endpoints
        gh_zip = io.BytesIO()
        with zipfile.ZipFile(gh_zip, "w") as zf:
            zf.writestr("clean_module.py", "def add(a, b): return a + b\n")
        gh_zip.seek(0)

        gh_res = await client.post(
            "/api/v1/scans/github-action",
            data={
                "project_id": project_id,
                "scan_type": "sast",
                "commit_sha": "abc1234567890",
                "branch": "feature/safe-code",
                "repository": "org/repo",
            },
            files={"source": ("clean_source.zip", gh_zip.getvalue(), "application/zip")},
            headers=headers,
        )
        assert gh_res.status_code == 201
        gh_data = gh_res.json()
        gh_scan_id = gh_data["scan_id"]
        assert gh_data["status"] == "completed"

        # Check CI status endpoint
        ci_status = await client.get(
            f"/api/v1/scans/{gh_scan_id}/status",
            headers=headers,
        )
        assert ci_status.status_code == 200
        assert ci_status.json()["status"] == "completed"

        # Check CI gate-result endpoint
        ci_gate = await client.get(
            f"/api/v1/scans/{gh_scan_id}/gate-result",
            headers=headers,
        )
        assert ci_gate.status_code == 200
        assert ci_gate.json()["passed"] is True
        assert ci_gate.json()["critical_count"] == 0

        pdf_export = await client.get(
            f"/api/v1/reports/export/pdf/{gh_scan_id}",
            headers=headers,
        )
        assert pdf_export.status_code == 200
        assert pdf_export.headers["content-type"] == "application/pdf"
        assert pdf_export.content.startswith(b"%PDF-")

    async def test_scan_and_report_access_rejects_other_user(self, client: AsyncClient):
        owner_registration = await client.post(
            "/api/v1/auth/register",
            json={"email": "owner@example.com", "password": "Password123!"},
        )
        assert owner_registration.status_code == 201
        owner_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "owner@example.com", "password": "Password123!"},
        )
        owner_headers = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}

        project_res = await client.post(
            "/api/v1/projects",
            json={"name": "Owner Project", "description": "Private project"},
            headers=owner_headers,
        )
        assert project_res.status_code == 201
        project_id = project_res.json()["id"]

        scan_res = await client.post(
            "/api/v1/scans/trigger",
            json={"project_id": project_id, "scan_type": "sast", "source_type": "zip"},
            headers=owner_headers,
        )
        assert scan_res.status_code == 201
        scan_id = scan_res.json()["id"]

        other_registration = await client.post(
            "/api/v1/auth/register",
            json={"email": "outsider@example.com", "password": "Password123!"},
        )
        assert other_registration.status_code == 201
        other_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "outsider@example.com", "password": "Password123!"},
        )
        outsider_headers = {"Authorization": f"Bearer {other_login.json()['access_token']}"}

        status_res = await client.get(
            f"/api/v1/scans/{scan_id}/status", headers=outsider_headers
        )
        gate_res = await client.get(
            f"/api/v1/scans/{scan_id}/gate-result", headers=outsider_headers
        )
        json_res = await client.get(
            f"/api/v1/reports/export/json/{scan_id}", headers=outsider_headers
        )
        csv_res = await client.get(
            f"/api/v1/reports/export/csv/{scan_id}", headers=outsider_headers
        )

        assert status_res.status_code == 403
        assert gate_res.status_code == 403
        assert json_res.status_code == 403
        assert csv_res.status_code == 403
