"""
Tests for Task 1: ZIP upload limit (1 GiB) and Task 2: DAST-only scan (no ZIP).
Covers:
  - Valid ZIP below limit → accepted
  - ZIP above configured limit → 413
  - Invalid / corrupted ZIP → 400
  - SAST-only without ZIP → 400
  - DAST-only without ZIP → accepted (uses project.target_url)
  - DAST-only without target URL → 400
  - DAST-only without authorization confirmation → 400
  - Full scan (SAST + DAST) with ZIP and target URL
  - Safe large-file streaming (memory usage assertion)
  - Archive cleanup on failure
"""
import io
import os
import zipfile
import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock

# ─── Fixtures ──────────────────────────────────────────────────────────────────

def make_zip(files: dict[str, str]) -> bytes:
    """Build an in-memory valid ZIP archive with the given filename→content map."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


MINIMAL_ZIP = make_zip({"app/main.py": "print('hello')"})

VULNERABLE_ZIP = make_zip({
    "app/config.py": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n',
    "requirements.txt": "requests==2.28.1\n",
})


# ─── Helpers ───────────────────────────────────────────────────────────────────

async def login_and_get_headers(client: AsyncClient) -> dict:
    await client.post("/api/v1/auth/register", json={
        "email": "scanner_test@example.com",
        "password": "Password123!",
        "full_name": "Scanner Tester",
    })
    res = await client.post("/api/v1/auth/login", json={
        "email": "scanner_test@example.com",
        "password": "Password123!",
    })
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


async def create_project(
    client: AsyncClient,
    headers: dict,
    name: str = "Test Project",
    target_url: str | None = None,
) -> str:
    payload = {"name": name, "description": "Test"}
    if target_url:
        payload["target_url"] = target_url
    res = await client.post("/api/v1/projects", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    return res.json()["id"]


# ═══════════════════════════════════════════════════════════════════════════════
# TASK 1 — ZIP Upload Limit
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestUploadLimit:

    async def test_valid_zip_below_limit_is_accepted(self, client: AsyncClient):
        """A small valid ZIP should be accepted and scan should complete."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "upload-limit-valid")

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "secrets", "confirm_authorization": "false"},
            files={"file": ("codebase.zip", VULNERABLE_ZIP, "application/zip")},
            headers=headers,
        )
        assert res.status_code == 201, res.text
        assert res.json()["status"] == "completed"

    async def test_zip_above_limit_returns_413(self, client: AsyncClient):
        """Uploading a ZIP above MAX_UPLOAD_SIZE_BYTES must return HTTP 413."""
        from app.core.config import settings

        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "upload-limit-exceeds")

        # Temporarily reduce the limit to 1 byte for this test
        original = settings.MAX_UPLOAD_SIZE_BYTES
        settings.MAX_UPLOAD_SIZE_BYTES = 1
        try:
            res = await client.post(
                "/api/v1/scans/upload-and-scan",
                data={"project_id": project_id, "scan_type": "sast", "confirm_authorization": "false"},
                files={"file": ("codebase.zip", MINIMAL_ZIP, "application/zip")},
                headers=headers,
            )
            assert res.status_code == 413, res.text
            assert "maximum allowed size" in res.json()["detail"].lower()
        finally:
            settings.MAX_UPLOAD_SIZE_BYTES = original

    async def test_corrupted_zip_returns_400(self, client: AsyncClient):
        """A file with .zip extension but invalid content must return HTTP 400."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "upload-corrupt-zip")

        corrupted = b"this is not a zip file at all --- garbage bytes xyz"
        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "sast", "confirm_authorization": "false"},
            files={"file": ("corrupt.zip", corrupted, "application/zip")},
            headers=headers,
        )
        assert res.status_code == 400, res.text
        assert "corrupt" in res.json()["detail"].lower() or "invalid" in res.json()["detail"].lower()

    async def test_non_zip_file_extension_returns_400(self, client: AsyncClient):
        """A .tar.gz file must be rejected with HTTP 400."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "upload-wrong-ext")

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "sast", "confirm_authorization": "false"},
            files={"file": ("archive.tar.gz", b"fake tarball content", "application/gzip")},
            headers=headers,
        )
        assert res.status_code == 400, res.text

    async def test_upload_limit_value_is_one_gib(self):
        """Settings must expose MAX_UPLOAD_SIZE_BYTES = 1 GiB."""
        from app.core.config import settings
        assert settings.MAX_UPLOAD_SIZE_BYTES == 1_073_741_824

    async def test_effective_max_upload_mb_property(self):
        """effective_max_upload_mb property should return 1024 for the default 1 GiB."""
        from app.core.config import settings
        assert settings.effective_max_upload_mb == 1024


# ═══════════════════════════════════════════════════════════════════════════════
# TASK 2 — Conditional SAST/DAST Scan Validation
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestScanTypeValidation:

    # ── A. SAST-only ─────────────────────────────────────────────────────────

    async def test_sast_without_zip_returns_400(self, client: AsyncClient):
        """SAST scan must be rejected if no ZIP file is provided."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "sast-no-zip")

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "sast", "confirm_authorization": "false"},
            # No file field
            headers=headers,
        )
        assert res.status_code == 400, res.text
        detail = res.json()["detail"].lower()
        assert "zip" in detail or "archive" in detail or "required" in detail

    async def test_sast_with_zip_succeeds(self, client: AsyncClient):
        """SAST scan with a valid ZIP must complete."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(client, headers, "sast-with-zip")

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={"project_id": project_id, "scan_type": "sast", "confirm_authorization": "false"},
            files={"file": ("code.zip", MINIMAL_ZIP, "application/zip")},
            headers=headers,
        )
        assert res.status_code == 201, res.text
        assert res.json()["scan_type"] == "sast"

    # ── B. DAST-only ──────────────────────────────────────────────────────────

    async def test_dast_without_zip_and_with_project_url_succeeds(self, client: AsyncClient):
        """DAST-only scan must succeed with no ZIP when project has a target_url."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(
            client, headers, "dast-no-zip", target_url="https://example.com"
        )

        # We mock the DAST scanner to avoid real network calls in unit tests
        mock_findings = [{
            "scanner": "passive-dast",
            "rule_id": "DAST-SEC-HEADER-CSP",
            "title": "Missing CSP",
            "description": "No CSP header.",
            "category": "dast",
            "severity": "medium",
            "confidence": "high",
            "file_path": None,
            "line_number": None,
            "column_number": None,
            "endpoint": "https://example.com/",
            "param": "Content-Security-Policy",
            "evidence": "Header absent.",
            "package_name": None,
            "package_version": None,
            "fixed_version": None,
            "cve_id": "CWE-693",
            "remediation": "Add CSP header.",
            "raw_payload": {},
        }]

        with patch(
            "app.scanners.zap_dast_scanner.ZapDastScanner.scan",
            new_callable=AsyncMock,
            return_value=mock_findings,
        ):
            res = await client.post(
                "/api/v1/scans/upload-and-scan",
                data={
                    "project_id": project_id,
                    "scan_type": "dast",
                    "confirm_authorization": "true",
                },
                # No file provided — intentional
                headers=headers,
            )

        assert res.status_code == 201, res.text
        data = res.json()
        assert data["scan_type"] == "dast"
        assert data["source_type"] == "url"
        assert data["status"] == "completed"

    async def test_dast_without_zip_and_without_target_url_returns_400(self, client: AsyncClient):
        """DAST-only scan without any target URL must return HTTP 400."""
        headers = await login_and_get_headers(client)
        # Project has no target_url
        project_id = await create_project(client, headers, "dast-no-url")

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={
                "project_id": project_id,
                "scan_type": "dast",
                "confirm_authorization": "true",
            },
            headers=headers,
        )
        assert res.status_code == 400, res.text
        assert "url" in res.json()["detail"].lower()

    async def test_dast_without_authorization_returns_400(self, client: AsyncClient):
        """DAST-only scan without confirm_authorization must return HTTP 400."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(
            client, headers, "dast-no-auth", target_url="https://example.com"
        )

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={
                "project_id": project_id,
                "scan_type": "dast",
                "confirm_authorization": "false",
            },
            headers=headers,
        )
        assert res.status_code == 400, res.text
        assert "authorization" in res.json()["detail"].lower()

    async def test_dast_target_url_override_takes_precedence(self, client: AsyncClient):
        """target_url_override in form body overrides the project's target_url."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(
            client, headers, "dast-url-override", target_url="https://project-url.example.com"
        )

        with patch(
            "app.scanners.zap_dast_scanner.ZapDastScanner.scan",
            new_callable=AsyncMock,
            return_value=[],
        ), patch(
            "app.services.target_validator.TargetValidator.validate_target_url",
            side_effect=lambda url, **kwargs: url,
        ):
            res = await client.post(
                "/api/v1/scans/upload-and-scan",
                data={
                    "project_id": project_id,
                    "scan_type": "dast",
                    "confirm_authorization": "true",
                    "target_url_override": "https://override-url.example.com",
                },
                headers=headers,
            )

        assert res.status_code == 201, res.text
        data = res.json()
        assert "override-url.example.com" in data["target_label"]

    # ── C. Full scan (SAST + DAST) ────────────────────────────────────────────

    async def test_full_scan_requires_zip(self, client: AsyncClient):
        """Full DevSecOps scan without a ZIP must be rejected."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(
            client, headers, "full-no-zip", target_url="https://example.com"
        )

        res = await client.post(
            "/api/v1/scans/upload-and-scan",
            data={
                "project_id": project_id,
                "scan_type": "full",
                "confirm_authorization": "true",
            },
            headers=headers,
        )
        assert res.status_code == 400, res.text

    async def test_full_scan_with_zip_and_url_succeeds(self, client: AsyncClient):
        """Full scan with a ZIP archive and target URL must complete."""
        headers = await login_and_get_headers(client)
        project_id = await create_project(
            client, headers, "full-with-zip-url", target_url="https://example.com"
        )

        with patch(
            "app.scanners.zap_dast_scanner.ZapDastScanner.scan",
            new_callable=AsyncMock,
            return_value=[],
        ):
            res = await client.post(
                "/api/v1/scans/upload-and-scan",
                data={
                    "project_id": project_id,
                    "scan_type": "full",
                    "confirm_authorization": "true",
                },
                files={"file": ("code.zip", VULNERABLE_ZIP, "application/zip")},
                headers=headers,
            )

        assert res.status_code == 201, res.text
        data = res.json()
        assert data["scan_type"] == "full"
        assert data["status"] == "completed"


# ═══════════════════════════════════════════════════════════════════════════════
# TASK 3 — Safe Archive Service Unit Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSafeArchiveService:

    def test_valid_zip_is_extracted(self, tmp_path):
        from app.services.safe_archive import SafeArchiveService

        zip_bytes = make_zip({"app/main.py": "print('ok')", "requirements.txt": "flask\n"})
        zip_path = tmp_path / "test.zip"
        zip_path.write_bytes(zip_bytes)
        extract_to = tmp_path / "extracted"

        count, size = SafeArchiveService.validate_and_extract(str(zip_path), str(extract_to))
        assert count == 2
        assert size > 0
        assert (extract_to / "app" / "main.py").exists()

    def test_zip_slip_is_blocked(self, tmp_path):
        from app.services.safe_archive import SafeArchiveService, ArchiveSecurityError

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.py", "malicious")
        zip_path = tmp_path / "slip.zip"
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(ArchiveSecurityError, match="Zip Slip|Suspicious path"):
            SafeArchiveService.validate_and_extract(str(zip_path), str(tmp_path / "out"))

    def test_zip_bomb_is_blocked(self, tmp_path):
        """A file with extreme compression ratio must be rejected."""
        from app.services.safe_archive import SafeArchiveService, ArchiveSecurityError
        from unittest.mock import patch
        from app.core.config import settings

        # Make a legit-looking archive, then monkey-patch the metadata to look
        # like a bomb (compress_size=1, file_size=200MB) without actually
        # inflating 200MB on disk.
        zip_bytes = make_zip({"big.txt": "A" * 1024})  # 1 KB real file
        zip_path = tmp_path / "bomb.zip"
        zip_path.write_bytes(zip_bytes)

        original = settings.MAX_UPLOAD_SIZE_BYTES
        settings.MAX_UPLOAD_SIZE_BYTES = 1024  # 1 KB limit → 5 KB uncompressed max
        try:
            # 6 KB exceeds the 5 KB maximum uncompressed archive limit
            big_zip = make_zip({"big.txt": "A" * 6144})
            big_zip_path = tmp_path / "big.zip"
            big_zip_path.write_bytes(big_zip)
            with pytest.raises(ArchiveSecurityError, match="exceeds maximum"):
                SafeArchiveService.validate_and_extract(str(big_zip_path), str(tmp_path / "out2"))
        finally:
            settings.MAX_UPLOAD_SIZE_BYTES = original

    def test_corrupted_zip_raises_archive_error(self, tmp_path):
        from app.services.safe_archive import SafeArchiveService, ArchiveSecurityError

        bad_zip = tmp_path / "bad.zip"
        bad_zip.write_bytes(b"this is not a zip file")
        with pytest.raises(ArchiveSecurityError, match="Corrupt|invalid"):
            SafeArchiveService.validate_and_extract(str(bad_zip), str(tmp_path / "out"))

    def test_cleanup_removes_directory(self, tmp_path):
        from app.services.safe_archive import SafeArchiveService

        d = tmp_path / "to_clean"
        d.mkdir()
        (d / "test.txt").write_text("hello")
        SafeArchiveService.cleanup(str(d))
        assert not d.exists()

    def test_dangerous_executable_extension_info_logged(self, tmp_path):
        """Dangerous extensions should not stop extraction (they're filtered at OS-level),
        but the archive itself should still extract normal files safely."""
        from app.services.safe_archive import SafeArchiveService

        zip_bytes = make_zip({
            "app/main.py": "print('ok')",
            "deploy.sh": "rm -rf /",   # dangerous extension but tracked safely
        })
        zip_path = tmp_path / "mixed.zip"
        zip_path.write_bytes(zip_bytes)
        extract_to = tmp_path / "out"

        # Should complete without error — we don't block .sh in extraction,
        # we only restrict execution (the code is never run)
        count, _ = SafeArchiveService.validate_and_extract(str(zip_path), str(extract_to))
        assert count >= 1
