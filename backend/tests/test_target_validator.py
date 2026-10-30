"""
Automated tests for DAST Target URL and SSRF validation.
"""
import pytest
from app.services.target_validator import TargetValidationError, TargetValidator


class TestTargetValidator:
    def test_valid_public_https_url(self):
        url = "https://example.com/api/test"
        validated = TargetValidator.validate_target_url(url)
        assert validated == url

    def test_empty_url_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            TargetValidator.validate_target_url("")
        assert "empty" in str(exc.value).lower()

    def test_unsupported_scheme_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            TargetValidator.validate_target_url("ftp://example.com/file")
        assert "Unsupported URL scheme" in str(exc.value)

    def test_cloud_metadata_ip_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            TargetValidator.validate_target_url(
                "http://169.254.169.254/latest/meta-data/"
            )
        assert "cloud metadata" in str(exc.value).lower()

    def test_localhost_blocked_by_default(self, monkeypatch):
        # Test default security behavior regardless of the local .env setting.
        monkeypatch.setattr(
            "app.services.target_validator.settings.ALLOW_LOCAL_TARGETS",
            False,
        )

        with pytest.raises(TargetValidationError) as exc:
            TargetValidator.validate_target_url("http://127.0.0.1:8000/api")

        assert (
            "private/restricted ip" in str(exc.value).lower()
            or "forbidden" in str(exc.value).lower()
        )

    def test_localhost_permitted_with_explicit_local_override(self):
        # Controlled opt-in for local student lab target.
        validated = TargetValidator.validate_target_url(
            "http://127.0.0.1:8000/api",
            allow_local_override=True,
        )
        assert validated == "http://127.0.0.1:8000/api"
