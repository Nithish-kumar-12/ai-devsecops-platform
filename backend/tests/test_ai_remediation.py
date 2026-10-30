import pytest

from app.services.ai_remediation import (
    AIRemediationService,
    REMEDIATION_KNOWLEDGE_BASE,
)


class TestAIRemediation:
    def test_pickle_title_routes_to_pickle_template(self):
        finding = {"title": "Avoid Pickle", "rule_id": "python-rule", "evidence": "data.txt"}
        template = AIRemediationService._select_template(finding)
        assert template == REMEDIATION_KNOWLEDGE_BASE["pickle"]

    def test_pickle_rule_and_evidence_route_narrowly(self):
        rule_finding = {"title": "Serialization", "rule_id": "avoid_pickle", "evidence": ""}
        evidence_finding = {"title": "Loading data", "rule_id": "some-rule", "evidence": "result = pickle.load(source)"}
        unrelated_finding = {"title": "Pickle documentation", "rule_id": "docs", "evidence": "Reference only"}

        assert AIRemediationService._select_template(rule_finding) is not None
        assert AIRemediationService._select_template(evidence_finding) is not None
        assert AIRemediationService._select_template(unrelated_finding) is None

    @pytest.mark.asyncio
    async def test_pickle_guidance_is_cautious_and_ml_aware(self):
        finding = {"title": "Avoid Pickle", "rule_id": "avoid_pickle", "evidence": "pickle.load(model_file)"}
        advice = await AIRemediationService.generate_remediation(finding)
        combined = " ".join(advice.values()).lower()

        assert "arbitrary code" in combined
        assert "does not prove" in combined
        assert "trusted independent source" in combined
        assert "scikit-learn" in combined
        assert "artificially_verified" not in combined

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_sca_scikit_learn_advisory_has_exact_metadata(self):
        finding = {
            "title": "Vulnerable dependency: scikit-learn==1.4.1",
            "rule_id": "GHSA-jw8x-6495-233v",
            "category": "sca",
            "description": "Sensitive data leakage vulnerability",
            "evidence": "Package: scikit-learn==1.4.1\nAdvisory: GHSA-jw8x-6495-233v\nCVE: CVE-2024-5206",
            "package_name": "scikit-learn",
            "package_version": "1.4.1",
            "fixed_version": "1.5.0",
            "cve_id": "CVE-2024-5206",
            "file_path": "requirements.txt",
            "line_number": 4,
        }
        advice = await AIRemediationService.generate_remediation(finding)
        combined = " ".join(advice.values())

        assert "scikit-learn==1.4.1" in combined
        assert "CVE-2024-5206 / GHSA-jw8x-6495-233v" in combined
        assert "1.4.1.post1" in combined
        assert "1.5.0" in combined
        assert "- scikit-learn==1.4.1" in advice["fix_diff"]
        assert "+ scikit-learn==1.5.0" in advice["fix_diff"]
        assert "pickle/joblib" in combined

    @pytest.mark.asyncio
    async def test_sca_missing_advisory_metadata_is_explicit_and_cautious(self):
        finding = {
            "title": "Vulnerable dependency: example-package@3.2.1",
            "rule_id": "unknown",
            "category": "sca",
            "description": "No advisory summary supplied",
            "package_name": "example-package",
            "package_version": "3.2.1",
            "fixed_version": None,
            "cve_id": None,
            "evidence": "Package: example-package==3.2.1",
            "file_path": "requirements.txt",
            "line_number": 9,
        }
        advice = await AIRemediationService.generate_remediation(finding)
        combined = " ".join(advice.values())

        assert "example-package==3.2.1" in combined
        assert "none supplied" in combined.lower()
        assert "enough advisory metadata" in combined.lower()
        assert "do not guess a fixed version" in combined.lower()
        assert "No verified code-specific dependency fix is available" in advice["fix_diff"]

    async def test_unrecognized_finding_uses_cautious_fallback(self):
        finding = {
            "title": "Custom scanner issue",
            "rule_id": "custom-rule",
            "category": "sast",
            "description": "A custom rule detected an event.",
            "evidence": "inspect this value",
            "file_path": "src/example.py",
            "line_number": 42,
        }
        advice = await AIRemediationService.generate_remediation(finding)

        assert "No verified code-specific fix is available" in advice["fix_diff"]
        assert "src/example.py" in advice["analysis"]
        assert "line 42" in advice["analysis"]
