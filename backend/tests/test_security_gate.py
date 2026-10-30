"""
Automated tests for CI/CD Security Gate Evaluation.
"""
from app.models.policy import SecurityPolicy
from app.services.security_gate import SecurityGateEvaluator


class TestSecurityGate:
    def test_gate_passes_clean_scan(self):
        findings = [
            {"severity": "low", "category": "sast", "status": "open"},
            {"severity": "medium", "category": "dast", "status": "open"},
        ]
        result = SecurityGateEvaluator.evaluate(findings)
        assert result.passed is True
        assert result.status == "passed"
        assert result.critical_count == 0
        assert result.high_count == 0

    def test_gate_fails_on_critical(self):
        findings = [
            {"severity": "critical", "category": "sast", "status": "open"},
        ]
        result = SecurityGateEvaluator.evaluate(findings)
        assert result.passed is False
        assert result.status == "failed"
        assert any("Found 1 Critical" in r for r in result.reasons)

    def test_gate_fails_on_secret(self):
        findings = [
            {"severity": "high", "category": "secret", "status": "open"},
        ]
        result = SecurityGateEvaluator.evaluate(findings)
        assert result.passed is False
        assert result.secret_count == 1
        assert any("Detected 1 exposed secret" in r for r in result.reasons)

    def test_gate_ignores_fixed_findings(self):
        findings = [
            {"severity": "critical", "category": "sast", "status": "fixed"},
            {"severity": "high", "category": "secret", "status": "closed"},
        ]
        result = SecurityGateEvaluator.evaluate(findings)
        assert result.passed is True
        assert result.status == "passed"
