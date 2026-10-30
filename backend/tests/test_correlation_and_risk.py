"""
Automated tests for Unified Finding Correlation and Risk Prioritization.
"""
from app.pipeline.correlation import CorrelationEngine
from app.pipeline.risk_prioritizer import RiskPrioritizer


class TestCorrelationAndRisk:
    def test_cross_vector_confirmed_correlation(self):
        findings = [
            {
                "category": "sast",
                "param": "user_id",
                "endpoint": None,
                "file_path": "app/users.py",
                "line_number": 45,
                "title": "SQL Injection in User Lookup",
                "severity": "high",
            },
            {
                "category": "dast",
                "param": "user_id",
                "endpoint": "https://api.target.com/users",
                "file_path": None,
                "line_number": None,
                "title": "SQL Injection Detected on Endpoint",
                "severity": "critical",
            },
        ]

        correlated = CorrelationEngine.correlate_findings(findings)
        assert len(correlated) == 2
        # Both must share the same correlation_group_id
        assert correlated[0]["correlation_group_id"] == correlated[1]["correlation_group_id"]
        assert "Confirmed cross-vector finding" in correlated[1]["correlation_reason"]

    def test_unrelated_findings_distinct_groups(self):
        findings = [
            {
                "category": "sast",
                "param": None,
                "file_path": "frontend/auth.ts",
                "line_number": 10,
                "title": "Insecure LocalStorage",
                "severity": "low",
            },
            {
                "category": "sca",
                "param": None,
                "package_name": "requests",
                "title": "Vulnerable requests package",
                "severity": "medium",
            },
        ]

        correlated = CorrelationEngine.correlate_findings(findings)
        assert correlated[0]["correlation_group_id"] != correlated[1]["correlation_group_id"]

    def test_risk_prioritization_calculation(self):
        crit_finding = {
            "title": "AWS Secret Key Exposed",
            "category": "secret",
            "severity": "critical",
            "confidence": "high",
        }
        med_finding = {
            "title": "Missing Header",
            "category": "dast",
            "severity": "medium",
            "confidence": "low",
        }

        crit_score = RiskPrioritizer.calculate_risk_score(crit_finding)
        med_score = RiskPrioritizer.calculate_risk_score(med_finding)

        assert crit_score > med_score
        assert crit_score >= 9.0
        assert med_score < 7.0

        sorted_list = RiskPrioritizer.prioritize_findings([med_finding, crit_finding])
        assert sorted_list[0]["title"] == "AWS Secret Key Exposed"
