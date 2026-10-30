"""
Risk Prioritization and Scoring Engine.
Computes clear, transparent risk scores (0.0 to 10.0) based on severity,
confidence, exposure context, and exploitability signals without inventing data.
"""
from typing import Any, Dict, List


class RiskPrioritizer:
    BASE_SEVERITY_SCORES = {
        "critical": 9.2,
        "high": 7.2,
        "medium": 4.5,
        "low": 2.0,
    }

    CONFIDENCE_WEIGHTS = {
        "high": 0.5,
        "medium": 0.0,
        "low": -0.5,
        "unknown": -0.2,
    }

    @classmethod
    def calculate_risk_score(cls, finding: Dict[str, Any]) -> float:
        """
        Calculates a deterministic risk score from 0.1 to 10.0.
        """
        sev = (finding.get("severity") or "medium").lower()
        base = cls.BASE_SEVERITY_SCORES.get(sev, 4.5)

        # Confidence modifier
        conf = (finding.get("confidence") or "medium").lower()
        conf_mod = cls.CONFIDENCE_WEIGHTS.get(conf, 0.0)

        # Category and exposure modifier
        cat = (finding.get("category") or "").lower()
        cat_mod = 0.0
        if cat == "secret":
            # Hardcoded secrets have immediate exploitability
            cat_mod = 0.5
        elif cat == "dast":
            # DAST findings indicate runtime exposure on active endpoint
            cat_mod = 0.4
        elif cat == "sca" and finding.get("cve_id"):
            # Known public CVE
            cat_mod = 0.3

        score = base + conf_mod + cat_mod
        return round(max(0.1, min(10.0, score)), 1)

    @classmethod
    def prioritize_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Assigns risk score and sorts findings by priority descending.
        """
        for f in findings:
            f["risk_score"] = cls.calculate_risk_score(f)

        # Sort: highest risk_score first
        findings.sort(key=lambda x: x.get("risk_score", 0.0), reverse=True)
        return findings
