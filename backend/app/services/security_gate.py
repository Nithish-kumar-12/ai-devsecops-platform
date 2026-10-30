"""
CI/CD Security Gate Evaluation Engine.
Evaluates scan findings against configurable project policies and produces
deterministic pass/fail decisions with machine-readable summaries.
"""
from typing import Any, Dict, List, Optional
from app.models.policy import SecurityPolicy
from app.schemas.policy import GateEvaluationResult


class SecurityGateEvaluator:
    @classmethod
    def evaluate(
        cls,
        findings: List[Dict[str, Any]],
        policy: Optional[SecurityPolicy] = None,
    ) -> GateEvaluationResult:
        """
        Evaluates findings against a security policy.
        If policy is None, default strict gate policy is applied:
        - 0 Criticals allowed
        - 0 Highs allowed
        - Max 5 Mediums
        - Secrets strictly blocked
        """
        policy_name = policy.name if policy else "Default Zero-Tolerance Policy"
        fail_on_critical = policy.fail_on_critical if policy else True
        fail_on_high = policy.fail_on_high if policy else True
        max_crit = policy.max_critical if policy else 0
        max_high = policy.max_high if policy else 0
        max_med = policy.max_medium if policy else 5
        block_secrets = policy.block_on_secrets if policy else True

        # Count active/open findings
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        secret_count = 0

        for f in findings:
            status = (f.get("status") or "open").lower()
            if status in ("fixed", "closed"):
                continue  # Ignore resolved findings

            sev = (f.get("severity") or "medium").lower()
            cat = (f.get("category") or "").lower()

            if sev == "critical":
                crit_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                med_count += 1
            elif sev == "low":
                low_count += 1

            if cat == "secret":
                secret_count += 1

        reasons: List[str] = []

        if fail_on_critical and crit_count > max_crit:
            reasons.append(
                f"Gate failed: Found {crit_count} Critical finding(s), threshold allows maximum {max_crit}."
            )

        if fail_on_high and high_count > max_high:
            reasons.append(
                f"Gate failed: Found {high_count} High finding(s), threshold allows maximum {max_high}."
            )

        if med_count > max_med:
            reasons.append(
                f"Gate failed: Found {med_count} Medium finding(s), threshold allows maximum {max_med}."
            )

        if block_secrets and secret_count > 0:
            reasons.append(
                f"Gate failed: Detected {secret_count} exposed secret(s). Policy strictly forbids hardcoded credentials."
            )

        passed = len(reasons) == 0

        return GateEvaluationResult(
            passed=passed,
            status="passed" if passed else "failed",
            policy_name=policy_name,
            reasons=reasons if reasons else ["All security thresholds met. Ready for deployment pipeline."],
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            secret_count=secret_count,
        )
