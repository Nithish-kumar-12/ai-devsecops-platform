"""
Unified Vulnerability Correlation Engine.
Correlates findings across SAST, DAST, Secret Detection, and SCA.
Identifies confirmed matches, likely matches, and preserves raw scanner provenance.
"""
import uuid
from typing import Any, Dict, List


class CorrelationEngine:
    """
    Analyzes findings across multiple security vectors and links correlated findings.
    """

    @classmethod
    def correlate_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes list of findings, groups correlated issues, assigns correlation_group_id,
        and provides clear explanation for links.
        """
        if not findings:
            return []

        # We keep track of assigned groups
        groups: List[Dict[str, Any]] = []

        for finding in findings:
            matched_group = None
            match_type = None
            match_reason = None

            # Compare against existing groups
            for group in groups:
                rep = group["representative"]

                # 1. Check for Confirmed Cross-Vector Match (SAST <-> DAST)
                if (
                    (finding.get("category") == "sast" and rep.get("category") == "dast")
                    or (finding.get("category") == "dast" and rep.get("category") == "sast")
                ):
                    # Check matching endpoint or parameter
                    f_param = (finding.get("param") or "").lower()
                    r_param = (rep.get("param") or "").lower()
                    f_end = (finding.get("endpoint") or "").lower()
                    r_end = (rep.get("endpoint") or "").lower()

                    if f_param and r_param and f_param == r_param:
                        match_type = "confirmed"
                        match_reason = f"Confirmed cross-vector finding: SAST and DAST both identified issue impacting parameter '{f_param}'."
                        matched_group = group
                        break

                    # Check route overlap with source file
                    if f_end or r_end:
                        file_p = (finding.get("file_path") or rep.get("file_path") or "").lower()
                        end_p = (f_end or r_end).split("?")[0]
                        route_name = end_p.rstrip("/").split("/")[-1]
                        if route_name and route_name in file_p and len(route_name) > 3:
                            match_type = "likely"
                            match_reason = f"Likely cross-vector correlation: SAST file '{file_p}' maps to DAST endpoint route '{route_name}'."
                            matched_group = group
                            break

                # 2. Check for Same-Vector Duplicate / Overlapping Findings
                # Same file + same line / rule
                if (
                    finding.get("file_path")
                    and rep.get("file_path")
                    and finding.get("file_path") == rep.get("file_path")
                ):
                    f_line = finding.get("line_number")
                    r_line = rep.get("line_number")
                    if f_line and r_line and abs(f_line - r_line) <= 3:
                        match_type = "confirmed"
                        match_reason = f"Confirmed co-located findings in {finding.get('file_path')} within lines {min(f_line, r_line)}-{max(f_line, r_line)}."
                        matched_group = group
                        break

                # 3. Same Dependency in SCA
                if (
                    finding.get("category") == "sca"
                    and rep.get("category") == "sca"
                    and finding.get("package_name")
                    and finding.get("package_name") == rep.get("package_name")
                ):
                    match_type = "likely"
                    match_reason = f"Shared vulnerable package '{finding.get('package_name')}' flagged across multiple advisories."
                    matched_group = group
                    break

            if matched_group:
                finding["correlation_group_id"] = matched_group["id"]
                finding["correlation_reason"] = match_reason
                matched_group["members"].append(finding)
            else:
                new_group_id = str(uuid.uuid4())
                finding["correlation_group_id"] = new_group_id
                finding["correlation_reason"] = "Distinct security finding (no cross-vector correlation detected)."
                groups.append({
                    "id": new_group_id,
                    "representative": finding,
                    "members": [finding],
                })

        return findings
