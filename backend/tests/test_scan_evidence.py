import io
import json
import zipfile
from types import SimpleNamespace

import pytest

from app.scanners.semgrep_scanner import SemgrepScanner


VULNERABLE_LINE = "app.run(debug=True, host='0.0.0.0', port=5000)"
CORRECTED_LINE = "app.run(debug=False, host='127.0.0.1', port=5000)"
SOURCE_PATH = "sql_defence_system/backend/app.py"


def make_source_zip(source: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(SOURCE_PATH, source)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_semgrep_normalizes_evidence_from_the_scan_result(tmp_path, monkeypatch):
    source = f"from flask import Flask\n{VULNERABLE_LINE}\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    scanner = SemgrepScanner()
    monkeypatch.setattr(scanner, "is_available", lambda: True)
    monkeypatch.setattr(scanner, "_get_executable", lambda: "semgrep")
    monkeypatch.setattr(
        "app.scanners.semgrep_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "Avoid_App_Run_With_Bad_Host",
                            "path": "app.py",
                            "start": {"line": 2, "col": 1},
                            "extra": {
                                "severity": "ERROR",
                                "message": "Unsafe Flask development server configuration",
                                "lines": VULNERABLE_LINE,
                                "metadata": {},
                            },
                        }
                    ]
                }
            ),
            stderr="",
        ),
    )

    findings = await scanner.scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["file_path"] == "app.py"
    assert findings[0]["line_number"] == 2
    assert findings[0]["evidence"] == VULNERABLE_LINE


def test_semgrep_evidence_comes_from_scanned_source_not_stale_output(tmp_path):
    source_file = tmp_path / "app.py"
    source_file.write_text(
        f"from flask import Flask\n{CORRECTED_LINE}\n",
        encoding="utf-8",
    )

    evidence = SemgrepScanner()._get_source_snippet(
        target_path=str(tmp_path),
        raw_path="app.py",
        line_number=2,
        semgrep_lines=VULNERABLE_LINE,
    )

    assert evidence == CORRECTED_LINE
    assert VULNERABLE_LINE not in evidence


@pytest.mark.asyncio
async def test_uploaded_scans_keep_evidence_and_findings_per_scan(
    client, monkeypatch
):
    registration = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "scan-evidence@example.com",
            "password": "Password123!",
            "full_name": "Scan Evidence Tester",
        },
    )
    assert registration.status_code == 201, registration.text
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "scan-evidence@example.com", "password": "Password123!"},
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    project_response = await client.post(
        "/api/v1/projects",
        json={"name": "scan-evidence-regression", "description": "test"},
        headers=headers,
    )
    assert project_response.status_code == 201, project_response.text
    project_id = project_response.json()["id"]

    async def scan_source(self, target_path, **kwargs):
        from pathlib import Path

        source_file = Path(target_path) / SOURCE_PATH
        source = source_file.read_text(encoding="utf-8")
        line_number = next(
            index
            for index, line in enumerate(source.splitlines(), start=1)
            if line.startswith("app.run(")
        )
        matched_line = source.splitlines()[line_number - 1]
        if "debug=True" not in matched_line or "0.0.0.0" not in matched_line:
            return []
        return [
            {
                "scanner": "semgrep",
                "rule_id": "Avoid_App_Run_With_Bad_Host",
                "title": "Avoid App Run With Bad Host",
                "description": "Unsafe Flask development server configuration",
                "category": "sast",
                "severity": "critical",
                "confidence": "high",
                "file_path": SOURCE_PATH,
                "line_number": line_number,
                "column_number": 1,
                "evidence": matched_line,
                "raw_payload": {"source_line": matched_line},
            }
        ]

    monkeypatch.setattr(SemgrepScanner, "is_available", lambda self: True)
    monkeypatch.setattr(SemgrepScanner, "scan", scan_source)

    vulnerable_response = await client.post(
        "/api/v1/scans/upload-and-scan",
        data={"project_id": project_id, "scan_type": "sast"},
        files={
            "file": (
                "vulnerable-source.zip",
                make_source_zip(f"from flask import Flask\n{VULNERABLE_LINE}\n"),
                "application/zip",
            )
        },
        headers=headers,
    )
    assert vulnerable_response.status_code == 201, vulnerable_response.text
    vulnerable_scan = vulnerable_response.json()
    assert len(vulnerable_scan["findings"]) == 1
    vulnerable_finding = vulnerable_scan["findings"][0]
    assert vulnerable_finding["file_path"] == SOURCE_PATH
    assert vulnerable_finding["line_number"] == 2
    assert vulnerable_finding["evidence"] == VULNERABLE_LINE
    assert vulnerable_finding["scan_id"] == vulnerable_scan["id"]

    corrected_response = await client.post(
        "/api/v1/scans/upload-and-scan",
        data={"project_id": project_id, "scan_type": "sast"},
        files={
            "file": (
                "corrected-source.zip",
                make_source_zip(f"from flask import Flask\n{CORRECTED_LINE}\n"),
                "application/zip",
            )
        },
        headers=headers,
    )
    assert corrected_response.status_code == 201, corrected_response.text
    corrected_scan = corrected_response.json()
    assert corrected_scan["id"] != vulnerable_scan["id"]
    assert corrected_scan["findings"] == []

    project_findings = await client.get(
        f"/api/v1/findings/project/{project_id}", headers=headers
    )
    assert project_findings.status_code == 200, project_findings.text
    assert len(project_findings.json()) == 1
    assert project_findings.json()[0]["scan_id"] == vulnerable_scan["id"]

    current_findings = await client.get(
        f"/api/v1/findings/project/{project_id}",
        params={"scan_id": corrected_scan["id"]},
        headers=headers,
    )
    assert current_findings.status_code == 200, current_findings.text
    assert current_findings.json() == []

    historical_findings = await client.get(
        f"/api/v1/findings/project/{project_id}",
        params={"scan_id": vulnerable_scan["id"]},
        headers=headers,
    )
    assert historical_findings.status_code == 200, historical_findings.text
    assert historical_findings.json()[0]["evidence"] == VULNERABLE_LINE

    historical_scan_details = await client.get(
        f"/api/v1/scans/{vulnerable_scan['id']}", headers=headers
    )
    assert historical_scan_details.status_code == 200
    assert historical_scan_details.json()["findings"][0]["scan_id"] == vulnerable_scan["id"]
