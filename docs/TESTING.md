# Automated Testing & Verification Report

This document records the automated testing architecture, verification commands, and actual test results for the **AI DevSecOps Platform**.

---

## Backend Test Suite (Pytest)

The backend test suite contains **72 automated unit and integration tests** covering the platform's API, scanners, archive handling, risk pipeline, and workflows.

### Running Backend Tests
From the `backend/` directory:
```powershell
.\.venv\Scripts\python.exe -m pytest tests\ -v
```

### Verified Test Results (72 Passed)

Latest run: 72 passed in 168.14 seconds with 79% total backend coverage. Scan-evidence regression tests verify uploaded-source evidence, corrected rescans, and historical scan association.

### Representative Coverage

| Test Module | Test Case | Status | Coverage Focus |
|---|---|---|---|
| `test_auth.py` | `test_register_user_success` | PASSED | User registration, password hashing, role assignment |
| `test_auth.py` | `test_register_duplicate_email_fails` | PASSED | Unique email constraint enforcement |
| `test_auth.py` | `test_login_success` | PASSED | Password verification & JWT access/refresh token generation |
| `test_auth.py` | `test_login_invalid_password_fails` | PASSED | Invalid credentials rejection with 401 |
| `test_auth.py` | `test_get_me_with_bearer_token` | PASSED | Bearer token authentication & profile extraction |
| `test_auth.py` | `test_get_me_unauthorized_without_token`| PASSED | 401 Unauthorized guard on protected endpoints |
| `test_safe_archive.py` | `test_valid_archive_extraction` | PASSED | Safe zip extraction and file count accounting |
| `test_safe_archive.py` | `test_zip_slip_traversal_blocked` | PASSED | Zip Slip `../evil.txt` path escape prevention |
| `test_safe_archive.py` | `test_absolute_path_entry_blocked` | PASSED | Absolute path `/etc/passwd` entry rejection |
| `test_safe_archive.py` | `test_excessive_file_count_blocked`| PASSED | Archive bomb / excessive file count mitigation |
| `test_target_validator.py` | `test_valid_public_https_url` | PASSED | Allowed HTTP/HTTPS public endpoint validation |
| `test_target_validator.py` | `test_empty_url_rejected` | PASSED | Empty target rejection |
| `test_target_validator.py` | `test_unsupported_scheme_rejected`| PASSED | FTP/dangerous protocol rejection |
| `test_target_validator.py` | `test_cloud_metadata_ip_rejected` | PASSED | Cloud metadata 169.254.169.254 unconditional blocking |
| `test_target_validator.py` | `test_localhost_blocked_by_default`| PASSED | Default blocking of localhost and private subnets |
| `test_target_validator.py` | `test_localhost_permitted_with_explicit_local_override` | PASSED | Controlled opt-in for academic lab targets |
| `test_scanners.py` | `test_secret_redaction` | PASSED | Credential masking (`AKIA***MPLE`) in evidence |
| `test_scanners.py` | `test_gitleaks_builtin_engine_detects_secret` | PASSED | Regex fallback secret engine detection |
| `test_scanners.py` | `test_dependency_scanner_manifest_detection` | PASSED | requirements.txt vulnerable package detection & fix recommendation |
| `test_scanners.py` | `test_dast_requires_authorization` | PASSED | DAST authorization confirmation requirement |
| `test_scanners.py` | `test_semgrep_availability` | PASSED | Real Semgrep CLI integration check |
| `test_correlation_and_risk.py` | `test_cross_vector_confirmed_correlation` | PASSED | SAST parameter & DAST endpoint correlation |
| `test_correlation_and_risk.py` | `test_unrelated_findings_distinct_groups` | PASSED | Distinct vulnerability grouping |
| `test_correlation_and_risk.py` | `test_risk_prioritization_calculation` | PASSED | Deterministic 0.1–10.0 risk scoring & sorting |
| `test_security_gate.py` | `test_gate_passes_clean_scan` | PASSED | Clean scan gate approval |
| `test_security_gate.py` | `test_gate_fails_on_critical` | PASSED | Gate failure on Critical findings |
| `test_security_gate.py` | `test_gate_fails_on_secret` | PASSED | Gate failure on exposed secrets |
| `test_security_gate.py` | `test_gate_ignores_fixed_findings` | PASSED | Gate pass on resolved/fixed findings |
| `test_health.py` | 7 Health & Readiness Tests | PASSED | API liveness, readiness probes, and schema access |
| `test_api_workflow.py` | `test_complete_platform_workflow` | PASSED | End-to-end integration test: User -> Project -> ZIP Upload -> Scan -> Correlation -> Risk -> Gate -> AI Remediation -> Export |
| `test_scan_evidence.py` | uploaded scan evidence regression tests | PASSED | Exact uploaded-source evidence and historical scan association |
| `test_upload_and_dast.py` | upload and authorized DAST workflows | PASSED | ZIP validation, upload limits, authorization, and scan lifecycle |

---

## Frontend Test Suite (Vitest)

The frontend test suite contains **10 automated tests** verifying UI rendering, lifecycle updates, and AI remediation feedback.

### Running Frontend Tests
From the `frontend/` directory:
```powershell
npm test
```

### Verified Test Results (10 Passed)
- `App (Phase 1 scaffold) > renders the platform title`: PASS
- `App (Phase 1 scaffold) > renders the phase completion indicator`: PASS
- `App (Phase 1 scaffold) > renders the API health link`: PASS
- `App (Phase 1 scaffold) > renders the API docs link`: PASS
- `State Synchronization & AI Remediation`: 6 tests passed, including API failure and immediate state update handling.

---

## Production Build Verification
From the `frontend/` directory:
```powershell
npm run build
```
- TypeScript check (`tsc`): PASSED (0 errors)
- Vite bundling: PASSED (dist/ chunks generated)
- Latest production build: PASSED; Vite transformed 2,431 modules.
