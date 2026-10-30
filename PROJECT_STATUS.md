# Project Status: AI-Powered Application Security Testing and DevSecOps Platform

> Last updated: 2026-10-26 | Latest measured run: **72 Backend Tests PASSED (79% Coverage) + 10 Frontend Tests PASSED + Production Build Clean**. PDF and refresh-token workflows are included in the backend suite.

---

## Current Baseline (2026-10-26)

| Check | Result |
|---|---|
| Backend pytest | 72 passed, 79% coverage |
| Frontend Vitest | 10 passed across 2 test files |
| Frontend production build | Passed with TypeScript and Vite |
| Public registration role | Forced to `developer`; requested roles cannot self-promote to `admin` |
| Cross-user scan/report access | Status, gate, JSON export, and CSV export endpoints enforce project ownership |
| AI remediation | Deterministic templates plus optional Gemini/OpenAI fallback; scanner evidence remains advisory |
| Git repository integration | Not implemented as a checkout workflow; Git URLs remain project metadata |
| PDF reports | Implemented | ReportLab generates authorized scan reports with scope, timestamps, severity summary, gate result, and findings |
| Private Git checkout | Not implemented | ZIP uploads remain the supported source workflow |
| Token refresh | Implemented | Refresh tokens issue a new access/refresh pair; access and refresh types are separated |


## Feature Checklist

- Implemented: authentication, project CRUD, ZIP upload defenses, Semgrep SAST integration, secret/SCA/authorized DAST paths, findings, lifecycle updates, correlation, risk scoring, exports, and security gates.
- Partially Implemented: scanner availability depends on installed services/tools; source-grounded AI patches depend on available scanner snippets and model context; DAST is passive/fallback-oriented unless ZAP is available.
- Partially Implemented: private Git checkout is intentionally not implemented; public repository URLs are project metadata only.
- Not Implemented: automatic deployment, multi-factor authentication, and independently confirmed exploitability.

## Phase Progress Summary

| # | Phase | Status | Verified Deliverables & Test Verification |
|---|---|---|---|
| **Phase 1** | Project setup & architecture | ✅ Complete | FastAPI ASGI app, structlog logging, Pydantic v2 config, health/readiness endpoints |
| **Phase 2** | Database models & migrations | ✅ Complete | SQLAlchemy 2.0 ORM models (`User`, `Project`, `Scan`, `Finding`, `AuditLog`, `SecurityPolicy`), Alembic migrations applied to SQLite |
| **Phase 3** | Authentication & RBAC | ✅ Complete | Native `bcrypt` password hashing, JWT Bearer token authentication, user registration, login, role checks |
| **Phase 4** | Project management & safe archive | ✅ Complete | Project CRUD endpoints, metrics aggregation, `SafeArchiveService` protecting against Zip Slip, traversal, bomb attacks, symlinks |
| **Phase 5** | Real SAST scanning | ✅ Implemented; evidence regression verified | `SemgrepScanner` integrates installed Semgrep CLI (`1.181.0`); evidence is now read from the exact extracted source tree rather than trusted from scanner output |
| **Phase 6** | Secret & dependency scanning | ✅ Complete | `GitleaksScanner` with built-in regex detection and evidence redaction (`***REDACTED***`); `DependencyScanner` with manifest parser and OSV.dev lookup |
| **Phase 7** | Authorized DAST scanning | ✅ Complete | `ZapDastScanner` & `TargetValidator` enforcing mandatory user authorization, blocking SSRF/localhost/cloud metadata, safe passive probe fallback |
| **Phase 8** | Correlation & risk prioritization | ✅ Complete | `CorrelationEngine` linking cross-vector findings (SAST <-> DAST); `RiskPrioritizer` computing deterministic 0.1–10.0 risk score |
| **Phase 9** | AI remediation service | ✅ Complete | `AIRemediationService` providing root cause explanations, potential impacts, safe diffs, and verification steps (rule-based deterministic fallback + Gemini/OpenAI interfaces) |
| **Phase 10** | CI/CD security gate | ✅ Complete | `SecurityGateEvaluator` producing pass/fail gate decisions based on Critical/High thresholds, reusable GitHub Actions gate workflow |
| **Phase 11** | Dashboard, reports & lifecycle | ✅ Complete | React 18 + Vite + Tailwind dashboard, charts (Recharts), ProjectDetail view, vulnerability lifecycle management (`open`, `in_progress`, `fixed`, `retested`, `closed`), JSON & CSV exports |
| **Phase 12** | Testing, hardening & documentation | ✅ Tests/build verified for this update | 72 backend tests passed (79% coverage), 10 frontend tests passed, production build passed |

---

## Verified Test Results

### 1. Backend Pytest Suite (72 Tests Passed)
The test names below are representative; the latest complete run is summarized by the 72-test result.
```
tests/test_api_workflow.py::TestApiWorkflow::test_complete_platform_workflow PASSED
tests/test_auth.py::TestAuthentication::test_register_user_success PASSED
tests/test_auth.py::TestAuthentication::test_register_duplicate_email_fails PASSED
tests/test_auth.py::TestAuthentication::test_login_success PASSED
tests/test_auth.py::TestAuthentication::test_login_invalid_password_fails PASSED
tests/test_auth.py::TestAuthentication::test_get_me_with_bearer_token PASSED
tests/test_auth.py::TestAuthentication::test_get_me_unauthorized_without_token PASSED
tests/test_correlation_and_risk.py::TestCorrelationAndRisk::test_cross_vector_confirmed_correlation PASSED
tests/test_correlation_and_risk.py::TestCorrelationAndRisk::test_unrelated_findings_distinct_groups PASSED
tests/test_correlation_and_risk.py::TestCorrelationAndRisk::test_risk_prioritization_calculation PASSED
tests/test_health.py::TestHealthEndpoints::test_health_returns_200 PASSED
tests/test_health.py::TestHealthEndpoints::test_health_response_shape PASSED
tests/test_health.py::TestHealthEndpoints::test_health_version_format PASSED
tests/test_health.py::TestHealthEndpoints::test_readiness_returns_200 PASSED
tests/test_health.py::TestHealthEndpoints::test_readiness_response_shape PASSED
tests/test_health.py::TestHealthEndpoints::test_unknown_route_returns_404 PASSED
tests/test_health.py::TestHealthEndpoints::test_openapi_schema_accessible_in_debug PASSED
tests/test_safe_archive.py::TestSafeArchiveService::test_valid_archive_extraction PASSED
tests/test_safe_archive.py::TestSafeArchiveService::test_zip_slip_traversal_blocked PASSED
tests/test_safe_archive.py::TestSafeArchiveService::test_absolute_path_entry_blocked PASSED
tests/test_safe_archive.py::TestSafeArchiveService::test_excessive_file_count_blocked PASSED
tests/test_scanners.py::TestScanners::test_secret_redaction PASSED
tests/test_scanners.py::TestScanners::test_gitleaks_builtin_engine_detects_secret PASSED
tests/test_scanners.py::TestScanners::test_dependency_scanner_manifest_detection PASSED
tests/test_scanners.py::TestScanners::test_dast_requires_authorization PASSED
tests/test_scanners.py::TestScanners::test_semgrep_availability PASSED
tests/test_security_gate.py::TestSecurityGate::test_gate_passes_clean_scan PASSED
tests/test_security_gate.py::TestSecurityGate::test_gate_fails_on_critical PASSED
tests/test_security_gate.py::TestSecurityGate::test_gate_fails_on_secret PASSED
tests/test_security_gate.py::TestSecurityGate::test_gate_ignores_fixed_findings PASSED
tests/test_target_validator.py::TestTargetValidator::test_valid_public_https_url PASSED
tests/test_target_validator.py::TestTargetValidator::test_empty_url_rejected PASSED
tests/test_target_validator.py::TestTargetValidator::test_unsupported_scheme_rejected PASSED
tests/test_target_validator.py::TestTargetValidator::test_cloud_metadata_ip_rejected PASSED
tests/test_target_validator.py::TestTargetValidator::test_localhost_blocked_by_default PASSED
tests/test_target_validator.py::TestTargetValidator::test_localhost_permitted_with_explicit_local_override PASSED

72 passed in 168.14s (Coverage: 79%)
```

### 2. Frontend Vitest Suite (10 Tests Passed across 2 Test Suites) & Build (0 Errors)
```
✓ tests/StateSync.test.tsx (6 tests)
  ✓ 1. Generates AI remediation and immediately renders it without refreshing
  ✓ 2. Changes Lifecycle State and immediately updates the UI without page reload
  ✓ 3. Closes and reopens the finding; verifies the new data remains intact
  ✓ 4. Handles AI generation API failure and shows an appropriate error banner
  ✓ 5. Handles Lifecycle update API failure and shows an appropriate error banner
  ✓ 6. Dispatches metrics invalidation event when status is updated

✓ tests/App.test.tsx (4 tests)
  ✓ renders the platform title
  ✓ renders the phase completion indicator
  ✓ renders the API health link
  ✓ renders the API docs link

Test Files: 2 passed (2) | Tests: 10 passed (10)
npm run build: tsc && vite build -> 0 errors, production dist chunks cleanly generated.
```

---

## Files Created & Modified

### Backend Core & API
- `backend/app/models/user.py`
- `backend/app/models/project.py`
- `backend/app/models/scan.py`
- `backend/app/models/finding.py`
- `backend/app/models/policy.py`
- `backend/app/models/audit_log.py`
- `backend/app/schemas/user.py`
- `backend/app/schemas/project.py`
- `backend/app/schemas/scan.py`
- `backend/app/schemas/finding.py`
- `backend/app/schemas/policy.py`
- `backend/app/api/deps.py`
- `backend/app/api/v1/auth.py`
- `backend/app/api/v1/projects.py`
- `backend/app/api/v1/scans.py`
- `backend/app/api/v1/findings.py`
- `backend/app/api/v1/policies.py`
- `backend/app/api/v1/reports.py`
- `backend/app/api/v1/router.py`
- `backend/app/main.py`
- `backend/app/core/security.py`

### Security Scanners & Pipelines
- `backend/app/scanners/base.py`
- `backend/app/scanners/semgrep_scanner.py`
- `backend/app/scanners/gitleaks_scanner.py`
- `backend/app/scanners/dependency_scanner.py`
- `backend/app/scanners/zap_dast_scanner.py`
- `backend/app/services/safe_archive.py`
- `backend/app/services/target_validator.py`
- `backend/app/services/scan_orchestrator.py`
- `backend/app/services/security_gate.py`
- `backend/app/services/ai_remediation.py`
- `backend/app/pipeline/correlation.py`
- `backend/app/pipeline/risk_prioritizer.py`

### Automated Tests
- `backend/tests/test_auth.py`
- `backend/tests/test_safe_archive.py`
- `backend/tests/test_target_validator.py`
- `backend/tests/test_scanners.py`
- `backend/tests/test_security_gate.py`
- `backend/tests/test_correlation_and_risk.py`
- `backend/tests/test_api_workflow.py`
- `backend/tests/test_health.py`
- `frontend/src/test/setup.ts`
- `frontend/tests/App.test.tsx`

### Frontend Application
- `frontend/src/api/client.ts`
- `frontend/src/components/Sidebar.tsx`
- `frontend/src/components/SeverityBadge.tsx`
- `frontend/src/components/GateBadge.tsx`
- `frontend/src/components/AIRemediationModal.tsx`
- `frontend/src/components/UploadScanModal.tsx`
- `frontend/src/pages/Dashboard.tsx`
- `frontend/src/pages/Projects.tsx`
- `frontend/src/pages/ProjectDetail.tsx`
- `frontend/src/pages/Login.tsx`
- `frontend/src/App.tsx`

### Documentation
- `docs/ARCHITECTURE.md`
- `docs/INSTALLATION.md`
- `docs/USER_GUIDE.md`
- `docs/SECURITY_MODEL.md`
- `docs/TESTING.md`
- `docs/API.md`
- `docs/LIMITATIONS.md`
- `README.md`
- `PROJECT_STATUS.md`

---

## Operating Instructions & Next Step
- Backend: Run `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload` from `backend/`
- Frontend: Run `npm run dev` from `frontend/`
- Access at `http://localhost:5173`

## Current Update (2026-10-26)

- Semgrep evidence normalization now reads match lines from the source file under the scan root. A regression test confirms stale `extra.lines` cannot override the corrected source content.
- The upload regression test confirms corrected-source scans produce no finding and historical evidence remains associated with its original scan.
- Dashboard copy now identifies overview counts as scan-history aggregates and directs users to a project's specific scan for version-specific results.
- The local `backend/devsecops.db` contains no record for `Avoid_App_Run_With_Bad_Host`; the precise origin of the reported dashboard item (older scan versus an uploaded archive containing old source) could not be confirmed from this workspace.
- Project detail selects the latest scan after a successful scan and offers a historical scan filter. Dashboard aggregates active findings across scan history; historical findings are intentionally retained and are not automatically marked fixed by a clean later scan.
- Verified in this session: backend pytest 72 passed (79% coverage); frontend Vitest 10 passed; frontend production build passed; Semgrep CLI 1.181.0 available.
- `npm run lint` was attempted but is not runnable because the frontend has no ESLint configuration file; this remains unverified and was not changed as part of the evidence fix.
- Remaining verification: reproduce the SQL Defence System scan with the exact corrected ZIP and inspect its selected scan in the UI. Broad review of all platform integrations and end-to-end service availability was not performed in this update.
