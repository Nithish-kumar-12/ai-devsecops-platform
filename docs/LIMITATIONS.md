# Scanner Coverage, Known Limitations & Boundary Disclosure

Honesty in security tooling is paramount. This document outlines genuine capabilities, platform assumptions, and limitations.

---

## 1. Scanner Coverage Matrix

| Vector | Primary Scanner | Current Host Support | Fallback Mechanism | Limitations |
|---|---|---|---|---|
| **SAST** | Semgrep CLI | ✅ Installed natively in virtual environment (`1.181.0`) | Graceful error logging | Analyzes languages supported by Semgrep community rules (Python, JS, TS, Java, Go, C, Ruby). Does not execute dynamic binary analysis. |
| **Secrets** | Gitleaks CLI | ⚠️ Optional system CLI | Built-in high-confidence regex engine for AWS, GitHub, Slack, Private Keys, Stripe, and Database URIs | Scans text and source code. Cannot unmask proprietary obfuscated binaries or encrypted archives. |
| **SCA** | OSV-Scanner | ⚠️ Optional system CLI | Manifest parsing for Python (`requirements.txt`) and Node (`package.json`) + free public OSV.dev API / offline catalog | Analyzes declared direct and lockfile dependencies. Transitive dependency resolution without lockfiles is best-effort. |
| **DAST** | OWASP ZAP | ⚠️ Optional daemon service (`http://localhost:8080`) | Safe passive HTTP defensive header & TLS auditor | Requires a live running HTTP service. Blocked against internal IP addresses by default to prevent SSRF. Passive audit checks headers and SSL, not deep multi-step business logic vulnerabilities. |

---

## 2. Platform Assumptions & Explicit Non-Goals
1. **Source Code Execution**: The platform strictly avoids running uploaded source code. Static analysis is performed solely by parsing file trees and regex/AST pattern matching.
2. **Third-Party Scanning**: Scanning arbitrary third-party infrastructure without explicit authorization is strictly forbidden. The system enforces authorization confirmation and network validation.
3. **Absence of Evidence is Not Evidence of Absence**: Passing all scanners or receiving 0 findings does not guarantee an application is free from unknown 0-day exploits or logic flaws.
4. **AI Output Verification**: AI remediation suggestions are advisory. Developers must independently review, test, and verify code diffs before merging them to production branches.
