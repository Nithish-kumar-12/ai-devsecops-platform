# AI-Powered Application Security Testing & DevSecOps Platform

> A production-grade, integrated Application Security Testing (AST) and DevSecOps platform built with **FastAPI**, **React 18**, **TypeScript**, **Tailwind CSS**, and **SQLite / PostgreSQL**. Features static analysis (SAST), secret scanning, software composition analysis (SCA), authorized dynamic testing (DAST), unified vulnerability correlation, transparent risk scoring, AI-assisted remediation, and CI/CD security gate enforcement.

---

## 📌 Project Overview

This platform provides engineering teams with an automated, developer-friendly security pipeline to detect vulnerabilities early in the software development lifecycle (SDLC):

1. **SAST (Static Application Security Testing)**: Powered by **Semgrep CLI** for detecting code vulnerabilities across Python, JavaScript, TypeScript, Go, Java, C/C++, PHP, and Ruby.
2. **Secret Detection**: Powered by **Gitleaks** with an integrated high-precision pattern engine, automatically masking sensitive credentials (`***REDACTED***`).
3. **SCA (Dependency Vulnerability Scanning)**: Scans package manifests (`requirements.txt`, `package.json`) against the authoritative **OSV.dev** vulnerability database.
4. **Authorized DAST (Dynamic Application Security Testing)**: Integrates **OWASP ZAP** with non-destructive passive probes and strict SSRF defenses (blocking cloud metadata `169.254.169.254` and internal IP ranges by default).
5. **Correlation & Normalization Engine**: Deduplicates findings and automatically links cross-vector issues (e.g., SAST SQL Injection linked with DAST SQLi alerts).
6. **Transparent Risk Prioritizer**: Computes deterministic 0.1–10.0 risk scores based on severity weights, asset exposure, and vulnerability category.
7. **AI-Assisted Remediation**: Delivers actionable root cause explanations, security impacts, secure code diffs, and verification steps (deterministic rule-based knowledge base with optional Gemini/OpenAI integration).
8. **CI/CD Security Gate**: Automated pass/fail gate policies configurable per project, with GitHub Actions integration.
9. **Interactive Security Dashboard**: Responsive React SPA with severity distribution charts, filterable finding tables, lifecycle status tracking (`open`, `in_progress`, `fixed`, `retested`, `closed`), and CSV/JSON report exports.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts |
| **Backend** | Python 3.10–3.14, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Structlog |
| **Database** | SQLite (zero-configuration local default) / PostgreSQL (production-ready) |
| **Security Engines** | Semgrep CLI, Gitleaks engine, OSV-Scanner / OSV.dev API, OWASP ZAP |
| **AI Engine** | Deterministic security knowledge base (offline default) + Gemini / OpenAI API support |
| **Testing** | Pytest, Pytest-Asyncio, Pytest-Cov, Vitest, JSDOM |

---

## 🚀 Quick Start on Windows 11 & VS Code

No Docker or paid cloud services are required for local development.

### 1. Prerequisites
- **Python 3.10+** (verified on Python 3.14 on Windows 11)
- **Node.js 18+** & **npm**
- **Git** & **VS Code**

### 2. Backend Setup
Open a terminal in VS Code (PowerShell):

```powershell
cd backend

# 1. Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt
pip install semgrep greenlet pytest-cov email-validator

# 3. Apply database migrations
alembic upgrade head

# 4. Start the FastAPI development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **API Base URL**: `http://localhost:8000`
- **Interactive Swagger Documentation**: `http://localhost:8000/api/docs`
- **Health Check**: `http://localhost:8000/api/health`

### 3. Frontend Setup
Open a second terminal in VS Code:

```powershell
cd frontend

# 1. Install frontend packages
npm install --legacy-peer-deps

# 2. Start Vite development server
npm run dev
```

- **Frontend Application**: `http://localhost:5173`

---

## 🔑 Default Login Credentials

On initial startup, the backend automatically seeds an administrator account:
- **Email**: `admin@example.com`
- **Password**: `changeme`

> 💡 *On the login page, you can also click the **"Autofill Admin Demo Credentials"** button for instant one-click login.*

---

## 🧪 Running Automated Tests

All platform modules are accompanied by unit, integration, and security regression tests.

### Backend Tests (Pytest)
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/ -v
```
*Executes the current backend suite (63 tests in the final measured run, 73% coverage), validating:*
- JWT authentication, password hashing, and role checks
- Zip Slip and path traversal defenses
- SSRF prevention, cloud metadata blocking, and target validation
- Semgrep CLI SAST execution
- Secret detection and evidence redaction (`***REDACTED***`)
- OSV manifest parsing and dependency analysis
- Authorized DAST gate enforcement
- Cross-vector SAST–DAST correlation and risk score calculation
- CI/CD security gate evaluations and end-to-end API workflows

### Frontend Tests (Vitest) & Production Build
```powershell
cd frontend
npm test
npm run build
```
*Validates UI layout, route links, TypeScript types, and compiles production assets.*

---

## 📖 Comprehensive Documentation

Detailed technical documentation is available in the [`docs/`](docs/) directory:

- 📐 [**Architecture Guide**](docs/ARCHITECTURE.md) — System design, data flow diagrams, database schema, and component interactions.
- ⚙️ [**Installation Guide**](docs/INSTALLATION.md) — Detailed setup instructions for Windows 11, Linux, and macOS.
- 📘 [**User Guide**](docs/USER_GUIDE.md) — Walkthrough of project creation, safe ZIP upload, scan analysis, AI remediation, and report exporting.
- 🛡️ [**Security Model**](docs/SECURITY_MODEL.md) — Defense-in-depth measures, Zip Slip protections, SSRF mitigation, and secret redaction.
- 🔬 [**Testing Guide**](docs/TESTING.md) — Automated test suite structure, fixtures, and coverage reports.
- 🔌 [**API Reference**](docs/API.md) — Endpoints, request/response schemas, and authentication headers.
- ⚠️ [**Scanner Limitations**](docs/LIMITATIONS.md) — Clear, transparent documentation of supported languages, rulesets, and scanning boundaries.
- 📋 [**Project Status**](PROJECT_STATUS.md) — Implementation verification matrix and phase deliverables.

---

## 🔒 Safe Upload & Security Guarantees

- **No Code Execution**: Uploaded source code is parsed statically and never executed.
- **Zip Slip Defense**: Archives are inspected before extraction; paths containing `..` or absolute prefixes are rejected.
- **Archive Bomb Protection**: Configurable compressed upload limit (1 GiB by default), 100,000-entry cap, and derived uncompressed/single-file caps.
- **Secret Redaction**: Detected secret keys and tokens are never stored or displayed in plain text.
- **Target Authorization**: DAST requires explicit authorization checkboxes and blocks private network targets (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`) by default.
- **Local AI Knowledge Base**: High-quality remediation guidance is generated deterministically without requiring paid AI API subscriptions.

---

## 📄 License

This project is licensed under the MIT License.
