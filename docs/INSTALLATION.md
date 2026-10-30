# Installation and Setup Guide (Windows 11 / Linux / macOS)

This guide provides simple, step-by-step instructions to set up and run the **AI-Powered Application Security Testing and DevSecOps Platform**.

---

## Prerequisites
- **Python**: 3.10+ (tested and verified on Python 3.14 on Windows 11)
- **Node.js**: 18+ (tested on Node v25.9.0 with npm 11.12.1)
- **Git**: Installed and available in PATH
- **Code Editor**: VS Code (recommended)

---

## Quick Start on Windows 11 (Direct Local Execution)

### 1. Backend Setup

Open PowerShell in the project directory:

```powershell
cd backend

# Create virtual environment (if not already present)
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r requirements.txt
pip install semgrep greenlet pytest-cov email-validator

# Run database migrations
alembic upgrade head
```

### 2. Frontend Setup

Open a second PowerShell window:

```powershell
cd frontend

# Install frontend dependencies
npm install --legacy-peer-deps

# Build or run development server
npm run dev
```

The frontend will start at **http://localhost:5173**.

### 3. Start Backend API Server

In your first PowerShell window (with `.venv` active):

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- API Base: **http://localhost:8000**
- Interactive Swagger UI Docs: **http://localhost:8000/api/docs**
- Health Probe: **http://localhost:8000/api/health**
- Readiness Probe: **http://localhost:8000/api/ready**

---

## Default Credentials

The platform seeds a default administrator on initial startup:
- **Email**: `admin@example.com`
- **Password**: `changeme`

On the frontend login screen, click **"Autofill Admin Demo Credentials"** to quickly log in.

---

## Running Automated Tests

### Backend Unit & Integration Tests (pytest)
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/
```
*(Backend suite currently contains authentication, refresh-token, safe archive, target validation, PDF/report, correlation, risk scoring, security gate, scanner, and API workflow tests. Run locally for the final count.)*

### Frontend Tests (vitest)
```powershell
cd frontend
npm test
```
*(Current frontend baseline: 10 tests across the application and state synchronization suites. Run locally to confirm current counts.)*

---

## Environment Variables (.env)

A `.env.example` is provided in the repository root. Key variables include:

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | Async database connection string | `sqlite+aiosqlite:///./devsecops.db` |
| `DATABASE_URL_SYNC` | Sync database string for migrations | `sqlite:///./devsecops.db` |
| `SECRET_KEY` | JWT signing secret | Auto-configured for local dev |
| `ALLOW_LOCAL_TARGETS` | Opt-in flag for local DAST student lab testing | `False` |
| `ZAP_BASE_URL` | OWASP ZAP daemon endpoint | `http://localhost:8080` |
| `OPENAI_API_KEY` | Optional OpenAI key for remediation | None (falls back to deterministic KB) |
| `GEMINI_API_KEY` | Optional Google Gemini key | None (falls back to deterministic KB) |
