# REST API Documentation

The backend exposes an OpenAPI 3.0-compliant RESTful interface mounted under `/api/v1`. Interactive documentation is accessible in development mode at `/api/docs`.

---

## Base Endpoints
- **Liveness Probe**: `GET /api/health`
- **Readiness Probe**: `GET /api/ready`
- **OpenAPI JSON**: `GET /api/openapi.json`
- **Swagger UI**: `GET /api/docs`

---

## Authentication (`/api/v1/auth`)

### 1. Register User
- **Method**: `POST /api/v1/auth/register`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "Password123!",
    "full_name": "Developer Name",
    "role": "developer"
  }
  ```
- **Response**: `201 Created` with User object (password omitted).

### 2. Login
- **Method**: `POST /api/v1/auth/login`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "Password123!"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1Ni...",
    "token_type": "bearer",
    "refresh_token": "eyJhbGci...",
    "user": { "id": "...", "email": "user@example.com", "role": "developer" }
  }
  ```

### 3. Current User Profile
- **Method**: `GET /api/v1/auth/me`
- **Header**: `Authorization: Bearer <access_token>`
- **Response**: `200 OK` with User object.

---

## Projects (`/api/v1/projects`)

### 1. List Projects
- **Method**: `GET /api/v1/projects`
- **Header**: `Authorization: Bearer <access_token>`
- **Response**: `200 OK` array of Project objects with computed metrics (`total_scans`, `open_findings_count`, `critical_count`, `high_count`).

### 2. Create Project
- **Method**: `POST /api/v1/projects`
- **Body**:
  ```json
  {
    "name": "Backend Service",
    "description": "Payment microservice",
    "target_url": "https://example.com"
  }
  ```
- **Response**: `201 Created`

### 3. Get / Update / Delete Project
- `GET /api/v1/projects/{project_id}`
- `PUT /api/v1/projects/{project_id}`
- `DELETE /api/v1/projects/{project_id}`

---

## Scans (`/api/v1/scans`)

### 1. Upload Source Code ZIP and Scan
- **Method**: `POST /api/v1/scans/upload-and-scan`
- **Content-Type**: `multipart/form-data`
- **Fields**:
  - `project_id`: string
  - `scan_type`: `full` | `sast` | `secrets` | `sca` | `dast`
  - `confirm_authorization`: `true` | `false`
  - `file`: binary `.zip` file
- **Response**: `201 Created` with detailed Scan record and parsed findings.

### 2. Trigger Scan via Repository / Target URL
- **Method**: `POST /api/v1/scans/trigger`
- **Body**:
  ```json
  {
    "project_id": "...",
    "scan_type": "full",
    "target_url": "https://example.com",
    "confirm_authorization": true
  }
  ```

### 3. Get Scan Details
- **Method**: `GET /api/v1/scans/{scan_id}`
- **Response**: `200 OK` with findings, gate results, and scanner details.

---

## Findings (`/api/v1/findings`)

### 1. List Project Findings
- **Method**: `GET /api/v1/findings/project/{project_id}`
- **Query Parameters**:
  - `severity`: `critical` | `high` | `medium` | `low`
  - `category`: `sast` | `secret` | `sca` | `dast`
  - `status`: `open` | `in_progress` | `fixed` | `retested` | `closed`
  - `search`: search substring
- **Response**: `200 OK` array of Finding objects sorted by `risk_score` descending.

### 2. Update Vulnerability Lifecycle
- **Method**: `PATCH /api/v1/findings/{finding_id}/status`
- **Body**: `{"status": "fixed"}`

### 3. Generate AI Remediation
- **Method**: `POST /api/v1/findings/{finding_id}/ai-remediation`
- **Response**: `200 OK` with `ai_analysis`, `ai_fix_diff`, and `ai_verification_steps`.

---

## Reports & Analytics (`/api/v1/reports`)

### 1. Dashboard Metrics
- **Method**: `GET /api/v1/reports/metrics`
- **Response**: `200 OK` summary containing total projects, total scans, severity counts, and recent pipeline executions.

### 2. Export Findings as JSON
- **Method**: `GET /api/v1/reports/export/json/{scan_id}`
- **Response**: Machine-readable JSON export for external SIEM / CI systems.

### 3. Export Findings as CSV
- **Method**: `GET /api/v1/reports/export/csv/{scan_id}`
- **Response**: Streaming `text/csv` file with finding headers.
