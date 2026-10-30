# User Guide — AI DevSecOps Platform

This guide describes how to use the platform to scan applications, understand vulnerability findings, generate AI remediations, and enforce CI/CD gate policies.

---

## 1. Authentication
1. Navigate to the web application at `http://localhost:5173`.
2. To sign in as the administrator, click **"Autofill Admin Demo Credentials"** or type:
   - Email: `admin@example.com`
   - Password: `changeme`
3. Alternatively, click **"Create Account"** to register a developer profile.

---

## 2. Managing Projects
1. From the navigation sidebar, click **"Projects & Scans"**.
2. Click **"New Project"**.
3. Enter:
   - **Project Name**: e.g. `Payment Gateway API`
   - **Description**: e.g. `Microservice handling payments`
   - **Target DAST URL (optional)**: e.g. `https://demo.example.com`
4. Click **"Create Project"**.

---

## 3. Uploading & Scanning a Codebase
1. On the project card or project detail page, click **"Scan Code"** or **"Scan Codebase"**.
2. Select your source-code `.zip` file.
   - The archive is inspected for Zip Slip attempts, suspicious path traversal, symlink attacks, and compression bombs.
3. Select the **Scan Scope**:
   - `Full DevSecOps`: Runs Semgrep SAST, Gitleaks secret detection, OSV dependency analysis, and authorized DAST testing.
   - `SAST Only`: Source code static analysis.
   - `Secret Detection Only`: Unencrypted API keys, tokens, and credentials.
   - `SCA Only`: Third-party dependencies and known CVEs.
   - `DAST Only`: Dynamic testing of running web applications.
4. If running DAST, check **"I confirm that I own or am explicitly authorized to perform security testing against this application target"**.
5. Click **"Start Scan"**.

---

## 4. Understanding Scan Results & Findings
1. After the scan completes, you will see:
   - **Security Gate Status**: PASSED (Green) or FAILED (Red) based on active policy thresholds.
   - **Severity Breakdown**: Counts of Critical, High, Medium, and Low vulnerabilities.
   - **Vulnerability Table**: Searchable and filterable by severity, vector (SAST, Secret, SCA, DAST), and lifecycle status.
2. Each finding lists:
   - **Title and Description**
   - **Location**: Source file and line number, or API endpoint URL
   - **Evidence**: Extracted snippet (all sensitive secret values are automatically redacted with `***REDACTED***`)
   - **Risk Score**: Transparent 0.1 to 10.0 score based on severity, confidence, and exposure.
   - **Correlation Engine**: If the same vulnerability was detected across static code and dynamic endpoints, a correlation note is displayed.

---

## 5. AI-Assisted Remediation
1. Click the **"Remediation"** button next to any finding.
2. In the modal, click **"Generate AI Remediation"**.
3. The platform generates:
   - **Root Cause & Simple Explanation**: Why the vulnerability exists.
   - **Potential Impact**: Security implications and business risk.
   - **Safe Code Diff / Example**: Contextual code example showing how to remediate the flaw.
   - **Developer Verification Steps**: Concrete testing steps to verify the fix works.
4. Update the **Lifecycle State** from `Open` to `In Progress` or `Fixed` as remediation proceeds.

---

## 6. Exporting Reports
From the Project Detail page:
- Click **"Export JSON"** to download a machine-readable JSON report for CI/CD audit logs.
- Click **"Export CSV"** to download an executive summary spreadsheet of all findings.
