# =============================================================================
# Backend Dockerfile
# Multi-stage: installs scanner CLIs, then installs Python deps, copies app.
# Scanner CLIs installed at image build time — no runtime internet required.
# =============================================================================

FROM python:3.12-slim AS base

# --------------------------------------------------------------------------
# System dependencies + scanner CLI installations
# --------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        unzip \
        wget \
        ca-certificates \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Semgrep (SAST) ---
RUN pip install --no-cache-dir semgrep==1.72.0

# --- Checkov (IaC) ---
RUN pip install --no-cache-dir checkov==3.2.76

# --- Gitleaks (Secret Detection) ---
RUN GITLEAKS_VERSION="8.18.4" && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# --- Trivy (Container + SCA) ---
RUN TRIVY_VERSION="0.51.4" && \
    wget -qO- "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy

# --- Syft (SBOM generation) ---
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin v1.4.1

# --- OSV-Scanner (SCA) ---
RUN OSV_VERSION="1.7.4" && \
    curl -sSfL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# --------------------------------------------------------------------------
# Python dependencies
# --------------------------------------------------------------------------
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --------------------------------------------------------------------------
# Application code
# --------------------------------------------------------------------------
COPY . .

# --------------------------------------------------------------------------
# Security: non-root user
# --------------------------------------------------------------------------
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /tmp/devsecops_uploads && \
    chown -R appuser:appuser /app /tmp/devsecops_uploads

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
