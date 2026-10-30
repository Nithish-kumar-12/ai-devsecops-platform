# Platform Security Model & Defense Architecture

The platform is designed around strict defensive engineering principles to ensure scanning operations do not compromise host safety, violate network boundaries, or leak sensitive developer assets.

---

## 1. Archive Sandbox & Zip Slip Protection (`SafeArchiveService`)
When source-code archives are uploaded:
- **Zip Slip Defense**: Every entry filename is verified against path traversal patterns (`..`, `/`, `\`, null bytes `\0`, drive letters `C:`). Extracted target paths are canonicalized with `os.path.abspath` and guaranteed to lie inside the designated sandbox directory.
- **Archive Bomb Mitigation**:
  - Maximum archive file size limit: 100 MB.
  - Maximum total extracted uncompressed size: 200 MB.
  - Maximum single file uncompressed size: 50 MB.
  - Maximum file count limit: 10,000 files.
  - Compression ratio threshold: Heuristic blocks archives with compression ratios exceeding 100:1.
- **Symlink & Special File Attack Defense**: Archive entries with Unix symlink mode (`0o120000`) or special device nodes are rejected.
- **No Execution**: Uploaded source code is purely parsed statically. No scripts, binaries, or commands from uploaded source archives are executed.
- **Ephemeral Sandbox & Cleanup**: Extracted files reside in transient directories that are wiped via `SafeArchiveService.cleanup()` upon scan completion or failure.

---

## 2. DAST SSRF & Network Boundary Defense (`TargetValidator`)
Dynamic application security scanning presents severe Server-Side Request Forgery (SSRF) and intranet-probing risks if unconstrained.
- **Target Authorization Gate**: DAST cannot be initiated without explicit boolean confirmation that the user is authorized to test the target.
- **Address Resolution Verification**: Target hostnames are resolved to IP addresses via `socket.getaddrinfo`.
- **Restricted Network Ranges (RFC 1918 / Loopback / Multicast)**:
  - Loopback (`127.0.0.0/8`, `::1/128`)
  - Private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-local and Cloud Metadata (`169.254.0.0/16` and `169.254.169.254`)
  - Multicast (`224.0.0.0/4`)
  - IPv6 unique local (`fc00::/7`) and link-local (`fe80::/10`)
- **Cloud Metadata Shield**: The cloud metadata IP `169.254.169.254` (used by AWS, Azure, GCP for instance identity tokens) is unconditionally blocked regardless of overrides.
- **Local Lab Override**: For controlled academic demonstration on local target services, `ALLOW_LOCAL_TARGETS=True` can be enabled in settings. Even with this flag active, cloud metadata endpoints remain strictly forbidden.
- **Non-Destructive Testing**: Only safe passive probes and read-only crawlers are executed. Destructive fuzzing and DoS payloads are prohibited.

---

## 3. Secret Protection & Evidence Redaction
- **Automatic Masking**: Any exposed secret detected by Gitleaks or the regex engine (AWS keys, GitHub PATs, private keys, database passwords) has its secret body masked with `***REDACTED***` before storage or presentation.
- **Credential Storage**: User passwords are encrypted using native `bcrypt` with unique salts. Secrets and API keys are never written to source control or public logging output.

---

## 4. AI Safety & Privacy
- **No Unsolicited Code Upload**: The core application functions fully offline without external AI APIs using deterministic rule-based security templates.
- **Provider Independence**: If an external LLM (Gemini or OpenAI) is configured, only the sanitized finding title, description, rule ID, and redacted evidence are provided. Untrusted source code files are not transferred across external networks.
- **Non-Authoritative Advice**: All AI-assisted advice is labeled with explicit disclaimers: *"AI/automated remediation suggestions should be verified and tested prior to deployment."*
