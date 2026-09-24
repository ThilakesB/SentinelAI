# Security Policy
## CyberGuard AI — Vulnerability Reporting & Security Guidelines

---

## Our Commitment

Security is the core purpose of CyberGuard AI. We take the security of our own codebase extremely seriously. If you find a vulnerability in our software, please report it responsibly — we will acknowledge and address it promptly.

We are committed to:
- Acknowledging vulnerability reports within **48 hours**
- Providing an initial assessment within **5 business days**
- Releasing a fix or mitigation within **30 days** for critical vulnerabilities
- Publicly crediting researchers who responsibly disclose issues (with permission)

---

## Supported Versions

Only the latest release receives active security patches.

| Version | Supported |
|---|---|
| 1.0.x (latest) | ✅ Active |
| 0.9.x (beta) | ⚠️ Security fixes only (critical) |
| < 0.9 | ❌ End of life — please upgrade |

---

## Reporting a Vulnerability

### Do NOT

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before we have released a fix
- Use the vulnerability to access systems you don't own

### Do

Report vulnerabilities **privately** via one of these channels:

#### Option 1: GitHub Private Security Advisory (Preferred)

1. Go to the [Security tab](https://github.com/your-org/cyberguard-ai/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill out the advisory form

#### Option 2: Email

Send details to: **security@cyberguard.ai**

Use our PGP key to encrypt sensitive reports:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP PUBLIC KEY WILL BE ADDED HERE]
-----END PGP PUBLIC KEY BLOCK-----
```

PGP key fingerprint: `XXXX XXXX XXXX XXXX XXXX`  
Available at: https://keys.openpgp.org/search?q=security@cyberguard.ai

---

## What to Include in Your Report

A good vulnerability report includes:

1. **Vulnerability type** — e.g., authentication bypass, privilege escalation, SQL injection
2. **Affected component** — agent, API server, dashboard, AI engine
3. **Affected version(s)** — which versions are vulnerable
4. **Severity assessment** — how impactful is this (your assessment)?
5. **Steps to reproduce** — detailed, repeatable steps
6. **Proof of concept** — code, screenshots, or logs demonstrating the issue
7. **Suggested fix** — if you have one (not required)

---

## High-Value Vulnerability Categories

We are particularly interested in reports related to:

| Category | Examples |
|---|---|
| **Authentication Bypass** | Accessing the dashboard without valid credentials |
| **Authorization Escalation** | Viewer role performing kill actions |
| **Kill Guard Bypass** | Finding a way to kill PID 1 or protected system processes |
| **Audit Log Tampering** | Bypassing hash chain protection to modify audit entries |
| **Agent Compromise** | Exploiting the agent process to gain host system access |
| **AI Model Poisoning** | Manipulating the ONNX model to misclassify malware as safe |
| **Remote Code Execution** | Achieving RCE via agent or API server |
| **Privilege Escalation** | Escalating from agent user to root/SYSTEM |
| **Token Forgery** | Creating valid JWT tokens without valid credentials |
| **Secrets Exposure** | API keys or credentials exposed in logs or error messages |

---

## Responsible Disclosure Timeline

| Day | Action |
|---|---|
| Day 0 | You submit the report |
| Day 1–2 | We acknowledge receipt |
| Day 3–5 | We triage and provide initial assessment |
| Day 10–30 | We develop and test a fix |
| Day 30–45 | Fix is released (may be faster for critical issues) |
| Day 45+ | Public disclosure (coordinated with you) |

For **Critical** vulnerabilities (RCE, auth bypass, kill guard bypass), we target a **7-day fix**. We may release an emergency patch before the full fix.

---

## Security Hall of Fame

We publicly thank security researchers who responsibly disclose vulnerabilities (with their permission):

| Researcher | Vulnerability | Date |
|---|---|---|
| *Your name could be here* | *Report a vulnerability!* | - |

---

## Security Architecture Overview

For security researchers evaluating CyberGuard AI:

### Key Security Controls

1. **TLS 1.3** — all agent-to-API and browser-to-dashboard communication is encrypted
2. **JWT tokens** — 8-hour expiry, signed with HS256 (configurable to RS256)
3. **bcrypt passwords** — cost factor 12+, no plaintext storage
4. **RBAC** — 4 roles enforced via API middleware on every request
5. **Kill guards** — hardcoded protection for PID 1, kernel processes; configurable additional PIDs
6. **Audit log integrity** — SHA-256 hash chain; database rules prevent UPDATE/DELETE
7. **Model integrity** — ONNX model verified with SHA-256 + Ed25519 signature before loading
8. **Least privilege** — agent runs as non-root user; only kill executor subprocess has elevated privileges

### Known Limitations (by Design)

- The AI model runs locally and cannot be updated in real-time for zero-day threats
- Network analysis relies on OS-level logs, not deep packet inspection
- Autonomous kill mode, when enabled, can cause service disruption if thresholds are misconfigured

---

## Security Configuration Best Practices

For operators deploying CyberGuard AI:

- **Always** use TLS certificates from a trusted CA (not self-signed in production)
- **Always** enable MFA for all dashboard user accounts
- **Keep** `autonomous_kill_threshold` at 0.85 or higher
- **Keep** supervised mode enabled for the first 30 days while learning your environment
- **Regularly** review the whitelist — don't whitelist by process name when hash-based whitelisting is possible
- **Restrict** API server access to trusted network segments only
- **Rotate** JWT secret keys and agent API keys every 90 days
- **Monitor** the audit log for unexpected actions, especially unauthorized kill attempts

---

*CyberGuard AI Security Team*  
*security@cyberguard.ai*
