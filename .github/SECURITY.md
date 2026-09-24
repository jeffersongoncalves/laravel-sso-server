# Security Policy

## Supported Versions

Only the latest major and minor releases receive security updates and patches. We strongly recommend always running the latest tagged version of the package.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Scope & Security Architecture

`laravel-sso-server` handles critical authentication and identity federation primitives, including:

- Authorization Code exchange with mandatory PKCE (S256).
- Cryptographic key generation, rotation, and public key publication via JWKS (RS256).
- Ephemeral tokens with atomic cache invalidation (anti-replay defense).
- Asymmetric JWT issuance and signature verification.
- HMAC-SHA256 request payload verification (`X-SSO-Signature` over `{timestamp}.{body}`).
- Asynchronous Single Logout (SLO) webhook dispatching.

Vulnerabilities involving cryptographic flaws, token replay risks, bypass of authorization codes, signature forgery, or unauthorized state mutation are treated with maximum priority.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or public discussions.**

If you believe you have found a security vulnerability in this package:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Use the native security advisory tool by navigating to the repository's **Security** tab, clicking on **Advisories**, and selecting **"Report a vulnerability"**.

2. **Direct Contact:**  
   If you cannot use GitHub Advisories, please send a detailed email to **contato@jeffersongoncalves.me** with the subject line `[SECURITY] laravel-sso-server Vulnerability Report`.

### What to include in your report:

- A clear description of the vulnerability and its potential impact.
- Step-by-step instructions to reproduce the issue (proof-of-concept script, curl commands, or Pest/PHPUnit test case).
- The package version, PHP version, and Laravel framework version affected.
- Any relevant logs, stack traces, or configuration details (redacting sensitive keys/secrets).

---

## Response Timeline

- **Initial Acknowledgement:** Within **48 hours**, confirming receipt of the report.
- **Triage & Assessment:** Within **5 business days**, validating the issue and assessing severity.
- **Remediation & Patching:** A fix will be developed in a private fork and tested across all supported database drivers (SQLite, MySQL, PostgreSQL) and supported PHP runtimes before release.
- **Public Disclosure:** Coordinated release with a patch version tag and a published GitHub Security Advisory (CVE assignment if applicable). We will credit reporters who practice responsible disclosure (unless anonymity is requested).
