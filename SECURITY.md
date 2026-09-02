# Security Policy — PHP FreeBase

## Overview & Philosophy

**PHP FreeBase** is engineered according to the principle of **Defense in Depth** and the **OWASP Top 10** guidelines. The goal is to provide a zero-boilerplate, highly hardened starter architecture for PHP web applications.

---

## Threat Model & Implemented Mitigations

| Threat / Vulnerability | OWASP Mapping | Mitigation in PHP FreeBase |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | A03:2021 – Injection | Native PDO prepared statements exclusively. Emulated prepares disabled (`ATTR_EMULATE_PREPARES = false`). String concatenation into SQL queries is strictly prohibited. |
| **Cross-Site Scripting (XSS)** | A03:2021 – Injection | Context-aware output encoding via `e()` helper (`htmlspecialchars` with `ENT_QUOTES \| ENT_SUBSTITUTE` in UTF-8). Defense-in-depth Content Security Policy (CSP) headers disallow unauthorized scripts. |
| **Cross-Site Request Forgery (CSRF)** | A01:2021 – Broken Access Control | Cryptographically secure synchronizer tokens (`csrf_token()`, `csrf_field()`, `verify_csrf()`) evaluated via timing-safe `hash_equals()`. State-changing actions (including logout) strictly require HTTP POST. |
| **Brute-Force & Credential Stuffing** | A07:2021 – Identification Failures | Database-backed persistent rate limiting (`login_attempts` table) tracking IP address and targeted username. Immune to session-drop attacks. |
| **Session Hijacking & Fixation** | A07:2021 – Identification Failures | PHP `session.use_strict_mode = 1`, `session.use_only_cookies = 1`, `session.use_trans_sid = 0`. Hardened cookie flags (`HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS). Session ID regeneration on authentication state changes. |
| **Session Lifetime & Inactivity** | A07:2021 – Identification Failures | Dual timeout enforcement: Inactivity idle timeout (`SESSION_LIFETIME`, default 1 hour) and absolute lifetime cap (`SESSION_MAX_LIFETIME`, default 8 hours). |
| **Information & Error Disclosure** | A05:2021 – Security Misconfiguration | Database connection exceptions logged exclusively to server error log (`error_log()`). Sanitized error responses prevent path disclosure or credential leaks. |
| **Sensitive File Access** | A05:2021 – Security Misconfiguration | Multi-layer containment: PHP internal guards (`defined('APP_SECURE') or die()`), `.htaccess` URL rewrites, and file match blocklists for `.env`, `.sql`, `.log`, `.git`. |
| **Clickjacking & Framing** | A05:2021 – Security Misconfiguration | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` emitted directly from PHP and Apache headers. |
| **MIME-Type Sniffing** | A05:2021 – Security Misconfiguration | `X-Content-Type-Options: nosniff` enforced globally. |
| **Open Redirects** | CWE-601 | `redirect()` helper sanitizes CRLF characters and strips external schemes and protocol-relative URIs. |
| **Hardcoded Secrets** | A07:2021 – Identification Failures | Zero hardcoded production credentials. Full support for `.env` files and system environment variables (`getenv()`) with `.gitignore` exclusion. |

---

## Environment & Server Hardening Checklist

When deploying PHP FreeBase to production:

1. **Serve exclusively over HTTPS**:
   - Ensure a valid TLS certificate is active. This activates the `Secure` flag on session cookies and enables `Strict-Transport-Security` (HSTS).
2. **Environment Variable Configuration**:
   - Create a `.env` file from `.env.example` outside the public web root (or ensure `.env` is blocked by your web server).
   - Set `APP_ENV=production` to suppress all debug output.
3. **Change Default Credentials**:
   - Update the default administrator credentials immediately after running `schema.sql`.
4. **Database Principle of Least Privilege**:
   - Configure a dedicated MySQL/MariaDB database user with permissions restricted strictly to `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the `freebase` database.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in this project:

1. **Do not create a public GitHub issue.**
2. Send an email with the vulnerability details, steps to reproduce, and impact assessment to the repository maintainer.
3. Allow reasonable time for remediation before any public disclosure.
