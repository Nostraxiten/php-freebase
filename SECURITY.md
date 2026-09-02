# Security Policy — PHP FreeBase

## Overview & Philosophy

**PHP FreeBase** is engineered according to the principle of **Defense in Depth** and the **OWASP Top 10** guidelines. The goal is to provide a zero-boilerplate, highly hardened starter architecture for PHP web applications.

---

## Password Security & Recovery Policy

### 1. Plaintext Passwords Are Never Recoverable
The platform employs strictly one-way cryptographic hashing via `password_hash($password, PASSWORD_DEFAULT)`.
- Existing user passwords cannot be retrieved, decrypted, viewed, or reversed by anyone, including system administrators or database operators.
- There is **no master password** or backdoor credential that can unlock or decrypt user accounts.
- Password recovery is conducted exclusively through **one-way password resets**.

### 2. Password Reset Token Architecture
- **Cryptographic Generation**: Reset tokens are generated using `bin2hex(random_bytes(32))` (256 bits of cryptographically secure entropy).
- **Hashed Token Storage**: The raw token is **never stored** in the database. Only its SHA-256 hash (`password_reset_tokens.token_hash`) is persisted. If the database is compromised, the stored hashes cannot be used directly to reset passwords.
- **Single-Use Enforcement**: Tokens are consumed atomically on first use (`used_at = NOW()`). Subsequent requests using the same token are rejected.
- **Time-to-Live Expiration**: Tokens expire automatically after 1 hour (`RESET_TOKEN_LIFETIME = 3600`).
- **Account Enumeration Defense**: The reset request endpoint (`forgot-password.php`) always returns an identical generic response regardless of whether the account exists.

### 3. Session Invalidation on Password Change
To prevent session fixation and account takeover, every account record maintains a `session_version` counter:
- Whenever a password is reset (by the user, an administrator, or emergency secret), `session_version` is incremented.
- Authenticated user sessions verify their stored `session_version` against the database on each request.
- Mismatched sessions are revoked immediately, ensuring that any stolen or stale session cookies are terminated instantly.

### 4. Administrator & Emergency Resets
- **Admin User Reset**: The administrator may set a new temporary password for a user via a CSRF-protected POST request. The administrator is never shown the user's prior password.
- **Offline Emergency Recovery**: An optional server-side secret (`ADMIN_RECOVERY_SECRET`) allows resetting the administrator password via constant-time comparison (`hash_equals()`). This feature is rate-limited and disabled unless explicitly configured in the environment.

---

## Threat Model & Implemented Mitigations

| Threat / Vulnerability | OWASP Mapping | Mitigation in PHP FreeBase |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | A03:2021 – Injection | Native PDO prepared statements exclusively. Emulated prepares disabled (`ATTR_EMULATE_PREPARES = false`). Concatenation into SQL queries is strictly prohibited. |
| **Cross-Site Scripting (XSS)** | A03:2021 – Injection | Context-aware output encoding via `e()` helper (`htmlspecialchars` with `ENT_QUOTES \| ENT_SUBSTITUTE` in UTF-8). Strict Content Security Policy (CSP) headers disallow unauthorized scripts. |
| **Cross-Site Request Forgery (CSRF)** | A01:2021 – Broken Access Control | Cryptographically secure synchronizer tokens (`csrf_token()`, `csrf_field()`, `verify_csrf()`) evaluated via timing-safe `hash_equals()`. State-changing actions strictly require HTTP POST. |
| **Brute-Force & Credential Stuffing** | A07:2021 – Identification Failures | Database-backed persistent rate limiting (`login_attempts` table) tracking IP address and targeted username. Immune to session-drop attacks. |
| **Session Hijacking & Stale Sessions** | A07:2021 – Identification Failures | PHP `session.use_strict_mode = 1`, `session.use_only_cookies = 1`, `session.use_trans_sid = 0`. Hardened cookie flags (`HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS). Automatic session revocation via `session_version`. |
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
   Ensure a valid TLS certificate is active. This activates the `Secure` flag on session cookies and enables `Strict-Transport-Security` (HSTS).
2. **Environment Variable Configuration**:
   Create a `.env` file from `.env.example` outside the public web root (or ensure `.env` is blocked by your web server). Set `APP_ENV=production` to suppress all debug output.
3. **Change Default Credentials**:
   Update the default administrator credentials (`admin123`) immediately after running `schema.sql`.
4. **Database Principle of Least Privilege**:
   Configure a dedicated MySQL/MariaDB database user with permissions restricted strictly to `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the `freebase` database.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in this project:

1. **Do not create a public GitHub issue.**
2. Send an email with the vulnerability details, steps to reproduce, and impact assessment to the repository maintainer.
3. Allow reasonable time for remediation before any public disclosure.
