<div align="center">

# PHP FreeBase

**An Enterprise-Hardened, Secure-by-Design PHP Starter Architecture.**  
Equipped with defense-in-depth security, database-backed brute force protection, user registration with expiring email verification, secure one-way password recovery, and a sleek Neon Dark UI.

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-MariaDB-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![License](https://img.shields.io/badge/license-Unlicense-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-00f0ff?style=for-the-badge)

</div>

<img width="982" height="733" alt="image" src="https://github.com/user-attachments/assets/e12f547f-2140-40c6-8f58-e999b9779734" />

## Table of Contents

- [Overview & Key Features](#overview--key-features)
- [Project Architecture](#project-architecture)
- [Password Architecture & Recovery](#password-architecture--recovery)
- [Requirements](#requirements)
- [Quick Start Installation](#quick-start-installation)
- [Configuration (.env)](#configuration-env)
- [Database Schema & Migrations](#database-schema--migrations)
- [Authentication & User Registration](#authentication--user-registration)
- [Admin Security Console & User Management](#admin-security-console--user-management)
- [Emergency Admin Recovery Secret](#emergency-admin-recovery-secret)
- [Production Checklist](#production-checklist)
- [License](#license)

---

## Overview & Key Features

PHP FreeBase provides a robust, production-ready starting point for building secure PHP applications without the overhead of heavy monolithic frameworks.

- **Zero SQL Injection by Design**: Native PDO prepared statements exclusively, with emulated prepares disabled (`ATTR_EMULATE_PREPARES = false`).
- **Database-Backed Brute-Force Rate Limiting**: Persistent throttling across IP addresses and usernames via `login_attempts`. Immune to session-drop attacks.
- **Enterprise Session Hardening & Revocation**: Strict session mode (`session.use_strict_mode = 1`), `HttpOnly`, `SameSite=Lax`, dual idle/absolute timeouts, and per-account `session_version` invalidation.
- **Secure One-Way Password Recovery**: Cryptographically sound reset workflow storing only SHA-256 token hashes, time-to-live expiration, single-use enforcement, and session termination.
- **Zero Plaintext Password Recovery**: The system **never reveals, decrypts, or recovers** an existing password. Passwords are strictly one-way hashed using `password_hash()`.
- **User Registration & Email Verification**: Secure registration system with username constraints (4 to 12 characters), expiring verification tokens, and automatic activation.
- **Role Separation**: Strict role boundaries where administrative access is reserved exclusively for the system administrator.
- **CSRF Defense with POST-Only Endpoints**: State-changing endpoints strictly require verified cryptographic synchronizer tokens, eliminating CSRF and forced logouts.
- **Centralized HTTP Security Headers**: Content Security Policy (CSP), Frame-Ancestors/X-Frame-Options, X-Content-Type-Options, and Permissions-Policy emitted directly in PHP.
- **Zero-Dependency .env Loader**: Native configuration loader supporting `.env` files and container environment variables.
- **Futuristic Neon Dark UI**: High-contrast, responsive design system crafted with vanilla CSS variables, clean typography, and zero emoji clutter.

---

<img width="850" height="585" alt="{8016A7B8-D4B7-49E1-BE37-B15258BA1366}" src="https://github.com/user-attachments/assets/65d60ab6-037e-47cc-a6c0-31abbf8625b7" />

**This nmap scan shows that when mounted correctly it does not have active CVE's as everything is ready for the latest versions. Unicamnte would make sure that the user who uses the tool does not expose 2 ports such as SSH or MYSQL. The page in HTML, **CSS, and JavaScript is fully modifiable as everything is in PHP format. It only exposes the link of the repo used in.git. Something that can be easily hidden.

## Project Architecture

```
php-freebase/
├── .env.example            Environment configuration template
├── .gitignore              Prevents leaking .env, logs, and sensitive files
├── .htaccess               Apache server hardening & file containment rules
├── README.md               Complete project documentation
├── SECURITY.md             Threat model & vulnerability report guidelines
├── index.php               Public landing page ("Nothing here yet" placeholder)
├── register.php            User registration with email verification flow
├── verify.php              Cryptographic email token activation endpoint
├── forgot-password.php     Password recovery request (anti-enumeration)
├── reset-password.php      Password reset execution (SHA-256 token check)
├── emergency-reset.php     Offline admin recovery via ADMIN_RECOVERY_SECRET
├── admin/
│   ├── login.php           Hardened sign-in portal (username or email)
│   ├── dashboard.php       Admin & member dashboard with user password reset
│   ├── reset-user-password.php POST-only admin password reset endpoint
│   ├── security.php        Admin-only security architecture console
│   └── logout.php          CSRF-protected POST-only logout endpoint
├── css/
│   └── style.css           Neon Dark UI design system (pure CSS)
├── db/
│   ├── .htaccess           Denies direct HTTP access
│   └── schema.sql          Database tables: users, password_reset_tokens, login_attempts
├── includes/
│   ├── .htaccess           Denies direct HTTP access
│   ├── auth.php            Authentication, recovery & session engine
│   ├── config.php          Central configuration & lightweight .env parser
│   ├── db.php              PDO singleton with safe exception handling
│   └── functions.php       Security helpers: CSP headers, validation, CSRF
└── js/
    └── script.js           Lightweight accessible client interactions
```

---

## Password Architecture & Recovery

> [!IMPORTANT]
> **Zero Plaintext Recovery Guarantee**:  
> Passwords in PHP FreeBase are strictly one-way hashes generated using `password_hash($password, PASSWORD_DEFAULT)`. There is **no mechanism, master password, or backdoor** that can reveal, decrypt, or recover an existing user's original plaintext password. The platform only supports **one-way password resets**.

### Password Reset Flow (`forgot-password.php` & `reset-password.php`)

1. **User Request (`forgot-password.php`)**:
   - The user enters their username or email.
   - The response is **always uniform and generic**:  
     `"If the account exists and is active, a password reset link has been generated."`  
     This completely prevents account enumeration.
   - If the account exists, a 32-byte cryptographic random token is generated: `bin2hex(random_bytes(32))`.
   - **Only the SHA-256 hash** of this token is stored in the database (`password_reset_tokens.token_hash`). Raw tokens are never stored on disk or in the database.
   - The token has an expiration window of 1 hour (`RESET_TOKEN_LIFETIME = 3600`).
   - Any previously unused reset tokens for that user are immediately invalidated.

2. **Local Development Delivery**:
   - When `APP_ENV=development`, `forgot-password.php` displays a local one-click activation card containing the reset URL.
   - In production (`APP_ENV=production`), the link is dispatched solely through a configured mailer and never displayed on screen.

3. **Reset Execution (`reset-password.php`)**:
   - The token presented in the URL is hashed with SHA-256 and compared against unconsumed, non-expired tokens in `password_reset_tokens`.
   - The new password is validated (minimum 8 characters, maximum 128 characters) and hashed.
   - The token is consumed atomically: `used_at = NOW()`.
   - The user's password hash is updated.

4. **Automatic Session Invalidation (`session_version`)**:
   - The user record in `users` contains a `session_version` column (default 1).
   - Upon completing a password reset, `session_version` is incremented by 1.
   - Active user sessions store the version observed at login (`$_SESSION['session_version']`).
   - Every authenticated request verifies that `$_SESSION['session_version']` matches the database.
   - If a mismatch is detected (e.g., password changed), the old session is immediately destroyed.

---

## Requirements

- **PHP 8.0 or higher** (PHP 8.1, 8.2, 8.3 fully supported)
- **PDO PHP Extension** with PDO_MYSQL driver
- **MySQL 5.7+ / 8.0+** or **MariaDB 10.3+**
- **Apache** (with `mod_rewrite` and `mod_headers`) or **Nginx** / **Caddy**

---

## Quick Start Installation

### 1. Clone the repository
```bash
git clone https://github.com/Nostraxiten/php-freebase.git
cd php-freebase
```

### 2. Configure your environment
Create a local `.env` file from the provided template:
```bash
cp .env.example .env
```
Edit `.env` to match your local database credentials:
```ini
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=freebase
DB_USER=root
DB_PASS=your_db_password
APP_ENV=development
```

### 3. Initialize the database
Import `db/schema.sql` into your MySQL/MariaDB server:
```bash
mysql -u root -p < db/schema.sql
```
This initializes the database, creates the `users`, `password_reset_tokens`, and `login_attempts` tables, and seeds the initial administrator account.

### 4. Run locally
Start PHP's built-in development server:
```bash
php -S localhost:8000
```
Open your browser and navigate to: `http://localhost:8000`

### 5. Access Credentials
- **Admin Portal**: `http://localhost:8000/admin/login.php`
- **Default Admin Username**: `admin`
- **Default Admin Password**: `admin123`
- **Public Landing**: `http://localhost:8000/index.php`
- **Create Account**: `http://localhost:8000/register.php`
- **Forgot Password**: `http://localhost:8000/forgot-password.php`

---

## Configuration (.env)

PHP FreeBase includes a native, zero-dependency `.env` parser:

```ini
APP_ENV=development              # 'development' or 'production'
APP_NAME="PHP FreeBase"
APP_URL=http://localhost:8000

DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=freebase
DB_USER=root
DB_PASS=
DB_CHARSET=utf8mb4

SESSION_NAME=freebase_sec_session
SESSION_LIFETIME=3600            # Idle timeout in seconds (1 hour)
SESSION_MAX_LIFETIME=28800       # Absolute timeout in seconds (8 hours)

LOGIN_MAX_ATTEMPTS=5             # Max failed attempts before lockout
LOGIN_LOCKOUT_SECONDS=300        # Lockout window in seconds (5 minutes)

RESET_TOKEN_LIFETIME=3600        # Reset token validity (1 hour)
VERIFY_TOKEN_LIFETIME=86400      # Email verification token validity (24 hours)

# Optional Emergency Admin Recovery Secret (Never commit to Git!)
ADMIN_RECOVERY_SECRET=
```

---

## Database Schema & Migrations

### Users Table (`users`)
Stores user accounts with role-based access control and session invalidation versioning:
- `id`: Primary key (INT UNSIGNED AUTO_INCREMENT)
- `username`: Unique username (VARCHAR 12, minimum 4 chars)
- `email`: Unique email address (VARCHAR 100)
- `password`: Secure bcrypt/Argon2 hash (VARCHAR 255)
- `role`: Role indicator (`admin` or `user`)
- `is_active`: Account enablement flag (TINYINT 1)
- `email_verified_at`: Timestamp of account verification
- `verification_token`: 64-character verification token
- `verification_expires_at`: Expiration timestamp for email activation
- `session_version`: Incrementing integer used to revoke concurrent sessions
- `created_at` / `updated_at`: Audit timestamps

### Password Reset Tokens Table (`password_reset_tokens`)
Stores hashed tokens for password resets:
- `id`: Primary key (BIGINT UNSIGNED AUTO_INCREMENT)
- `user_id`: Foreign key to `users(id)` ON DELETE CASCADE
- `token_hash`: SHA-256 hash of the 64-character hex token (CHAR 64)
- `expires_at`: Expiration timestamp (1 hour default)
- `used_at`: Timestamp when the token was consumed (single-use)
- `created_at`: Creation timestamp
- `requested_ip`: Requesting client IP address

### Rate Limiting Table (`login_attempts`)
Tracks failed attempts for brute-force defense:
- `id`: Primary key (BIGINT UNSIGNED AUTO_INCREMENT)
- `ip_address`: Client IP address (VARCHAR 45, IPv4/IPv6)
- `username`: Attempted target username/email (VARCHAR 50)
- `attempted_at`: Timestamp of the attempt

---

## Admin Security Console & User Management

### Security Telemetry (`admin/security.php`)
Restricted strictly to the administrator (`require_admin()`):
- Reports **real runtime TLS status** (accurately distinguishes plain HTTP from production HTTPS).
- Documents active HTTP security headers (CSP, X-Frame-Options: DENY, nosniff, Permissions-Policy).
- Live query of throttled brute-force attempts from `login_attempts`.

### Admin Password Reset Capability (`admin/dashboard.php`)
The administrator has access to a user management table with a **secure POST-only password reset tool**:
- The administrator **never sees or accesses prior user passwords**.
- Setting a new password generates a fresh `password_hash()` and increments `session_version`, invalidating the target user's existing sessions.
- All actions are logged without ever exposing the password.

---

## Emergency Admin Recovery Secret

An optional offline recovery mechanism is available via `emergency-reset.php`:
- Configured by setting `ADMIN_RECOVERY_SECRET` in your environment or `.env` file.
- When unset, the endpoint is **completely disabled**.
- When configured, the secret is compared using constant-time `hash_equals()`.
- The endpoint is rate-limited and audit-logged to prevent brute-force attacks.
- This secret **cannot reveal passwords**; it only authorizes setting a new administrator password.

---

## Production Checklist

Before deploying PHP FreeBase to a public production environment:

1. **Change the Default Admin Password**:
   Update `admin123` immediately after initial database setup.
2. **Serve Exclusively over HTTPS**:
   Enforces the `Secure` flag on session cookies and emits HSTS headers.
3. **Switch to Production Environment**:
   Set `APP_ENV=production` in your `.env` file to suppress diagnostic notices and enforce system logging.
4. **Protect Configuration Files**:
   Ensure `.env` and `.git` are not reachable over the web.

---

## License

This project is released under the **Unlicense** — public domain.

<div align="center">

Maintained by [@Nostraxiten](https://github.com/Nostraxiten)

</div>
