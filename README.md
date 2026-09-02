<div align="center">

# PHP FreeBase

**An Enterprise-Hardened, Secure-by-Design PHP Starter Architecture.**  
Equipped with defense-in-depth security, OWASP Top 10 mitigations, database-backed brute force protection, and a sleek Dark UI.

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-MariaDB-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Hardened-success?style=for-the-badge)
![License](https://img.shields.io/badge/license-Unlicense-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/SQLi%20%7C%20CSRF%20%7C%20BruteForce-Protected-critical?style=for-the-badge)

</div>

---

## Table of Contents

- [Overview & Key Features](#overview--key-features)
- [Project Architecture](#project-architecture)
- [Security & OWASP Hardening](#security--owasp-hardening)
- [Requirements](#requirements)
- [Quick Start Installation](#quick-start-installation)
- [Configuration (.env)](#configuration-env)
- [Database Schema & Migrations](#database-schema--migrations)
- [Admin Portal & Authentication](#admin-portal--authentication)
- [Security Notes & Production Checklist](#security-notes--production-checklist)
- [License](#license)

---

## Overview & Key Features

PHP FreeBase provides a robust, production-ready starting point for building secure PHP applications without the weight and overhead of heavy monolithic frameworks.

-  **Zero SQL Injection by Design**: Native PDO prepared statements exclusively, with emulated prepares disabled (`ATTR_EMULATE_PREPARES = false`).
-  **Database-Backed Brute-Force Rate Limiting**: Persistent throttling across IP addresses and usernames via `login_attempts`. Immune to session-drop attacks.
-  **Enterprise Session Hardening**: Strict session mode (`session.use_strict_mode = 1`), `HttpOnly`, `SameSite=Lax`, dual idle/absolute timeouts, and session ID regeneration.
-  **CSRF Defense with POST-Only Logout**: State-changing endpoints strictly require verified cryptographic synchronizer tokens, eliminating Logout CSRF.
-  **Centralized HTTP Security Headers**: Content Security Policy (CSP), Frame-Ancestors/X-Frame-Options, X-Content-Type-Options, and Permissions-Policy emitted directly in PHP (works on Apache, Nginx, and Caddy).
-  **Zero-Dependency .env Loader**: Native configuration loader supporting `.env` files and container environment variables.
-  **Modern Minimalist Dark UI**: High-contrast, responsive design system crafted with vanilla CSS variables and semantic HTML.

---

## Project Architecture

```
php-freebase/
├── .env.example            Environment configuration template
├── .gitignore              Prevents leaking .env, logs, and sensitive files
├── .htaccess               Apache server hardening & file containment rules
├── README.md               Complete project documentation
├── SECURITY.md             Threat model, security policy & vulnerability report guidelines
├── index.php               Public landing page with security overview
├── admin/
│   ├── login.php           Hardened login portal with rate limiting & CSRF
│   ├── dashboard.php       Protected admin console & security telemetry
│   └── logout.php          CSRF-protected POST-only logout endpoint
├── css/
│   └── style.css           Modern Dark UI design system (variables, components, responsive)
├── db/
│   ├── .htaccess           Denies direct HTTP access
│   └── schema.sql          Database tables: users and login_attempts
├── includes/
│   ├── .htaccess           Denies direct HTTP access
│   ├── auth.php            Authentication, role authorization & session engine
│   ├── config.php          Central configuration & lightweight .env parser
│   ├── db.php              PDO singleton with safe exception handling
│   └── functions.php       Security helpers: CSP headers, validation, CSRF, escaping
└── js/
    └── script.js           Lightweight accessible client interactions (vanilla JS)
```

---

## Security & OWASP Hardening

| Component | Protection Mechanism | Mitigated Threats |
| :--- | :--- | :--- |
| **Authentication** | `password_hash()` (bcrypt), `password_verify()`, `password_needs_rehash()` | Plain-text credentials, weak hashes |
| **Rate Limiting** | Database table `login_attempts` tracking IP + username with temporal window | Brute-force, dictionary attacks, credential stuffing |
| **Authorization** | `require_login()`, `require_admin()`, active account status check | Broken access control, privilege escalation |
| **Sessions** | `use_strict_mode`, `use_only_cookies`, `session_regenerate_id(true)`, idle/absolute timers | Session fixation, session hijacking, stale sessions |
| **CSRF** | Cryptographic tokens (`bin2hex(random_bytes(32))`), timing-safe verification, POST logout | Cross-Site Request Forgery, Forced Logout |
| **Database** | PDO native prepared statements, no string interpolation, masked exceptions | SQL Injection (SQLi), error-based information disclosure |
| **Output** | Contextual `e()` helper (`htmlspecialchars` with `ENT_QUOTES \| ENT_SUBSTITUTE`) | Cross-Site Scripting (Reflected & Stored XSS) |
| **HTTP Headers** | Strict CSP, X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Permissions-Policy | Clickjacking, MIME-sniffing, drive-by execution |
| **File Protection**| PHP execution guards (`defined('APP_SECURE') or die()`) + `.htaccess` rules | Direct script access, config leaks |

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
This creates the `freebase` database, the `users` table with role support, the `login_attempts` rate-limiting table, and seeds the initial administrator account.

### 4. Run locally
You can run the application immediately with PHP's built-in development server:
```bash
php -S localhost:8000
```
Open your browser and navigate to: `http://localhost:8000`

### 5. Access the Admin Portal
- URL: `http://localhost:8000/admin/login.php`
- Default Username: `admin`
- Default Password: `admin`

> [!CAUTION]
> **Change the default administrator password immediately** after your first login!

---

## Configuration (.env)

PHP FreeBase includes a native, lightweight `.env` parser that loads settings without any Composer dependencies:

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
```

---

## Database Schema & Migrations

### Users Table (`users`)
Stores user accounts with role-based access control and account status:
- `id`: Primary key (INT UNSIGNED AUTO_INCREMENT)
- `username`: Unique username (VARCHAR 50)
- `password`: Secure hash (VARCHAR 255)
- `role`: Role indicator (`admin` or `user`)
- `is_active`: Account enablement flag (TINYINT 1)
- `created_at` / `updated_at`: Audit timestamps

### Rate Limiting Table (`login_attempts`)
Tracks failed authentication attempts to defend against brute force:
- `id`: Primary key (BIGINT UNSIGNED AUTO_INCREMENT)
- `ip_address`: Client IP address (VARCHAR 45, IPv4/IPv6)
- `username`: Attempted target username (VARCHAR 50)
- `attempted_at`: Timestamp of the attempt (indexed for rapid window calculations)

---

## Security Notes & Production Checklist

Before deploying PHP FreeBase to a public production environment:

1. **Serve strictly over HTTPS**:
   Enabling HTTPS automatically configures the `Secure` flag on session cookies and emits `Strict-Transport-Security` headers.
2. **Switch to Production Mode**:
   Set `APP_ENV=production` in your `.env` file to suppress all detailed diagnostic messages and enforce error logging.
3. **Protect the `.env` file**:
   Ensure `.env` is never accessible over the web. On Apache, `.htaccess` automatically denies access; on Nginx, include `location ~ /\.env { deny all; }`.
4. **Database Privileges**:
   Use a dedicated database user with privileges restricted strictly to `SELECT, INSERT, UPDATE, DELETE` on the `freebase` database.

---

## License

This project is licensed under the **Unlicense** — public domain. You are free to use, modify, and distribute it for any purpose.

<div align="center">

Maintained by [@Nostraxiten](https://github.com/Nostraxiten)

</div>
