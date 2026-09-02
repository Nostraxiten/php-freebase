<div align="center">

# PHP FreeBase

**An Enterprise-Hardened, Secure-by-Design PHP Starter Architecture.**  
Equipped with defense-in-depth security, database-backed brute force protection, user registration with email verification, and a sleek Neon Dark UI.

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-MariaDB-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![License](https://img.shields.io/badge/license-Unlicense-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-00f0ff?style=for-the-badge)

</div>

---

## Table of Contents

- [Overview & Key Features](#overview--key-features)
- [Project Architecture](#project-architecture)
- [Requirements](#requirements)
- [Quick Start Installation](#quick-start-installation)
- [Configuration (.env)](#configuration-env)
- [Database Schema & Migrations](#database-schema--migrations)
- [Authentication & User Registration](#authentication--user-registration)
- [Admin Security Console](#admin-security-console)
- [Production Checklist](#production-checklist)
- [License](#license)

---

## Overview & Key Features

PHP FreeBase provides a robust, production-ready starting point for building secure PHP applications without the overhead of heavy monolithic frameworks.

- **Zero SQL Injection by Design**: Native PDO prepared statements exclusively, with emulated prepares disabled (`ATTR_EMULATE_PREPARES = false`).
- **Database-Backed Brute-Force Rate Limiting**: Persistent throttling across IP addresses and usernames via `login_attempts`. Immune to session-drop attacks.
- **Enterprise Session Hardening**: Strict session mode (`session.use_strict_mode = 1`), `HttpOnly`, `SameSite=Lax`, dual idle/absolute timeouts, and session ID regeneration.
- **User Registration & Email Verification**: Secure registration system with username constraints (4 to 12 characters), email verification tokens, and automatic status activation.
- **Role Separation**: Strict role boundaries where administrative access is reserved exclusively for the system administrator.
- **CSRF Defense with POST-Only Logout**: State-changing endpoints strictly require verified cryptographic synchronizer tokens, eliminating Logout CSRF.
- **Centralized HTTP Security Headers**: Content Security Policy (CSP), Frame-Ancestors/X-Frame-Options, X-Content-Type-Options, and Permissions-Policy emitted directly in PHP (works on Apache, Nginx, and Caddy).
- **Zero-Dependency .env Loader**: Native configuration loader supporting `.env` files and container environment variables.
- **Modern Minimalist Neon Dark UI**: High-contrast, responsive design system crafted with vanilla CSS variables, semantic HTML, clean typography, and zero emoji clutter.

---

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
├── admin/
│   ├── login.php           Hardened sign-in portal (username or email)
│   ├── dashboard.php       Role-aware member & admin dashboard
│   ├── security.php        Admin-only security architecture console
│   └── logout.php          CSRF-protected POST-only logout endpoint
├── css/
│   └── style.css           Neon Dark UI design system (pure CSS)
├── db/
│   ├── .htaccess           Denies direct HTTP access
│   └── schema.sql          Database tables: users and login_attempts
├── includes/
│   ├── .htaccess           Denies direct HTTP access
│   ├── auth.php            Authentication, registration & session engine
│   ├── config.php          Central configuration & lightweight .env parser
│   ├── db.php              PDO singleton with safe exception handling
│   └── functions.php       Security helpers: CSP headers, validation, CSRF
└── js/
    └── script.js           Lightweight accessible client interactions
```

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
This initializes the database, creates the `users` and `login_attempts` tables, and seeds the initial administrator account.

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

---

## Authentication & User Registration

- **Username Constraints**: Usernames must be between 4 and 12 characters (alphanumeric, dashes, and underscores only).
- **Password Strength**: Passwords require a minimum of 8 characters (maximum 128 characters) and are hashed using bcrypt/Argon2.
- **Email Verification**: New accounts are created with a 64-character cryptographic token. In development mode, `register.php` displays an instant one-click activation link pointing to `verify.php?token=...`.
- **Role Assignment**: All new registrations are assigned strictly to the `user` role. Only the designated `admin` account possesses administrative privileges.

---

## Admin Security Console

Administrators can access the internal security dashboard at:
`http://localhost:8000/admin/security.php`

This section is strictly restricted (`require_admin()`) and provides:
- Comprehensive security architecture documentation in English.
- Real-time telemetry on active HTTP security headers.
- Session configuration inspection (Strict mode, lifetimes, cookie flags).
- Live query of throttled brute-force attempts from `login_attempts`.
- Verification of continuous password hashing and auto-rehash routines.

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
