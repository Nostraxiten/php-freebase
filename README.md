<div align="center">

# PHP FreeBase

**A free, secure-by-default PHP starter base.**
Copy the folder, plug in a database, and start building — instead of staring at a project with 0 lines of code.

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-MariaDB-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![License](https://img.shields.io/badge/license-Unlicense-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)
![Security](https://img.shields.io/badge/SQLi-protected-critical?style=for-the-badge)

</div>

---

## Table of contents

- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Setup (step by step)](#setup-step-by-step)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes-read-before-deploying-anywhere-real)
- [License](#license)

---

## What you get

- **Landing page** — `index.php`, public entry point, ready to gut and replace
- **Admin panel** — `admin/`, working login, dashboard, logout
- **Database layer** — PDO with real prepared statements, SQL injection is off the table by design
- **Passwords** — `password_hash()` / `password_verify()`, never plain text
- **CSRF protection** — every form ships with a synchronizer token
- **XSS protection** — `e()` helper escapes all dynamic output
- **Sessions** — hardened cookies: `HttpOnly`, `SameSite`, `secure` over HTTPS
- **Brute-force throttle** — basic login rate-limiting out of the box
- **Access control** — `.htaccess` blocks direct access to `includes/` and `db/`
- **Database schema** — empty, ready-to-extend `db/schema.sql`

---

## Requirements

- PHP 8.0+
- MySQL / MariaDB
- Apache with `mod_rewrite` and `mod_headers` (for the `.htaccess` rules)
  — on Nginx, port the rules in `.htaccess` to your server block

---

## Setup (step by step)

### 1 · Get PHP and MySQL running

`python -m http.server` will **not** work here — it only serves static files and doesn't understand PHP.

- **macOS** — `brew install php mysql && brew services start mysql`
- **Debian/Ubuntu** — `sudo apt install php mysql-server && sudo systemctl start mysql`
- **Windows** — [XAMPP](https://www.apachefriends.org/) or [Laragon](https://laragon.org/), both bundle PHP + MySQL

Check: `php -v` and `mysql -u root -p`

### 2 · Import the schema

```bash
mysql -u root -p < db/schema.sql
```

Creates the `freebase` database, the `users` table, and the default admin row.

### 3 · Configure the connection

Edit `includes/config.php` — set `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS` to match your setup.

### 4 · Run it locally

```bash
php -S localhost:8000
```

Open `http://localhost:8000`. Note: PHP's built-in server doesn't read `.htaccess` — that only kicks in on real Apache hosting.

### 5 · Log in

`http://localhost:8000/admin/login.php`

```
username: admin
password: admin
```

### 6 · Change the default password

Do this immediately — it's public, anyone with this base knows it.

```php
<?php echo password_hash('your-new-password', PASSWORD_BCRYPT);
```

Then:

```sql
UPDATE users SET password = '<hash>' WHERE username = 'admin';
```

---

## Project layout

```
php-freebase/
├── index.php              Public landing page
├── .htaccess               Security headers + blocks includes/ and db/
├── css/style.css           Base styling
├── js/script.js             Base JS, no dependencies
├── includes/
│   ├── config.php           DB + app settings (edit this)
│   ├── db.php                PDO connection (prepared statements only)
│   ├── functions.php         sanitize_input(), e(), CSRF helpers
│   └── auth.php              Session handling, login/logout, throttling
├── admin/
│   ├── login.php
│   ├── dashboard.php         Protected — requires login
│   └── logout.php
└── db/
    └── schema.sql            users table + default admin row
```

---

## Troubleshooting

<details>
<summary><strong>DB connection failed: SQLSTATE[HY000] [2002] No such file or directory</strong></summary>
<br>

MySQL isn't running, isn't installed, or PDO can't find its socket.

1. Confirm MySQL is installed and started (see [step 1](#1--get-php-and-mysql-running)).
2. Still failing? Force TCP instead of a socket — in `includes/config.php`:
   ```php
   define('DB_HOST', '127.0.0.1');
   ```
</details>

<details>
<summary><strong>PHP file downloads as raw text / shows source code in the browser</strong></summary>
<br>

You're serving the folder with something other than PHP (Python's `http.server`, a static file server, etc). Use `php -S localhost:8000` instead.
</details>

<details>
<summary><strong>"Invalid or expired form submission" on login</strong></summary>
<br>

The CSRF token in your session expired or doesn't match. Reload `login.php` and try again.
</details>

---

## Security notes (read before deploying anywhere real)

This base gives you a sane, non-vulnerable starting point — not a finished product. Before going live, at minimum:

- Change the default admin password (see [step 6](#6--change-the-default-password))
- Serve everything over HTTPS — the session cookie only gets `secure` when `$_SERVER['HTTPS']` is set
- Set `APP_ENV` to `production` in `includes/config.php` to stop leaking error details
- Add real rate-limiting at the network layer (fail2ban, WAF, reverse proxy) — the built-in throttle is per-session only
- Keep PHP and dependencies up to date

Patterns in `db.php`, `functions.php`, and `auth.php` follow the OWASP SQL Injection Prevention Cheat Sheet and OWASP CSRF Prevention Cheat Sheet.

---

## License

Do whatever you want with this. It's a base, not a product — no attribution required.

<div align="center">

Built by [@Nostraxiten](https://github.com/Nostraxiten)

</div>
