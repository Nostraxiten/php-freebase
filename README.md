# PHP FreeBase

A free, zero-dependency PHP starter base. Copy the folder, plug in a database,
and start building instead of staring at an empty project with 0 lines of code.

## What you get

- A public landing page (`index.php`)
- A working admin panel with login/logout (`admin/`)
- A PDO database layer using **real prepared statements** (no SQL injection by design)
- Password hashing via `password_hash()` / `password_verify()` (never plain text)
- CSRF tokens on every form
- An `e()` helper to escape all output (XSS prevention)
- Hardened session cookies (`HttpOnly`, `SameSite`, `secure` on HTTPS)
- Basic login throttling against brute-force attempts
- `.htaccess` rules blocking direct access to `includes/` and `db/`
- An empty, ready-to-extend MySQL schema (`db/schema.sql`)

## Requirements

- PHP 8.0+
- MySQL / MariaDB
- Apache with `mod_rewrite` and `mod_headers` (for the `.htaccess` rules).
  Using Nginx instead? Port the rules in `.htaccess` to your server block.

## Setup

1. Copy this folder into your web root (or run `php -S localhost:8000` inside it for a quick local test).
2. Import the schema:
   ```
   mysql -u root -p < db/schema.sql
   ```
3. Edit `includes/config.php` with your real DB host/user/password.
4. Visit `/admin/login.php` and log in with:
   - **username:** `admin`
   - **password:** `admin`
5. **Change that password immediately.** It's a public default — anyone with
   this base knows it. There's no "change password" screen yet on purpose:
   build it as your first exercise, or update the hash directly:
   ```php
   <?php echo password_hash('your-new-password', PASSWORD_BCRYPT);
   ```
   then `UPDATE users SET password = '<hash>' WHERE username = 'admin';`

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

## Security notes (read before deploying anywhere real)

This base gives you a sane, non-vulnerable starting point, not a finished
product. Before going to production, at minimum:

- Change the default admin password (see above).
- Serve everything over HTTPS (the session cookie only gets the `secure`
  flag when `$_SERVER['HTTPS']` is set).
- Set `APP_ENV` to `production` in `includes/config.php` to stop leaking
  error details.
- Add real rate-limiting at the network layer (fail2ban, WAF, reverse proxy)
  — the built-in throttle in `auth.php` is per-session only.
- Keep PHP and your dependencies up to date.

Reference: OWASP SQL Injection Prevention Cheat Sheet and OWASP CSRF
Prevention Cheat Sheet — the patterns in `db.php`, `functions.php` and
`auth.php` follow their recommended defenses (prepared statements as the
primary defense against injection, synchronizer-token CSRF protection).

## License

Do whatever you want with this. It's a base, not a product — MIT-style, no attribution required.
