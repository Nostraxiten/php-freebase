<?php
/**
 * functions.php
 * --------------
 * Security helpers: output encoding, strict input validation, CSRF tokens,
 * HTTP security headers, client IP resolution, and safe redirection.
 * Direct access to this file is blocked by PHP guard and .htaccess.
 */

declare(strict_types=1);

if (!defined('APP_SECURE')) {
    http_response_code(403);
    die('Direct access not permitted.');
}

/**
 * Emit defense-in-depth HTTP security headers directly from PHP.
 * Works uniformly across Apache, Nginx, Caddy, and PHP's built-in server.
 */
function send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');

    // Strict Content Security Policy (No inline scripts/styles needed for basic app)
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self';");

    // HSTS (HTTP Strict Transport Security) only when served over HTTPS
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/**
 * Sanitize basic string input (trims whitespace and removes null bytes).
 * Note: Sanitization is NOT a replacement for contextual validation or prepared statements.
 */
function sanitize_input(string $data): string
{
    $data = trim($data);
    return str_replace("\0", '', $data);
}

/**
 * Validate username according to safe format constraints:
 * - Length between 3 and 50 characters (matches DB column length)
 * - Only alphanumeric characters, dots, dashes, and underscores
 */
function validate_username(string $username): bool
{
    if (strlen($username) < 3 || strlen($username) > 50) {
        return false;
    }
    return (bool) preg_match('/^[a-zA-Z0-9_.\-]+$/', $username);
}

/**
 * Validate password length constraints:
 * - Minimum 8 characters for baseline strength
 * - Maximum 128 characters to prevent DoS via bcrypt CPU exhaustion
 */
function validate_password_length(string $password): bool
{
    $len = strlen($password);
    return $len >= 8 && $len <= 128;
}

/**
 * Escape a string for safe HTML output (XSS Prevention - OWASP Recommendation).
 * Always use in HTML templates: <?= e($untrustedData) ?>
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Generate (or reuse) a cryptographically secure CSRF token.
 */
function csrf_token(bool $forceNew = false): string
{
    if ($forceNew || empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Regenerate the CSRF token (useful upon privilege change or login).
 */
function rotate_csrf_token(): string
{
    return csrf_token(true);
}

/**
 * Output a hidden <input> containing the CSRF token.
 */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

/**
 * Verify a submitted CSRF token using timing-safe comparison.
 */
function verify_csrf(?string $submittedToken, bool $rotate = false): bool
{
    if (empty($_SESSION['csrf_token']) || empty($submittedToken)) {
        return false;
    }

    $valid = hash_equals($_SESSION['csrf_token'], $submittedToken);

    if ($valid && $rotate) {
        rotate_csrf_token();
    }

    return $valid;
}

/**
 * Validate an email address format.
 */
function is_valid_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Safely extract the client's IP address.
 * Uses REMOTE_ADDR to prevent IP spoofing attacks against the rate limiter.
 */
function get_client_ip(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    return '127.0.0.1';
}

/**
 * Safe redirect helper.
 * Prevents Open Redirect (CWE-601) by ensuring the path is relative and does not
 * specify external schemes or protocol-relative paths.
 */
function redirect(string $path): never
{
    // Prevent CRLF injection in HTTP headers
    $path = str_replace(["\r", "\n"], '', $path);

    // Block external URLs and protocol-relative paths (e.g. "//evil.com" or "javascript:")
    if (preg_match('#^(https?:|//|javascript:|data:)#i', $path)) {
        $path = 'index.php';
    }

    header('Location: ' . $path);
    exit;
}
