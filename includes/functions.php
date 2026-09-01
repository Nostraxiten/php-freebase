<?php
/**
 * functions.php
 * --------------
 * Small set of security helpers used across the whole base.
 */

declare(strict_types=1);

/**
 * Clean up raw input (trim + strip null bytes). This is NOT a substitute
 * for prepared statements or output escaping — it just tidies the value.
 */
function sanitize_input(string $data): string
{
    $data = trim($data);
    $data = str_replace("\0", '', $data);
    return $data;
}

/**
 * Escape a string for safe HTML output (XSS prevention).
 * Use this EVERY time you print user-controlled data into HTML: <?= e($value) ?>
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Generate (or reuse) a CSRF token stored in the session.
 */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Output a hidden <input> with the current CSRF token, ready to drop into a <form>.
 */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

/**
 * Verify a submitted CSRF token using a timing-safe comparison.
 */
function verify_csrf(?string $submittedToken): bool
{
    if (empty($_SESSION['csrf_token']) || empty($submittedToken)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $submittedToken);
}

/**
 * Very small helper to validate an email address.
 */
function is_valid_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Redirect and stop execution.
 */
function redirect(string $path): never
{
    header('Location: ' . $path);
    exit;
}
