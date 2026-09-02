<?php
/**
 * logout.php
 * ----------
 * Secure logout endpoint protected against Logout CSRF (CWE-352).
 * Strictly requires HTTP POST with a valid CSRF token.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();

// Prevent Logout CSRF: Reject GET requests and unverified POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (verify_csrf($_POST['csrf_token'] ?? null)) {
        logout();
    }
}

// Redirect back to login page
redirect('login.php');
