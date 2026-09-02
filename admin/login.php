<?php
/**
 * login.php
 * ---------
 * Secure administrative authentication portal.
 * Features CSRF protection, persistent brute-force mitigation,
 * strict input validation, and modern dark aesthetics.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();

if (is_logged_in()) {
    redirect('dashboard.php');
}

$error = '';
$usernameVal = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Invalid or expired security token. Please try again.';
    } else {
        $usernameVal = sanitize_input((string) ($_POST['username'] ?? ''));
        $password    = (string) ($_POST['password'] ?? '');

        if ($usernameVal === '' || $password === '') {
            $error = 'Please enter both your username and password.';
        } elseif (!validate_username($usernameVal)) {
            $error = 'Invalid username format (3-50 alphanumeric characters).';
        } elseif (!validate_password_length($password)) {
            $error = 'Password must be between 8 and 128 characters.';
        } else {
            $auth = attempt_login($usernameVal, $password);
            if ($auth['success']) {
                redirect('dashboard.php');
            } else {
                $error = $auth['error'];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
    <main class="card auth-card">
        <div class="auth-header">
            <div class="brand-badge">
                <span class="shield-icon" aria-hidden="true">🛡️</span>
                <span><?= e(APP_NAME) ?></span>
            </div>
            <h1>Authentication Portal</h1>
            <p class="subtitle">Secure administrative access</p>
        </div>

        <?php if ($error !== ''): ?>
            <div class="alert alert-danger" role="alert" id="auth-alert">
                <span class="alert-icon" aria-hidden="true">⚠️</span>
                <span class="alert-message"><?= e($error) ?></span>
                <button type="button" class="alert-close" aria-label="Dismiss alert" onclick="this.parentElement.remove();">&times;</button>
            </div>
        <?php endif; ?>

        <form method="post" action="login.php" class="auth-form" novalidate autocomplete="off">
            <?= csrf_field() ?>

            <div class="form-group">
                <label for="username">Username</label>
                <div class="input-container">
                    <input
                        type="text"
                        id="username"
                        name="username"
                        value="<?= e($usernameVal) ?>"
                        autocomplete="username"
                        maxlength="50"
                        placeholder="Enter your username"
                        required
                        autofocus
                    >
                </div>
            </div>

            <div class="form-group">
                <div class="label-row">
                    <label for="password">Password</label>
                </div>
                <div class="input-container">
                    <input
                        type="password"
                        id="password"
                        name="password"
                        autocomplete="current-password"
                        maxlength="128"
                        placeholder="••••••••••••"
                        required
                    >
                </div>
            </div>

            <button type="submit" class="btn btn-primary btn-block">
                <span>Sign In</span>
                <span class="arrow-icon" aria-hidden="true">&rarr;</span>
            </button>
        </form>

        <?php if (APP_DEBUG): ?>
            <div class="dev-notice">
                <div class="dev-badge">DEV ENVIRONMENT</div>
                <p>Default credentials: <code>admin</code> / <code>admin</code>. Remember to update this password before deploying to production.</p>
            </div>
        <?php endif; ?>

        <footer class="auth-footer">
            <a href="../index.php" class="link-muted">&larr; Return to Homepage</a>
        </footer>
    </main>
</div>

<script src="../js/script.js"></script>
</body>
</html>
