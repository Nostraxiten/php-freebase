<?php
/**
 * login.php
 * ---------
 * Administrative and member authentication portal.
 * Features CSRF protection, persistent brute-force mitigation,
 * strict input validation, and neon aesthetics.
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
$identifierVal = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Security verification failed. Please refresh and try again.';
    } else {
        $identifierVal = sanitize_input((string) ($_POST['identifier'] ?? ''));
        $password      = (string) ($_POST['password'] ?? '');

        if ($identifierVal === '' || $password === '') {
            $error = 'Please enter your username/email and password.';
        } elseif (strlen($identifierVal) < 3 || strlen($identifierVal) > 100) {
            $error = 'Invalid identifier length.';
        } elseif (!validate_password_length($password)) {
            $error = 'Password must be between 8 and 128 characters.';
        } else {
            $auth = attempt_login($identifierVal, $password);
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
    <title>Sign In &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
    <main class="card auth-card">
        <div class="auth-header">
            <div class="brand-badge">
                <span class="badge-dot"></span>
                <span><?= e(APP_NAME) ?></span>
            </div>
            <h1>Authentication</h1>
            <p class="subtitle">Access your account</p>
        </div>

        <?php if ($error !== ''): ?>
            <div class="alert alert-danger" role="alert">
                <span class="alert-message"><?= e($error) ?></span>
                <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
            </div>
        <?php endif; ?>

        <form method="post" action="login.php" class="auth-form" novalidate autocomplete="off">
            <?= csrf_field() ?>

            <div class="form-group">
                <label for="identifier">Username or Email</label>
                <div class="input-container">
                    <input
                        type="text"
                        id="identifier"
                        name="identifier"
                        value="<?= e($identifierVal) ?>"
                        autocomplete="username"
                        maxlength="100"
                        placeholder="Username or email"
                        required
                        autofocus
                    >
                </div>
            </div>

            <div class="form-group">
                <div class="label-row">
                    <label for="password">Password</label>
                    <a href="../forgot-password.php" class="link-muted text-sm">Forgot password?</a>
                </div>
                <div class="input-container">
                    <input
                        type="password"
                        id="password"
                        name="password"
                        autocomplete="current-password"
                        minlength="8"
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
                <div class="dev-badge">DEVELOPMENT NOTICE</div>
                <p>Default admin credentials: <code>admin</code> / <code>admin123</code></p>
            </div>
        <?php endif; ?>

        <footer class="auth-footer">
            <p>Need an account? <a href="../register.php" class="link-accent">Register here</a></p>
            <?php if (ADMIN_RECOVERY_SECRET !== ''): ?>
                <p><a href="../emergency-reset.php" class="link-muted text-sm">Emergency Admin Reset</a></p>
            <?php endif; ?>
            <a href="../index.php" class="link-muted">&larr; Return to Homepage</a>
        </footer>
    </main>
</div>

<script src="../js/script.js"></script>
</body>
</html>
