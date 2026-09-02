<?php
/**
 * register.php
 * ------------
 * User registration portal.
 * Creates standard user accounts with cryptographic email verification.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

if (is_logged_in()) {
    redirect('admin/dashboard.php');
}

$error = '';
$success = false;
$verificationToken = '';
$registeredEmail = '';

$usernameVal = '';
$emailVal = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Security verification failed. Please refresh and try again.';
    } else {
        $usernameVal     = sanitize_input((string) ($_POST['username'] ?? ''));
        $emailVal        = sanitize_input((string) ($_POST['email'] ?? ''));
        $password        = (string) ($_POST['password'] ?? '');
        $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

        if ($usernameVal === '' || $emailVal === '' || $password === '') {
            $error = 'All fields are required.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (!validate_username($usernameVal)) {
            $error = 'Username must be between 4 and 12 alphanumeric characters.';
        } elseif (!is_valid_email($emailVal)) {
            $error = 'Please enter a valid email address.';
        } elseif (!validate_password_length($password)) {
            $error = 'Password must be between 8 and 128 characters.';
        } else {
            $reg = register_user($usernameVal, $emailVal, $password);
            if ($reg['success']) {
                $success = true;
                $verificationToken = $reg['token'];
                $registeredEmail = $emailVal;
            } else {
                $error = $reg['error'];
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
    <title>Create Account &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
    <main class="card auth-card">
        <div class="auth-header">
            <div class="brand-badge">
                <span class="badge-dot"></span>
                <span><?= e(APP_NAME) ?></span>
            </div>
            <h1>Create Account</h1>
            <p class="subtitle">Join the platform</p>
        </div>

        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                <div class="alert-content">
                    <strong>Account created successfully!</strong>
                    <p>A verification email has been dispatched to <code><?= e($registeredEmail) ?></code>.</p>
                </div>
            </div>

            <div class="verification-box">
                <div class="box-title">LOCAL ENVIRONMENT ACTIVATION</div>
                <p>Since this system is running locally, use this instant verification link to activate your account:</p>
                <div class="token-link-wrapper">
                    <a href="verify.php?token=<?= e($verificationToken) ?>" class="btn btn-primary btn-block">
                        Activate Account Now &rarr;
                    </a>
                </div>
            </div>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Proceed to Sign In</a>
            </footer>

        <?php else: ?>

            <?php if ($error !== ''): ?>
                <div class="alert alert-danger" role="alert">
                    <span class="alert-message"><?= e($error) ?></span>
                    <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
                </div>
            <?php endif; ?>

            <form method="post" action="register.php" class="auth-form" novalidate autocomplete="off">
                <?= csrf_field() ?>

                <div class="form-group">
                    <label for="username">Username <span class="label-hint">(4 to 12 characters)</span></label>
                    <div class="input-container">
                        <input
                            type="text"
                            id="username"
                            name="username"
                            value="<?= e($usernameVal) ?>"
                            autocomplete="username"
                            minlength="4"
                            maxlength="12"
                            placeholder="e.g. user_dev"
                            required
                            autofocus
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="email">Email Address</label>
                    <div class="input-container">
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value="<?= e($emailVal) ?>"
                            autocomplete="email"
                            maxlength="100"
                            placeholder="you@domain.com"
                            required
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="password">Password <span class="label-hint">(min 8 characters)</span></label>
                    <div class="input-container">
                        <input
                            type="password"
                            id="password"
                            name="password"
                            autocomplete="new-password"
                            minlength="8"
                            maxlength="128"
                            placeholder="••••••••••••"
                            required
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="input-container">
                        <input
                            type="password"
                            id="confirm_password"
                            name="confirm_password"
                            autocomplete="new-password"
                            minlength="8"
                            maxlength="128"
                            placeholder="••••••••••••"
                            required
                        >
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    <span>Register Account</span>
                </button>
            </form>

            <footer class="auth-footer">
                <p>Already have an account? <a href="admin/login.php" class="link-accent">Sign In</a></p>
                <a href="index.php" class="link-muted">&larr; Return to Homepage</a>
            </footer>

        <?php endif; ?>
    </main>
</div>

<script src="js/script.js"></script>
</body>
</html>
