<?php
/**
 * forgot-password.php
 * -------------------
 * Password recovery request endpoint.
 * Protects against account enumeration by always returning a generic response.
 * In development mode, displays an instant activation link for local testing.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

if (is_logged_in()) {
    redirect('admin/dashboard.php');
}

$message = '';
$devToken = '';
$devEmail = '';
$error = '';
$identifierVal = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Security verification failed. Please refresh and try again.';
    } else {
        $identifierVal = sanitize_input((string) ($_POST['identifier'] ?? ''));

        if ($identifierVal === '') {
            $error = 'Please enter your username or email address.';
        } else {
            $res = request_password_reset($identifierVal);
            $message = $res['message'];
            if (!empty($res['dev_token'])) {
                $devToken = $res['dev_token'];
                $devEmail = $res['dev_email'] ?? '';
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
    <title>Reset Password &mdash; <?= e(APP_NAME) ?></title>
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
            <h1>Password Recovery</h1>
            <p class="subtitle">Request a secure password reset link</p>
        </div>

        <?php if ($error !== ''): ?>
            <div class="alert alert-danger" role="alert">
                <span class="alert-message"><?= e($error) ?></span>
                <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
            </div>
        <?php endif; ?>

        <?php if ($message !== ''): ?>
            <div class="alert alert-success" role="alert">
                <span class="alert-message"><?= e($message) ?></span>
            </div>

            <?php if ($devToken !== ''): ?>
                <div class="verification-box">
                    <div class="box-title">LOCAL DEVELOPMENT RESET LINK</div>
                    <p>Since the application is running in local development mode, use this link to complete the reset for <code><?= e($devEmail) ?></code>:</p>
                    <div class="token-link-wrapper">
                        <a href="reset-password.php?token=<?= e($devToken) ?>" class="btn btn-primary btn-block">
                            Reset Password Now &rarr;
                        </a>
                    </div>
                </div>
            <?php endif; ?>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Return to Sign In</a>
            </footer>

        <?php else: ?>

            <form method="post" action="forgot-password.php" class="auth-form" novalidate autocomplete="off">
                <?= csrf_field() ?>

                <div class="form-group">
                    <label for="identifier">Username or Email Address</label>
                    <div class="input-container">
                        <input
                            type="text"
                            id="identifier"
                            name="identifier"
                            value="<?= e($identifierVal) ?>"
                            autocomplete="username"
                            maxlength="100"
                            placeholder="Enter your username or email"
                            required
                            autofocus
                        >
                    </div>
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    <span>Send Reset Instructions</span>
                </button>
            </form>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Return to Sign In</a>
            </footer>

        <?php endif; ?>
    </main>
</div>

<script src="js/script.js"></script>
</body>
</html>
