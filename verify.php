<?php
/**
 * verify.php
 * ----------
 * Email verification endpoint.
 * Validates cryptographic tokens and activates user accounts.
 * Hardened with Referrer-Policy: no-referrer and cache suppression.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers('no-referrer');
send_no_cache_headers();
start_secure_session();

$token = trim((string) ($_GET['token'] ?? ''));
$verified = false;
$username = '';
$error = '';

if ($token === '') {
    $error = 'No verification token was provided.';
} else {
    $res = verify_email_token($token);
    if ($res['success']) {
        $verified = true;
        $username = $res['username'];
    } else {
        $error = $res['error'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Verification &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
    <main class="card auth-card text-center">
        <div class="auth-header">
            <div class="brand-badge">
                <span class="badge-dot"></span>
                <span><?= e(APP_NAME) ?></span>
            </div>
            <h1>Account Verification</h1>
        </div>

        <?php if ($verified): ?>
            <div class="alert alert-success" role="alert">
                <span class="alert-message">Email address verified successfully.</span>
            </div>

            <p>Welcome, <strong><?= e($username) ?></strong>! Your account has been verified and is now ready for use.</p>

            <div class="mt-4">
                <a href="admin/login.php" class="btn btn-primary btn-block">
                    Proceed to Sign In &rarr;
                </a>
            </div>

        <?php else: ?>
            <div class="alert alert-danger" role="alert">
                <span class="alert-message"><?= e($error) ?></span>
            </div>

            <p class="subtitle">The verification link may have expired or already been activated.</p>

            <div class="mt-4">
                <a href="register.php" class="btn btn-secondary btn-block">
                    Create a New Account
                </a>
            </div>
        <?php endif; ?>

        <footer class="auth-footer">
            <a href="index.php" class="link-muted">&larr; Return to Homepage</a>
        </footer>
    </main>
</div>

<script src="js/script.js"></script>
</body>
</html>
