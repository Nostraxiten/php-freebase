<?php
/**
 * reset-password.php
 * ------------------
 * Password reset execution endpoint.
 * Validates the single-use token against stored SHA-256 hashes, updates the password,
 * increments the account session version to invalidate old sessions, and consumes the token.
 * Hardened with Referrer-Policy: no-referrer and strict cache suppression.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers('no-referrer');
send_no_cache_headers();
start_secure_session();

$token = trim((string) ($_GET['token'] ?? ($_POST['token'] ?? '')));
$tokenData = null;
$error = '';
$success = false;

if ($token === '') {
    $error = 'No reset token was provided.';
} else {
    $tokenData = verify_password_reset_token($token);
    if ($tokenData === null && $_SERVER['REQUEST_METHOD'] !== 'POST') {
        $error = 'This password reset link is invalid, has expired, or has already been used.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Security verification failed. Please refresh and try again.';
    } elseif ($tokenData === null) {
        $error = 'This password reset link is invalid, has expired, or has already been used.';
    } else {
        $newPassword     = (string) ($_POST['password'] ?? '');
        $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

        if ($newPassword === '') {
            $error = 'Please enter your new password.';
        } elseif ($newPassword !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (!validate_password_length($newPassword)) {
            $error = 'Password must be between 8 and 128 characters.';
        } else {
            $res = complete_password_reset($token, $newPassword);
            if ($res['success']) {
                $success = true;
            } else {
                $error = $res['error'];
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
    <title>Set New Password &mdash; <?= e(APP_NAME) ?></title>
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
            <h1>Create New Password</h1>
            <?php if ($tokenData !== null): ?>
                <p class="subtitle">Resetting credentials for <strong><?= e($tokenData['username']) ?></strong></p>
            <?php endif; ?>
        </div>

        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                <span class="alert-message">Your password has been successfully updated. All prior sessions for this account have been invalidated.</span>
            </div>

            <div class="mt-4">
                <a href="admin/login.php" class="btn btn-primary btn-block">
                    Proceed to Sign In &rarr;
                </a>
            </div>

        <?php elseif ($tokenData === null && $error !== ''): ?>

            <div class="alert alert-danger" role="alert">
                <span class="alert-message"><?= e($error) ?></span>
            </div>

            <p class="subtitle">Reset links are single-use and automatically expire after 1 hour.</p>

            <div class="mt-4">
                <a href="forgot-password.php" class="btn btn-secondary btn-block">
                    Request a New Reset Link
                </a>
            </div>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Return to Sign In</a>
            </footer>

        <?php else: ?>

            <?php if ($error !== ''): ?>
                <div class="alert alert-danger" role="alert">
                    <span class="alert-message"><?= e($error) ?></span>
                    <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
                </div>
            <?php endif; ?>

            <form method="post" action="reset-password.php" class="auth-form" novalidate autocomplete="off">
                <?= csrf_field() ?>
                <input type="hidden" name="token" id="reset-token-field" value="<?= e($token) ?>">

                <div class="form-group">
                    <label for="password">New Password <span class="label-hint">(min 8 characters)</span></label>
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
                            autofocus
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
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
                    <span>Update Password &amp; Invalidate Sessions</span>
                </button>
            </form>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Cancel and Return to Sign In</a>
            </footer>

        <?php endif; ?>
    </main>
</div>

<script>
// Clear token from browser address bar after page load to prevent history/shoulder leakage
if (window.history.replaceState && window.location.search.includes('token=')) {
    window.history.replaceState({}, document.title, window.location.pathname);
}
</script>
<script src="js/script.js"></script>
</body>
</html>
