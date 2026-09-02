<?php
/**
 * emergency-reset.php
 * -------------------
 * Offline Emergency Administrator Password Reset.
 * Enabled ONLY when the ADMIN_RECOVERY_SECRET environment variable is populated.
 * Uses constant-time hash comparison and rate limiting to prevent brute-force attacks.
 * Never stores or reveals plaintext passwords or the secret itself.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$isConfigured = (ADMIN_RECOVERY_SECRET !== '');
$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$isConfigured) {
        $error = 'Emergency recovery is disabled on this server.';
    } elseif (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Security verification failed. Please refresh and try again.';
    } else {
        $secret          = (string) ($_POST['recovery_secret'] ?? '');
        $newPassword     = (string) ($_POST['new_password'] ?? '');
        $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

        if ($secret === '' || $newPassword === '') {
            $error = 'All fields are required.';
        } elseif ($newPassword !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (!validate_password_length($newPassword)) {
            $error = 'Password must be between 8 and 128 characters.';
        } else {
            $res = emergency_secret_reset_admin_password($secret, $newPassword);
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
    <title>Emergency Admin Reset &mdash; <?= e(APP_NAME) ?></title>
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
            <h1>Emergency Recovery</h1>
            <p class="subtitle">Offline administrator credential reset</p>
        </div>

        <?php if (!$isConfigured): ?>
            <div class="alert alert-danger" role="alert">
                <span class="alert-message">Emergency Recovery Disabled</span>
            </div>
            <p>The emergency administrative recovery feature is currently disabled on this instance.</p>
            <p class="subtitle">To enable it, set <code>ADMIN_RECOVERY_SECRET</code> in your server environment or <code>.env</code> file.</p>

            <footer class="auth-footer">
                <a href="admin/login.php" class="link-muted">&larr; Return to Sign In</a>
            </footer>

        <?php elseif ($success): ?>
            <div class="alert alert-success" role="alert">
                <span class="alert-message">The administrator password was reset successfully. All active sessions have been invalidated.</span>
            </div>

            <div class="mt-4">
                <a href="admin/login.php" class="btn btn-primary btn-block">
                    Proceed to Admin Sign In &rarr;
                </a>
            </div>

        <?php else: ?>

            <?php if ($error !== ''): ?>
                <div class="alert alert-danger" role="alert">
                    <span class="alert-message"><?= e($error) ?></span>
                    <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
                </div>
            <?php endif; ?>

            <form method="post" action="emergency-reset.php" class="auth-form" novalidate autocomplete="off">
                <?= csrf_field() ?>

                <div class="form-group">
                    <label for="recovery_secret">Admin Recovery Secret</label>
                    <div class="input-container">
                        <input
                            type="password"
                            id="recovery_secret"
                            name="recovery_secret"
                            autocomplete="off"
                            placeholder="Enter the environment recovery secret"
                            required
                            autofocus
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="new_password">New Admin Password <span class="label-hint">(min 8 characters)</span></label>
                    <div class="input-container">
                        <input
                            type="password"
                            id="new_password"
                            name="new_password"
                            autocomplete="new-password"
                            minlength="8"
                            maxlength="128"
                            placeholder="••••••••••••"
                            required
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
                    <span>Authorize Emergency Reset</span>
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
