<?php
/**
 * reset-user-password.php
 * -----------------------
 * Administrator endpoint to set a new password for a user account.
 * Strictly requires admin privileges, HTTP POST, and CSRF token.
 * Never reveals or displays prior passwords.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('dashboard.php');
}

if (!verify_csrf($_POST['csrf_token'] ?? null)) {
    $_SESSION['admin_flash'] = ['type' => 'danger', 'message' => 'Security token expired. Please try again.'];
    redirect('dashboard.php');
}

$targetUserId = (int) ($_POST['target_user_id'] ?? 0);
$newPassword  = (string) ($_POST['new_password'] ?? '');

if ($targetUserId <= 0) {
    $_SESSION['admin_flash'] = ['type' => 'danger', 'message' => 'Invalid target user selected.'];
    redirect('dashboard.php');
}

if (!validate_password_length($newPassword)) {
    $_SESSION['admin_flash'] = ['type' => 'danger', 'message' => 'New password must be between 8 and 128 characters.'];
    redirect('dashboard.php');
}

$res = admin_reset_user_password($targetUserId, $newPassword);

if ($res['success']) {
    $_SESSION['admin_flash'] = [
        'type'    => 'success',
        'message' => sprintf('Password for user "%s" was successfully reset. All active sessions for that user were invalidated.', $res['username'])
    ];
} else {
    $_SESSION['admin_flash'] = ['type' => 'danger', 'message' => $res['error']];
}

redirect('dashboard.php');
