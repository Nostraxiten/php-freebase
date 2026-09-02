<?php
/**
 * manage-role.php
 * ---------------
 * Super Administrator (root) endpoint to manage user roles within the web application.
 * Allows elevating standard users to 'admin' and demoting administrators to 'user'.
 * Protected strictly by require_super_admin(), HTTP POST, and CSRF token verification.
 * Automatically increments session_version to immediately invalidate the target user's active sessions.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
send_no_cache_headers();
start_secure_session();
require_super_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('dashboard.php');
}

if (!verify_csrf($_POST['csrf_token'] ?? null)) {
    $_SESSION['admin_flash'] = [
        'type'    => 'danger',
        'message' => 'Security token expired or invalid. Please try again.'
    ];
    redirect('dashboard.php');
}

$targetUserId = (int) ($_POST['target_user_id'] ?? 0);
$newRole      = strtolower(trim((string) ($_POST['new_role'] ?? '')));

if ($targetUserId <= 0) {
    $_SESSION['admin_flash'] = [
        'type'    => 'danger',
        'message' => 'Invalid target user specified.'
    ];
    redirect('dashboard.php');
}

if (!in_array($newRole, ['admin', 'user'], true)) {
    $_SESSION['admin_flash'] = [
        'type'    => 'danger',
        'message' => 'Invalid role selected. Allowed roles are "admin" or "user".'
    ];
    redirect('dashboard.php');
}

try {
    $pdo = get_pdo();
    $stmt = $pdo->prepare('SELECT id, username, role FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$targetUserId]);
    $targetUser = $stmt->fetch();

    if (!$targetUser) {
        $_SESSION['admin_flash'] = [
            'type'    => 'danger',
            'message' => 'Target user account does not exist.'
        ];
        redirect('dashboard.php');
    }

    // Protect Super Admin root account from role alteration or demotion
    if ($targetUser['username'] === 'root' || (int) $targetUser['id'] === (int) ($_SESSION['user_id'] ?? 0)) {
        $_SESSION['admin_flash'] = [
            'type'    => 'danger',
            'message' => 'The Super Administrator (root) account role cannot be modified.'
        ];
        redirect('dashboard.php');
    }

    // Update role and increment session_version to force session re-authentication with new privileges
    $updateStmt = $pdo->prepare('UPDATE users SET role = ?, session_version = session_version + 1 WHERE id = ?');
    $updateStmt->execute([$newRole, $targetUserId]);

    $_SESSION['admin_flash'] = [
        'type'    => 'success',
        'message' => sprintf(
            'Permissions updated: User "%s" is now assigned the "%s" role. All active sessions for this user were invalidated.',
            e($targetUser['username']),
            strtoupper($newRole)
        )
    ];
} catch (Throwable $e) {
    error_log('[Manage Role Exception] ' . $e->getMessage());
    $_SESSION['admin_flash'] = [
        'type'    => 'danger',
        'message' => 'Failed to update user role due to a database error.'
    ];
}

redirect('dashboard.php');
