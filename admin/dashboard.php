<?php
/**
 * dashboard.php
 * -------------
 * Account and administration dashboard.
 * Adapts contextually based on user role (Admin vs Standard User).
 * Real runtime security telemetry and administrative user password reset.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
send_no_cache_headers();
start_secure_session();
require_login();

$username       = (string) ($_SESSION['username'] ?? 'User');
$email          = (string) ($_SESSION['email'] ?? '');
$role           = (string) ($_SESSION['role'] ?? 'user');
$currentUserId  = (int) ($_SESSION['user_id'] ?? 0);
$sessionVer     = (int) ($_SESSION['session_version'] ?? 1);
$isAdmin        = is_admin();
$sessionCreated = date('H:i:s d/m/Y', (int) ($_SESSION['created_at'] ?? time()));
$lastActivity   = date('H:i:s', (int) ($_SESSION['last_activity'] ?? time()));

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
           ((int) ($_SERVER['SERVER_PORT'] ?? 80) === 443) ||
           (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

$dbConnected = is_database_connected();
$allUsers = [];
$flash = $_SESSION['admin_flash'] ?? null;
unset($_SESSION['admin_flash']);

if ($dbConnected && $isAdmin) {
    try {
        $pdo = get_pdo();
        $stmt = $pdo->query('SELECT id, username, email, role, is_active, email_verified_at, created_at, session_version FROM users ORDER BY id ASC');
        $allUsers = $stmt->fetchAll();
    } catch (Throwable $e) {
        error_log('[Dashboard User Query Error] ' . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<header class="site-header">
    <div class="header-brand">
        <a href="dashboard.php" class="brand-link">
            <span class="neon-dot"></span>
            <span class="brand-title"><?= e(APP_NAME) ?></span>
            <span class="badge badge-<?= $isAdmin ? 'admin' : 'neon' ?>">
                <?= $isAdmin ? 'Admin Console' : 'Member Portal' ?>
            </span>
        </a>
    </div>
    <nav class="header-nav">
        <?php if ($isAdmin): ?>
            <a href="security.php" class="btn btn-sm btn-secondary">Security Console</a>
        <?php endif; ?>

        <div class="user-profile">
            <span class="user-avatar" aria-hidden="true"><?= strtoupper(substr($username, 0, 1)) ?></span>
            <div class="user-meta">
                <span class="user-name"><?= e($username) ?></span>
                <span class="badge badge-<?= $isAdmin ? 'admin' : 'muted' ?>"><?= strtoupper(e($role)) ?></span>
            </div>
        </div>

        <form method="post" action="logout.php" class="logout-form">
            <?= csrf_field() ?>
            <button type="submit" class="btn btn-sm btn-outline-danger">Sign Out</button>
        </form>
    </nav>
</header>

<main class="container">
    <?php if ($flash !== null): ?>
        <div class="alert alert-<?= e($flash['type']) ?>" role="alert">
            <span class="alert-message"><?= e($flash['message']) ?></span>
            <button type="button" class="alert-close" aria-label="Dismiss alert">&times;</button>
        </div>
    <?php endif; ?>

    <div class="page-header">
        <div>
            <h1><?= $isAdmin ? 'System Administration' : 'Member Dashboard' ?></h1>
            <p class="subtitle">Welcome back, <?= e($username) ?>.</p>
        </div>
        <div class="header-actions">
            <?php if ($isAdmin): ?>
                <a href="security.php" class="btn btn-sm btn-primary">Open Security Console &rarr;</a>
            <?php endif; ?>
            <a href="../index.php" class="btn btn-sm btn-secondary" target="_blank">View Portal &nearr;</a>
        </div>
    </div>

    <!-- Status Overview -->
    <div class="stats-grid">
        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Account Role</span>
                <span class="badge badge-<?= $isAdmin ? 'admin' : 'neon' ?>"><?= strtoupper(e($role)) ?></span>
            </div>
            <div class="stat-value"><?= e($username) ?></div>
            <div class="stat-meta">Session Version: v<?= (int) $sessionVer ?></div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Email Status</span>
                <span class="status-indicator status-online"></span>
            </div>
            <div class="stat-value">Verified</div>
            <div class="stat-meta"><?= e($email !== '' ? $email : 'admin@freebase.local') ?></div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Session Inception</span>
                <span class="badge badge-muted">Session Active</span>
            </div>
            <div class="stat-value text-mono"><?= e($lastActivity) ?></div>
            <div class="stat-meta">Started: <?= e($sessionCreated) ?></div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Client IP</span>
                <span class="badge badge-muted">Direct</span>
            </div>
            <div class="stat-value text-mono"><?= e(get_client_ip()) ?></div>
            <div class="stat-meta">
                <?= $isHttps ? 'TLS Active (Encrypted)' : 'Plaintext HTTP (Insecure)' ?>
            </div>
        </div>
    </div>

    <!-- User Management Section (Admin Only) -->
    <?php if ($isAdmin): ?>
        <section class="card content-card">
            <div class="card-header">
                <h2>User Account Management &amp; Password Reset</h2>
                <span class="badge badge-admin">Admin Capability</span>
            </div>
            <p>
                As administrator, you can reset passwords for accounts directly without ever seeing their prior passwords.
                Resetting a password automatically increments the account's session version, invalidating all existing sessions.
            </p>

            <?php if (!empty($allUsers)): ?>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Version</th>
                                <th>Status</th>
                                <th>Emergency Password Reset</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($allUsers as $u): ?>
                                <tr>
                                    <td>#<?= (int) $u['id'] ?></td>
                                    <td><strong><?= e($u['username']) ?></strong></td>
                                    <td><?= e($u['email']) ?></td>
                                    <td><span class="badge badge-<?= $u['role'] === 'admin' ? 'admin' : 'muted' ?>"><?= strtoupper(e($u['role'])) ?></span></td>
                                    <td class="text-mono">v<?= (int) $u['session_version'] ?></td>
                                    <td>
                                        <?php if (!empty($u['email_verified_at'])): ?>
                                            <span class="badge badge-success">Verified</span>
                                        <?php else: ?>
                                            <span class="badge badge-warning">Unverified</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ((int) $u['id'] === $currentUserId): ?>
                                            <span class="badge badge-muted">Current Session (Self-reset restricted)</span>
                                        <?php else: ?>
                                            <form method="post" action="reset-user-password.php" class="inline-reset-form">
                                                <?= csrf_field() ?>
                                                <input type="hidden" name="target_user_id" value="<?= (int) $u['id'] ?>">
                                                <input type="password" name="new_password" placeholder="New pass (min 8)" minlength="8" maxlength="128" required class="input-inline">
                                                <button type="submit" class="btn btn-sm btn-secondary" onclick="return confirm('Reset password for this user? All existing sessions will be invalidated.');">Set Password</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="empty-state">No users retrieved.</p>
            <?php endif; ?>
        </section>
    <?php else: ?>
        <section class="card content-card">
            <div class="card-header">
                <h2>Member Sector</h2>
                <span class="badge badge-neon">Standard Account</span>
            </div>
            <p>
                Your account is active and verified. The platform modules are currently being prepared for deployment.
            </p>
            <p class="subtitle">Check back regularly for updates to your dashboard.</p>
        </section>
    <?php endif; ?>

    <!-- Session Diagnostics -->
    <section class="card content-card">
        <div class="card-header">
            <h2>Active Session Details</h2>
            <span class="badge badge-muted">Runtime Security</span>
        </div>
        <div class="info-table-wrapper">
            <table class="info-table">
                <tbody>
                    <tr>
                        <td><strong>Session ID</strong></td>
                        <td class="text-mono"><?= e(substr(session_id(), 0, 8)) ?>•••••••••••••••• (Masked)</td>
                    </tr>
                    <tr>
                        <td><strong>Session Version</strong></td>
                        <td>v<?= (int) $sessionVer ?> (Invalidated immediately if password is reset)</td>
                    </tr>
                    <tr>
                        <td><strong>Idle Timeout Limit</strong></td>
                        <td><?= (int)(SESSION_LIFETIME / 60) ?> minutes of inactivity</td>
                    </tr>
                    <tr>
                        <td><strong>Absolute Session Cap</strong></td>
                        <td><?= (int)(SESSION_MAX_LIFETIME / 3600) ?> hours</td>
                    </tr>
                    <tr>
                        <td><strong>Transport Layer Security</strong></td>
                        <td>
                            <?php if ($isHttps): ?>
                                <span class="badge badge-success">HTTPS (TLS Active - Secure Cookies Enforced)</span>
                            <?php else: ?>
                                <span class="badge badge-warning">HTTP (Plaintext Insecure - Development Mode)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </section>
</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &bull; Session securely active</p>
</footer>

<script src="../js/script.js"></script>
</body>
</html>
