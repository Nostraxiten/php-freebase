<?php
/**
 * dashboard.php
 * -------------
 * Account and administration dashboard.
 * Adapts contextually based on user role (Admin vs Standard User).
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();
require_login();

$username       = (string) ($_SESSION['username'] ?? 'User');
$email          = (string) ($_SESSION['email'] ?? '');
$role           = (string) ($_SESSION['role'] ?? 'user');
$isAdmin        = is_admin();
$sessionCreated = date('H:i:s d/m/Y', (int) ($_SESSION['created_at'] ?? time()));
$lastActivity   = date('H:i:s', (int) ($_SESSION['last_activity'] ?? time()));

$dbConnected = is_database_connected();
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
            <div class="stat-meta">Active session verified</div>
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
            <div class="stat-meta">Encrypted connection</div>
        </div>
    </div>

    <!-- Main Content Area -->
    <?php if ($isAdmin): ?>
        <section class="card content-card">
            <div class="card-header">
                <h2>Administrative Control</h2>
                <span class="badge badge-admin">Privileged Access</span>
            </div>
            <p>
                You are authenticated as the system administrator. From here, you have full oversight of user records,
                database integrity, and platform configuration.
            </p>
            <div class="mt-4">
                <a href="security.php" class="btn btn-primary">
                    Access Security Architecture &amp; Threat Telemetry &rarr;
                </a>
            </div>
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
                        <td><strong>Idle Timeout Limit</strong></td>
                        <td><?= (int)(SESSION_LIFETIME / 60) ?> minutes of inactivity</td>
                    </tr>
                    <tr>
                        <td><strong>Absolute Session Cap</strong></td>
                        <td><?= (int)(SESSION_MAX_LIFETIME / 3600) ?> hours</td>
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
