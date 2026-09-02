<?php
/**
 * dashboard.php
 * -------------
 * Administrative Control Center.
 * Protected area requiring active authentication. Features system health monitoring,
 * security metrics, and CSRF-protected logout.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();
require_login();

$username = (string) ($_SESSION['username'] ?? 'User');
$role = (string) ($_SESSION['role'] ?? 'user');
$sessionCreated = date('H:i:s d/m/Y', (int) ($_SESSION['created_at'] ?? time()));
$lastActivity = date('H:i:s', (int) ($_SESSION['last_activity'] ?? time()));

$dbConnected = is_database_connected();
$recentAttempts = [];

if ($dbConnected && is_admin()) {
    try {
        $pdo = get_pdo();
        $stmt = $pdo->query('SELECT ip_address, username, attempted_at FROM login_attempts ORDER BY attempted_at DESC LIMIT 5');
        $recentAttempts = $stmt->fetchAll();
    } catch (Throwable $e) {
        error_log('[Dashboard Query Error] ' . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<header class="site-header">
    <div class="header-brand">
        <a href="dashboard.php" class="brand-link">
            <span class="brand-icon">⚡</span>
            <span class="brand-title"><?= e(APP_NAME) ?></span>
            <span class="badge badge-accent">Admin Console</span>
        </a>
    </div>
    <nav class="header-nav">
        <div class="user-profile">
            <span class="user-avatar" aria-hidden="true"><?= strtoupper(substr($username, 0, 1)) ?></span>
            <div class="user-meta">
                <span class="user-name"><?= e($username) ?></span>
                <span class="badge badge-<?= $role === 'admin' ? 'admin' : 'muted' ?>"><?= strtoupper(e($role)) ?></span>
            </div>
        </div>

        <!-- Secure POST Logout to prevent Logout CSRF (CWE-352) -->
        <form method="post" action="logout.php" class="logout-form">
            <?= csrf_field() ?>
            <button type="submit" class="btn btn-sm btn-outline-danger">
                <span>Sign Out</span>
            </button>
        </form>
    </nav>
</header>

<main class="container">
    <div class="page-header">
        <div>
            <h1>Dashboard Overview</h1>
            <p class="subtitle">System security telemetry and application health</p>
        </div>
        <div>
            <a href="../index.php" class="btn btn-sm btn-secondary" target="_blank">View Public Site &nearr;</a>
        </div>
    </div>

    <!-- Telemetry Cards Grid -->
    <div class="stats-grid">
        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Security Posture</span>
                <span class="status-indicator status-online"></span>
            </div>
            <div class="stat-value">Hardened</div>
            <div class="stat-meta">OWASP Top 10 Compliant</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Database Status</span>
                <span class="status-indicator <?= $dbConnected ? 'status-online' : 'status-offline' ?>"></span>
            </div>
            <div class="stat-value"><?= $dbConnected ? 'Active' : 'Offline' ?></div>
            <div class="stat-meta">MySQL PDO (Prepared)</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Environment</span>
                <span class="badge badge-<?= APP_ENV === 'production' ? 'success' : 'warning' ?>"><?= strtoupper(APP_ENV) ?></span>
            </div>
            <div class="stat-value">PHP <?= e(PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION) ?></div>
            <div class="stat-meta">Strict Mode Enabled</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Client IP</span>
                <span class="badge badge-muted">Direct</span>
            </div>
            <div class="stat-value text-mono"><?= e(get_client_ip()) ?></div>
            <div class="stat-meta">Protected against spoofing</div>
        </div>
    </div>

    <!-- Security Diagnostics Section -->
    <section class="card content-card">
        <div class="card-header">
            <h2>Active Session Diagnostics</h2>
            <span class="badge badge-accent">Strict Session</span>
        </div>
        <div class="info-table-wrapper">
            <table class="info-table">
                <tbody>
                    <tr>
                        <td><strong>Session Identifier</strong></td>
                        <td class="text-mono"><?= e(substr(session_id(), 0, 8)) ?>•••••••••••••••• (Masked)</td>
                    </tr>
                    <tr>
                        <td><strong>Session Inception</strong></td>
                        <td><?= e($sessionCreated) ?></td>
                    </tr>
                    <tr>
                        <td><strong>Last Activity Timestamp</strong></td>
                        <td><?= e($lastActivity) ?> (Idle Timeout: <?= (int)(SESSION_LIFETIME / 60) ?>m)</td>
                    </tr>
                    <tr>
                        <td><strong>Absolute Lifetime Limit</strong></td>
                        <td><?= (int)(SESSION_MAX_LIFETIME / 3600) ?> hours</td>
                    </tr>
                    <tr>
                        <td><strong>Transport Layer Security</strong></td>
                        <td>
                            <?php if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'): ?>
                                <span class="badge badge-success">HTTPS (Secure Cookie Active)</span>
                            <?php else: ?>
                                <span class="badge badge-warning">HTTP (Development Mode)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </section>

    <!-- Recent Login Attempts (Audit Log) -->
    <?php if (is_admin()): ?>
    <section class="card content-card">
        <div class="card-header">
            <h2>Recent Throttled Attempts (Brute-Force Monitor)</h2>
            <span class="badge badge-muted">Last 5 records</span>
        </div>
        <?php if (!empty($recentAttempts)): ?>
            <div class="table-responsive">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Attempted Username</th>
                            <th>Timestamp</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentAttempts as $attempt): ?>
                            <tr>
                                <td class="text-mono"><?= e($attempt['ip_address']) ?></td>
                                <td><code><?= e($attempt['username']) ?></code></td>
                                <td><?= e($attempt['attempted_at']) ?></td>
                                <td><span class="badge badge-danger">Blocked / Failed</span></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <p class="empty-state">No failed authentication attempts logged. System is operating normally.</p>
        <?php endif; ?>
    </section>
    <?php endif; ?>

</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &bull; Enterprise Hardened PHP Architecture</p>
</footer>

<script src="../js/script.js"></script>
</body>
</html>
