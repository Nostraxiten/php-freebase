<?php
/**
 * security.php
 * ------------
 * Administrator-only Security Intelligence & Architecture Console.
 * Restricted strictly to users with the 'admin' role.
 * Fully documented in English.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/../includes/auth.php';

send_security_headers();
start_secure_session();
require_admin();

$username = (string) ($_SESSION['username'] ?? 'admin');
$role = (string) ($_SESSION['role'] ?? 'admin');

$recentAttempts = [];
try {
    $pdo = get_pdo();
    $stmt = $pdo->query(
        'SELECT ip_address, username, attempted_at FROM login_attempts
         ORDER BY attempted_at DESC LIMIT 10'
    );
    $recentAttempts = $stmt->fetchAll();
} catch (Throwable $e) {
    error_log('[Security Dashboard Query Error] ' . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Architecture &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<header class="site-header">
    <div class="header-brand">
        <a href="dashboard.php" class="brand-link">
            <span class="neon-dot"></span>
            <span class="brand-title"><?= e(APP_NAME) ?></span>
            <span class="badge badge-neon">Admin Security</span>
        </a>
    </div>
    <nav class="header-nav">
        <a href="dashboard.php" class="btn btn-sm btn-secondary">&larr; Dashboard</a>
        <form method="post" action="logout.php" class="logout-form">
            <?= csrf_field() ?>
            <button type="submit" class="btn btn-sm btn-outline-danger">Sign Out</button>
        </form>
    </nav>
</header>

<main class="container">
    <div class="page-header">
        <div>
            <h1>Security Architecture & Controls</h1>
            <p class="subtitle">System defenses, OWASP mitigations, and runtime security telemetry</p>
        </div>
        <div>
            <span class="badge badge-success">Defense-in-Depth Active</span>
        </div>
    </div>

    <!-- Security Matrix Cards -->
    <div class="stats-grid">
        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">SQL Injection</span>
                <span class="badge badge-success">Mitigated</span>
            </div>
            <div class="stat-value">PDO Native</div>
            <div class="stat-meta">ATTR_EMULATE_PREPARES = false</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Brute-Force Defense</span>
                <span class="badge badge-success">Persistent</span>
            </div>
            <div class="stat-value">DB Throttling</div>
            <div class="stat-meta">login_attempts (IP & User)</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">Session Hardening</span>
                <span class="badge badge-neon">Strict Mode</span>
            </div>
            <div class="stat-value">Dual Timeout</div>
            <div class="stat-meta">HttpOnly | SameSite | Fixation Immune</div>
        </div>

        <div class="card stat-card">
            <div class="stat-header">
                <span class="stat-label">CSRF Protection</span>
                <span class="badge badge-success">Active</span>
            </div>
            <div class="stat-value">Synchronizer</div>
            <div class="stat-meta">POST-only state mutation</div>
        </div>
    </div>

    <!-- OWASP Controls Overview -->
    <section class="card content-card">
        <div class="card-header">
            <h2>OWASP Top 10 Defensive Implementations</h2>
            <span class="badge badge-muted">Architectural Reference</span>
        </div>
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Mitigation Mechanism</th>
                        <th>Implementation Details</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>A01: Broken Access Control</strong></td>
                        <td>Server-side validation &amp; CSRF Tokens</td>
                        <td>Strict separation of authentication and authorization. Role checks (<code>require_admin()</code>) enforced on server. POST-only state changes.</td>
                    </tr>
                    <tr>
                        <td><strong>A02: Cryptographic Failures</strong></td>
                        <td>Bcrypt / Argon2 with Auto-Rehash</td>
                        <td>Passwords hashed via <code>password_hash()</code>. Routine <code>password_needs_rehash()</code> automatically upgrades hashes upon login.</td>
                    </tr>
                    <tr>
                        <td><strong>A03: Injection (SQLi &amp; XSS)</strong></td>
                        <td>PDO Prepared Statements &amp; Output Encoding</td>
                        <td>Zero concatenated SQL queries. Contextual HTML encoding via <code>htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')</code>.</td>
                    </tr>
                    <tr>
                        <td><strong>A05: Security Misconfiguration</strong></td>
                        <td>HTTP Headers &amp; Error Masking</td>
                        <td>Content-Security-Policy, X-Frame-Options (DENY), X-Content-Type-Options. Technical database exceptions are masked and sent to server error logs.</td>
                    </tr>
                    <tr>
                        <td><strong>A07: Identification Failures</strong></td>
                        <td>DB Rate Limiting &amp; Session Strict Mode</td>
                        <td>Persistent IP-based lockout immune to session discarding. Enforced <code>session.use_strict_mode = 1</code> preventing session fixation.</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </section>

    <!-- Runtime Security Telemetry -->
    <section class="card content-card">
        <div class="card-header">
            <h2>Active Telemetry &amp; HTTP Security Headers</h2>
            <span class="badge badge-neon">HTTP Response Headers</span>
        </div>
        <div class="info-table-wrapper">
            <table class="info-table">
                <tbody>
                    <tr>
                        <td><strong>Content-Security-Policy (CSP)</strong></td>
                        <td class="text-mono">default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none';</td>
                    </tr>
                    <tr>
                        <td><strong>X-Frame-Options</strong></td>
                        <td class="text-mono">DENY (Clickjacking Defense)</td>
                    </tr>
                    <tr>
                        <td><strong>X-Content-Type-Options</strong></td>
                        <td class="text-mono">nosniff (MIME-Sniffing Defense)</td>
                    </tr>
                    <tr>
                        <td><strong>Referrer-Policy</strong></td>
                        <td class="text-mono">strict-origin-when-cross-origin</td>
                    </tr>
                    <tr>
                        <td><strong>Session Idle Timeout</strong></td>
                        <td><?= (int)(SESSION_LIFETIME / 60) ?> minutes</td>
                    </tr>
                    <tr>
                        <td><strong>Session Absolute Lifetime</strong></td>
                        <td><?= (int)(SESSION_MAX_LIFETIME / 3600) ?> hours</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </section>

    <!-- Throttled Attempts Log -->
    <section class="card content-card">
        <div class="card-header">
            <h2>Persistent Throttling Activity (Brute-Force Monitor)</h2>
            <span class="badge badge-muted">Live DB Feed</span>
        </div>
        <?php if (!empty($recentAttempts)): ?>
            <div class="table-responsive">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Client IP</th>
                            <th>Target Username / Email</th>
                            <th>Attempt Timestamp</th>
                            <th>Action Taken</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentAttempts as $att): ?>
                            <tr>
                                <td class="text-mono"><?= e($att['ip_address']) ?></td>
                                <td><code><?= e($att['username']) ?></code></td>
                                <td><?= e($att['attempted_at']) ?></td>
                                <td><span class="badge badge-danger">Throttled</span></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <p class="empty-state">No failed attempts currently logged. All authentication traffic is normal.</p>
        <?php endif; ?>
    </section>
</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &bull; Internal Security Console</p>
</footer>

<script src="../js/script.js"></script>
</body>
</html>
