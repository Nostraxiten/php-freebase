<?php
/**
 * index.php
 * ---------
 * Public presentation and landing portal for PHP FreeBase.
 * Demonstrates architecture features, security controls, and quick-start guides.
 */

declare(strict_types=1);

define('APP_SECURE', true);

require_once __DIR__ . '/includes/auth.php';

send_security_headers();
start_secure_session();

$loggedIn = is_logged_in();
$currentUser = $loggedIn ? ($_SESSION['username'] ?? 'User') : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e(APP_NAME) ?> &mdash; Secure PHP Starter Architecture</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<header class="site-header">
    <div class="header-brand">
        <a href="index.php" class="brand-link">
            <span class="brand-icon">🛡️</span>
            <span class="brand-title"><?= e(APP_NAME) ?></span>
            <span class="badge badge-accent">v2.0 Hardened</span>
        </a>
    </div>
    <nav class="header-nav">
        <?php if ($loggedIn): ?>
            <span class="badge badge-admin">Active Session: <?= e((string)$currentUser) ?></span>
            <a href="admin/dashboard.php" class="btn btn-sm btn-primary">Go to Dashboard &rarr;</a>
        <?php else: ?>
            <a href="admin/login.php" class="btn btn-sm btn-primary">Admin Portal &rarr;</a>
        <?php endif; ?>
    </nav>
</header>

<main class="container">
    <!-- Hero Section -->
    <section class="hero-section">
        <div class="hero-badge">ENTERPRISE-GRADE STARTER BASE</div>
        <h1 class="hero-title">Secure by Design. Minimal by Choice.</h1>
        <p class="hero-desc">
            A hardened, modern PHP foundation equipped with defense-in-depth security,
            OWASP Top 10 mitigations, database-backed brute force protection, and a sleek Dark UI.
        </p>
        <div class="hero-actions">
            <?php if ($loggedIn): ?>
                <a href="admin/dashboard.php" class="btn btn-primary">Enter Dashboard &rarr;</a>
            <?php else: ?>
                <a href="admin/login.php" class="btn btn-primary">Open Admin Console &rarr;</a>
            <?php endif; ?>
            <a href="README.md" class="btn btn-secondary" target="_blank">View Documentation</a>
        </div>
    </section>

    <!-- Security Badges Feature Grid -->
    <div class="features-grid">
        <div class="card feature-card">
            <div class="feature-icon">🔒</div>
            <h3>Zero SQL Injection</h3>
            <p>Native PDO prepared statements with emulated prepares disabled (<span class="code-inline">ATTR_EMULATE_PREPARES = false</span>).</p>
        </div>

        <div class="card feature-card">
            <div class="feature-icon">🛡️</div>
            <h3>Brute-Force Shield</h3>
            <p>Database-backed rate limiting by IP and username. Session-drop evasion attacks are completely mitigated.</p>
        </div>

        <div class="card feature-card">
            <div class="feature-icon">🔑</div>
            <h3>Hardened Sessions</h3>
            <p>Strict mode enabled, HttpOnly, SameSite, idle timeout, absolute lifetime expiration, and fixation defense.</p>
        </div>

        <div class="card feature-card">
            <div class="feature-icon">⚡</div>
            <h3>CSRF Protection</h3>
            <p>Cryptographic synchronizer tokens on forms with automatic rotation and POST-only protected logout.</p>
        </div>

        <div class="card feature-card">
            <div class="feature-icon">🌐</div>
            <h3>Security Headers</h3>
            <p>Centralized PHP + Apache headers: Strict CSP, Frame-Ancestors, X-Content-Type-Options, and Permissions-Policy.</p>
        </div>

        <div class="card feature-card">
            <div class="feature-icon">🎨</div>
            <h3>Modern Dark UI</h3>
            <p>Crafted with modern CSS variables, accessible high-contrast typography, fluid responsive layout, and zero heavy dependencies.</p>
        </div>
    </div>

    <!-- Quick Architecture Reference -->
    <section class="card content-card">
        <div class="card-header">
            <h2>Ready to Extend</h2>
            <span class="badge badge-muted">Zero Boilerplate</span>
        </div>
        <p>
            Start building your domain logic immediately in <code>admin/dashboard.php</code> or add your public
            pages right here. All security services (<a href="includes/auth.php"><code>auth.php</code></a>,
            <a href="includes/db.php"><code>db.php</code></a>, <a href="includes/functions.php"><code>functions.php</code></a>)
            are pre-configured and ready to use.
        </p>
    </section>
</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &mdash; Free & Open Starter Architecture &bull; Designed for Security & Performance</p>
</footer>

<script src="js/script.js"></script>
</body>
</html>
