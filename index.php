<?php
/**
 * index.php
 * ---------
 * Public portal landing page.
 * Minimalist "Nothing here yet" placeholder with neon dark aesthetics.
 * Zero security architecture disclosures or internal telemetry.
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
    <title><?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<header class="site-header">
    <div class="header-brand">
        <a href="index.php" class="brand-link">
            <span class="neon-dot"></span>
            <span class="brand-title"><?= e(APP_NAME) ?></span>
        </a>
    </div>
    <nav class="header-nav">
        <?php if ($loggedIn): ?>
            <span class="badge badge-neon">Signed in as <?= e((string)$currentUser) ?></span>
            <a href="admin/dashboard.php" class="btn btn-sm btn-primary">Dashboard &rarr;</a>
        <?php else: ?>
            <a href="register.php" class="btn btn-sm btn-secondary">Create Account</a>
            <a href="admin/login.php" class="btn btn-sm btn-primary">Sign In &rarr;</a>
        <?php endif; ?>
    </nav>
</header>

<main class="container">
    <div class="hero-section">
        <div class="neon-pill">PORTAL STANDBY</div>
        <h1 class="hero-title">Nothing here yet.</h1>
        <p class="hero-desc">
            This sector is currently undergoing scheduled development.
            Public applications and tools will become available here soon.
        </p>

        <div class="hero-actions">
            <?php if ($loggedIn): ?>
                <a href="admin/dashboard.php" class="btn btn-primary">Go to Dashboard &rarr;</a>
            <?php else: ?>
                <a href="register.php" class="btn btn-primary">Create an Account &rarr;</a>
                <a href="admin/login.php" class="btn btn-secondary">Member Sign In</a>
            <?php endif; ?>
        </div>
    </div>

    <div class="status-box">
        <div class="status-grid-inner">
            <div class="status-col">
                <span class="status-label">Network Status</span>
                <span class="status-text text-neon">Operational</span>
            </div>
            <div class="status-col">
                <span class="status-label">Gateway</span>
                <span class="status-text">Standby</span>
            </div>
            <div class="status-col">
                <span class="status-label">Access</span>
                <span class="status-text">Authorized Users Only</span>
            </div>
        </div>
    </div>
</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &bull; All systems operational.</p>
</footer>

<script src="js/script.js"></script>
</body>
</html>
