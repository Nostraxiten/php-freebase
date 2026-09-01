<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
start_secure_session();
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
    <h1><?= e(APP_NAME) ?></h1>
    <nav>
        <a href="admin/login.php">Admin panel</a>
    </nav>
</header>

<main class="container">
    <section class="card">
        <h2>Welcome</h2>
        <p>
            This is your starting point. Replace this page with your own project.
            The base already includes a working admin panel, a secure PDO database
            connection, CSRF protection and an empty schema ready to extend.
        </p>
    </section>

    <section class="card">
        <h2>What's inside</h2>
        <ul>
            <li>PDO with real prepared statements (no SQL injection by design)</li>
            <li>Password hashing with <code>password_hash()</code> / <code>password_verify()</code></li>
            <li>CSRF tokens on every form</li>
            <li>Output escaping helper <code>e()</code> against XSS</li>
            <li>Hardened session cookies (HttpOnly, SameSite, secure when on HTTPS)</li>
            <li>Basic login throttling against brute force</li>
            <li>.htaccess rules blocking direct access to includes/ and db/</li>
        </ul>
    </section>
</main>

<footer class="site-footer">
    <p><?= e(APP_NAME) ?> &mdash; edit me in index.php</p>
</footer>

<script src="js/script.js"></script>
</body>
</html>
