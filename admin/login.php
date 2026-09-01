<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
start_secure_session();

if (is_logged_in()) {
    redirect('dashboard.php');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Invalid or expired form submission. Please try again.';
    } elseif (too_many_attempts()) {
        $error = 'Too many failed attempts. Please wait a few minutes before trying again.';
    } else {
        $username = sanitize_input($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $error = 'Please fill in both fields.';
        } elseif (attempt_login($username, $password)) {
            redirect('dashboard.php');
        } else {
            $error = 'Invalid username or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login &mdash; <?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="../css/style.css">
</head>
<body>

<main class="container center">
    <section class="card login-card">
        <h1>Admin Login</h1>

        <?php if ($error !== ''): ?>
            <p class="alert"><?= e($error) ?></p>
        <?php endif; ?>

        <form method="post" action="login.php" novalidate>
            <?= csrf_field() ?>

            <label for="username">Username</label>
            <input type="text" id="username" name="username" autocomplete="username" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" autocomplete="current-password" required>

            <button type="submit">Log in</button>
        </form>

        <p class="hint">Default credentials: <code>admin</code> / <code>admin</code> &mdash; change this immediately after import.</p>
        <p><a href="../index.php">&larr; Back to site</a></p>
    </section>
</main>

</body>
</html>
