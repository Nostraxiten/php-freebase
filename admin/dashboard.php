<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
start_secure_session();
require_login();
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
    <h1>Dashboard</h1>
    <nav>
        <span>Signed in as <strong><?= e($_SESSION['username']) ?></strong></span>
        <a href="logout.php">Log out</a>
    </nav>
</header>

<main class="container">
    <section class="card">
        <h2>You're in</h2>
        <p>
            This is your protected area. Anything you add here is only reachable
            by a logged-in user, checked through <code>require_login()</code>.
        </p>
        <p>Build your admin tools here: user management, content editing, whatever your project needs.</p>
    </section>
</main>

</body>
</html>
