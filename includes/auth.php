<?php
/**
 * auth.php
 * ---------
 * Session bootstrap + login/logout logic + brute-force throttling.
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name(SESSION_NAME);

    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME,
        'path'     => '/',
        'domain'   => '',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), // only over HTTPS when available
        'httponly' => true,   // JS cannot read the cookie -> mitigates session theft via XSS
        'samesite' => 'Lax',  // mitigates CSRF via cross-site cookie sending
    ]);

    session_start();

    // Basic idle timeout
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_LIFETIME)) {
        session_unset();
        session_destroy();
        session_start();
    }
    $_SESSION['last_activity'] = time();
}

function is_logged_in(): bool
{
    return !empty($_SESSION['user_id']);
}

function require_login(): void
{
    if (!is_logged_in()) {
        redirect('login.php');
    }
}

/**
 * Basic per-session brute-force throttle. For real production use, throttle
 * by IP + username at the database/proxy level too (e.g. fail2ban, WAF).
 */
function too_many_attempts(): bool
{
    $data = $_SESSION['login_throttle'] ?? null;
    if (!$data) {
        return false;
    }
    if ($data['count'] >= LOGIN_MAX_ATTEMPTS && (time() - $data['first_attempt']) < LOGIN_LOCKOUT_SECONDS) {
        return true;
    }
    if ((time() - $data['first_attempt']) >= LOGIN_LOCKOUT_SECONDS) {
        unset($_SESSION['login_throttle']);
    }
    return false;
}

function register_failed_attempt(): void
{
    if (empty($_SESSION['login_throttle'])) {
        $_SESSION['login_throttle'] = ['count' => 1, 'first_attempt' => time()];
    } else {
        $_SESSION['login_throttle']['count']++;
    }
}

function clear_attempts(): void
{
    unset($_SESSION['login_throttle']);
}

/**
 * Attempt to log a user in. Always uses a prepared statement + password_verify,
 * never string-concatenated SQL and never plain-text password comparison.
 */
function attempt_login(string $username, string $password): bool
{
    $pdo = get_pdo();

    $stmt = $pdo->prepare('SELECT id, username, password FROM users WHERE username = ? LIMIT 1');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        // Prevent session fixation: issue a fresh session ID on privilege change.
        session_regenerate_id(true);
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        clear_attempts();
        return true;
    }

    register_failed_attempt();
    return false;
}

function logout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}
