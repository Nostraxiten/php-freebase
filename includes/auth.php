<?php
/**
 * auth.php
 * ---------
 * Robust session management, persistent rate-limiting (database-backed against brute force),
 * role-based authorization, and secure authentication flow.
 * Direct access to this file is blocked by PHP guard and .htaccess.
 */

declare(strict_types=1);

if (!defined('APP_SECURE')) {
    http_response_code(403);
    die('Direct access not permitted.');
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

/**
 * Bootstrap an enterprise-grade hardened PHP session.
 * Implements strict mode, secure cookie parameters, idle timeout, and absolute expiration.
 */
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    // Harden PHP session core directives before session_start()
    ini_set('session.use_strict_mode', '1');  // Prevents session fixation (CWE-384)
    ini_set('session.use_only_cookies', '1'); // Disallow session IDs in URLs
    ini_set('session.use_trans_sid', '0');    // Disable transparent session ID passing

    session_name(SESSION_NAME);

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               ((int)($_SERVER['SERVER_PORT'] ?? 80) === 443);

    session_set_cookie_params([
        'lifetime' => 0,          // Cookie expires when the browser closes
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,   // Secure flag only sent over HTTPS
        'httponly' => true,       // Mitigate XSS session theft
        'samesite' => 'Lax',      // Mitigate CSRF
    ]);

    session_start();

    $now = time();

    // 1. Idle Timeout (User inactive for more than SESSION_LIFETIME)
    if (isset($_SESSION['last_activity']) && ($now - (int)$_SESSION['last_activity'] > SESSION_LIFETIME)) {
        session_unset();
        session_destroy();
        session_start();
        session_regenerate_id(true);
    }

    // 2. Absolute Lifetime (Session older than SESSION_MAX_LIFETIME, e.g. 8 hours)
    if (isset($_SESSION['created_at']) && ($now - (int)$_SESSION['created_at'] > SESSION_MAX_LIFETIME)) {
        session_unset();
        session_destroy();
        session_start();
        session_regenerate_id(true);
    }

    if (empty($_SESSION['created_at'])) {
        $_SESSION['created_at'] = $now;
    }

    $_SESSION['last_activity'] = $now;
}

/**
 * Check if the user is currently authenticated.
 */
function is_logged_in(): bool
{
    return !empty($_SESSION['user_id']);
}

/**
 * Check if the authenticated user has administrative privileges.
 */
function is_admin(): bool
{
    return is_logged_in() && (($_SESSION['role'] ?? '') === 'admin');
}

/**
 * Require an authenticated session; redirect to login if not logged in.
 */
function require_login(): void
{
    if (!is_logged_in()) {
        redirect('login.php');
    }
}

/**
 * Require administrative role; redirect with 403 or to dashboard if insufficient.
 */
function require_admin(): void
{
    require_login();
    if (!is_admin()) {
        http_response_code(403);
        die('Forbidden: Administrator privileges required.');
    }
}

/**
 * Database-backed brute force rate-limiting.
 * Checks whether the client IP or target username exceeds failed attempt thresholds.
 * Overcomes session-drop attacks (OWASP A07 / CWE-307).
 */
function is_rate_limited(string $username, string $ip): bool
{
    try {
        $pdo = get_pdo();
        $cutoff = date('Y-m-d H:i:s', time() - LOGIN_LOCKOUT_SECONDS);

        // Count recent failed attempts for either this IP or this specific username
        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM login_attempts
             WHERE (ip_address = ? OR username = ?) AND attempted_at >= ?'
        );
        $stmt->execute([$ip, $username, $cutoff]);
        $attempts = (int) $stmt->fetchColumn();

        return $attempts >= LOGIN_MAX_ATTEMPTS;
    } catch (Throwable $e) {
        // Fail-safe fallback to session throttling if DB is unreachable
        error_log('[RateLimit Check Error] ' . $e->getMessage());
        $data = $_SESSION['login_throttle'] ?? null;
        if ($data && ($data['count'] >= LOGIN_MAX_ATTEMPTS) && (time() - $data['first_attempt'] < LOGIN_LOCKOUT_SECONDS)) {
            return true;
        }
        return false;
    }
}

/**
 * Record a failed authentication attempt in the database.
 */
function record_failed_attempt(string $username, string $ip): void
{
    // Dual-layer: Record in session
    if (empty($_SESSION['login_throttle'])) {
        $_SESSION['login_throttle'] = ['count' => 1, 'first_attempt' => time()];
    } else {
        $_SESSION['login_throttle']['count']++;
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, username, attempted_at) VALUES (?, ?, NOW())');
        $stmt->execute([$ip, $username]);

        // Probabilistic cleanup of records older than 24 hours (1 in 20 requests)
        if (random_int(1, 20) === 1) {
            $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < (NOW() - INTERVAL 1 DAY)");
        }
    } catch (Throwable $e) {
        error_log('[Record Failed Attempt Error] ' . $e->getMessage());
    }
}

/**
 * Clear failed attempts for a specific IP and username upon successful login.
 */
function clear_failed_attempts(string $username, string $ip): void
{
    unset($_SESSION['login_throttle']);

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('DELETE FROM login_attempts WHERE ip_address = ? OR username = ?');
        $stmt->execute([$ip, $username]);
    } catch (Throwable $e) {
        error_log('[Clear Attempts Error] ' . $e->getMessage());
    }
}

/**
 * Attempt authentication with password verification, automatic rehash, and session protection.
 * Returns an array with ['success' => bool, 'error' => string].
 */
function attempt_login(string $username, string $password): array
{
    $ip = get_client_ip();

    if (is_rate_limited($username, $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many failed login attempts. Please wait 5 minutes before trying again.',
        ];
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('SELECT id, username, password, role, is_active FROM users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user) {
            // Check if user account is disabled
            if ((int) $user['is_active'] !== 1) {
                record_failed_attempt($username, $ip);
                return [
                    'success' => false,
                    'error'   => 'This account has been disabled. Please contact an administrator.',
                ];
            }

            if (password_verify($password, $user['password'])) {
                // Check if password hash needs to be updated to stronger algorithm/cost
                if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    $updateStmt = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');
                    $updateStmt->execute([$newHash, $user['id']]);
                }

                // Prevent session fixation on privilege elevation
                session_regenerate_id(true);

                // Rotate CSRF token on authentication change
                rotate_csrf_token();

                // Clear throttling records
                clear_failed_attempts($username, $ip);

                $_SESSION['user_id']       = (int) $user['id'];
                $_SESSION['username']      = (string) $user['username'];
                $_SESSION['role']          = (string) ($user['role'] ?? 'user');
                $_SESSION['auth_time']     = time();
                $_SESSION['created_at']    = time();
                $_SESSION['last_activity'] = time();

                return ['success' => true, 'error' => ''];
            }
        }
    } catch (Throwable $e) {
        error_log('[Authentication Exception] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Authentication service temporarily unavailable.',
        ];
    }

    record_failed_attempt($username, $ip);

    return [
        'success' => false,
        'error'   => 'Invalid username or password.',
    ];
}

/**
 * Completely invalidate and destroy the current session, clearing cookies and tokens.
 */
function logout(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 86400,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
}
