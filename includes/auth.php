<?php
/**
 * auth.php
 * ---------
 * Robust session management, persistent rate-limiting (database-backed),
 * user registration with email verification, role authorization, and secure authentication.
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
 */
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');  // Prevents session fixation (CWE-384)
    ini_set('session.use_only_cookies', '1'); // Disallow session IDs in URLs
    ini_set('session.use_trans_sid', '0');    // Disable transparent session ID passing

    session_name(SESSION_NAME);

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               ((int)($_SERVER['SERVER_PORT'] ?? 80) === 443);

    session_set_cookie_params([
        'lifetime' => 0,          // Cookie expires on browser close
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,   // Secure flag only sent over HTTPS
        'httponly' => true,       // Mitigate XSS session theft
        'samesite' => 'Lax',      // Mitigate CSRF
    ]);

    session_start();

    $now = time();

    // 1. Idle Timeout
    if (isset($_SESSION['last_activity']) && ($now - (int)$_SESSION['last_activity'] > SESSION_LIFETIME)) {
        session_unset();
        session_destroy();
        session_start();
        session_regenerate_id(true);
    }

    // 2. Absolute Lifetime
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
 * Check if the authenticated user is the administrator.
 * Only the designated "admin" user has administrative privileges.
 */
function is_admin(): bool
{
    return is_logged_in() &&
           (($_SESSION['role'] ?? '') === 'admin') &&
           (($_SESSION['username'] ?? '') === 'admin');
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
 * Require administrative privileges; reject with 403 if insufficient.
 */
function require_admin(): void
{
    require_login();
    if (!is_admin()) {
        http_response_code(403);
        die('Access Denied: Administrator privileges required.');
    }
}

/**
 * Database-backed brute force rate-limiting.
 */
function is_rate_limited(string $identifier, string $ip): bool
{
    try {
        $pdo = get_pdo();
        $cutoff = date('Y-m-d H:i:s', time() - LOGIN_LOCKOUT_SECONDS);

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM login_attempts
             WHERE (ip_address = ? OR username = ?) AND attempted_at >= ?'
        );
        $stmt->execute([$ip, $identifier, $cutoff]);
        $attempts = (int) $stmt->fetchColumn();

        return $attempts >= LOGIN_MAX_ATTEMPTS;
    } catch (Throwable $e) {
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
function record_failed_attempt(string $identifier, string $ip): void
{
    if (empty($_SESSION['login_throttle'])) {
        $_SESSION['login_throttle'] = ['count' => 1, 'first_attempt' => time()];
    } else {
        $_SESSION['login_throttle']['count']++;
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, username, attempted_at) VALUES (?, ?, NOW())');
        $stmt->execute([$ip, $identifier]);

        if (random_int(1, 20) === 1) {
            $pdo->exec("DELETE FROM login_attempts WHERE attempted_at < (NOW() - INTERVAL 1 DAY)");
        }
    } catch (Throwable $e) {
        error_log('[Record Failed Attempt Error] ' . $e->getMessage());
    }
}

/**
 * Clear failed attempts for a specific IP and identifier.
 */
function clear_failed_attempts(string $identifier, string $ip): void
{
    unset($_SESSION['login_throttle']);

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('DELETE FROM login_attempts WHERE ip_address = ? OR username = ?');
        $stmt->execute([$ip, $identifier]);
    } catch (Throwable $e) {
        error_log('[Clear Attempts Error] ' . $e->getMessage());
    }
}

/**
 * Register a new user account with email verification token.
 * All new registrations are strictly assigned the 'user' role.
 */
function register_user(string $username, string $email, string $password): array
{
    $ip = get_client_ip();

    if (is_rate_limited($ip, $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many registration requests. Please wait a few minutes.',
        ];
    }

    if (!validate_username($username)) {
        return [
            'success' => false,
            'error'   => 'Username must be between 4 and 12 alphanumeric characters.',
        ];
    }

    if (!is_valid_email($email)) {
        return [
            'success' => false,
            'error'   => 'Please provide a valid email address.',
        ];
    }

    if (!validate_password_length($password)) {
        return [
            'success' => false,
            'error'   => 'Password must be between 8 and 128 characters.',
        ];
    }

    try {
        $pdo = get_pdo();

        // Check if username or email is already registered
        $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1');
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            return [
                'success' => false,
                'error'   => 'Username or email address is already in use.',
            ];
        }

        // Generate strong password hash
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // Generate cryptographic email verification token
        $verificationToken = bin2hex(random_bytes(32));

        // Insert user with role 'user' and pending verification
        $insertStmt = $pdo->prepare(
            'INSERT INTO users (username, email, password, role, is_active, email_verified_at, verification_token)
             VALUES (?, ?, ?, "user", 1, NULL, ?)'
        );
        $insertStmt->execute([$username, $email, $passwordHash, $verificationToken]);

        return [
            'success' => true,
            'token'   => $verificationToken,
            'error'   => '',
        ];
    } catch (Throwable $e) {
        error_log('[Registration Error] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Account creation temporarily unavailable. Please try again later.',
        ];
    }
}

/**
 * Verify a user account using an email verification token.
 */
function verify_email_token(string $token): array
{
    if (strlen($token) !== 64 || !ctype_xdigit($token)) {
        return [
            'success' => false,
            'error'   => 'Invalid verification token format.',
        ];
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare(
            'SELECT id, username FROM users
             WHERE verification_token = ? AND email_verified_at IS NULL
             LIMIT 1'
        );
        $stmt->execute([$token]);
        $user = $stmt->fetch();

        if (!$user) {
            return [
                'success' => false,
                'error'   => 'Verification link is invalid or has already been used.',
            ];
        }

        // Activate and clear verification token
        $updateStmt = $pdo->prepare(
            'UPDATE users SET email_verified_at = NOW(), verification_token = NULL WHERE id = ?'
        );
        $updateStmt->execute([$user['id']]);

        return [
            'success'  => true,
            'username' => (string) $user['username'],
            'error'    => '',
        ];
    } catch (Throwable $e) {
        error_log('[Email Verification Error] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Verification service error. Please try again later.',
        ];
    }
}

/**
 * Attempt authentication with password verification, rehash, and email verification check.
 */
function attempt_login(string $identifier, string $password): array
{
    $ip = get_client_ip();

    if (is_rate_limited($identifier, $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many failed attempts. Please wait 5 minutes before trying again.',
        ];
    }

    try {
        $pdo = get_pdo();
        // Support logging in via username or email
        $stmt = $pdo->prepare(
            'SELECT id, username, email, password, role, is_active, email_verified_at
             FROM users WHERE username = ? OR email = ? LIMIT 1'
        );
        $stmt->execute([$identifier, $identifier]);
        $user = $stmt->fetch();

        if ($user) {
            // Account active check
            if ((int) $user['is_active'] !== 1) {
                record_failed_attempt($identifier, $ip);
                return [
                    'success' => false,
                    'error'   => 'This account has been deactivated.',
                ];
            }

            // Email verification check
            if ($user['email_verified_at'] === null) {
                record_failed_attempt($identifier, $ip);
                return [
                    'success' => false,
                    'error'   => 'Email verification required. Please check your inbox or activation link.',
                ];
            }

            if (password_verify($password, $user['password'])) {
                // Automatic hash upgrade when algorithm/cost evolves
                if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    $updateStmt = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');
                    $updateStmt->execute([$newHash, $user['id']]);
                }

                session_regenerate_id(true);
                rotate_csrf_token();
                clear_failed_attempts($identifier, $ip);

                // Enforce strictly: only 'admin' username receives admin role
                $assignedRole = ($user['username'] === 'admin' && $user['role'] === 'admin') ? 'admin' : 'user';

                $_SESSION['user_id']       = (int) $user['id'];
                $_SESSION['username']      = (string) $user['username'];
                $_SESSION['email']         = (string) $user['email'];
                $_SESSION['role']          = $assignedRole;
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

    record_failed_attempt($identifier, $ip);

    return [
        'success' => false,
        'error'   => 'Invalid credentials. Please verify your username/email and password.',
    ];
}

/**
 * Invalidate and destroy session.
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
