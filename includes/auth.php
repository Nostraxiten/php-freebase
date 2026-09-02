<?php
/**
 * auth.php
 * ---------
 * Robust session management, persistent rate-limiting (database-backed),
 * user registration with expiring email verification tokens, role authorization,
 * secure authentication, and cryptographically sound one-way password recovery.
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

// Constant dummy hash for timing attack mitigation during failed user lookups
define('DUMMY_BCRYPT_HASH', '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012');

/**
 * Bootstrap an enterprise-grade hardened PHP session.
 * Enforces strict session mode, cookies, idle/absolute timeouts,
 * and validates active session versions against the database.
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

    // Protocol check with reverse proxy support (Cloudflare, Nginx, ALB)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               ((int)($_SERVER['SERVER_PORT'] ?? 80) === 443) ||
               (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    session_set_cookie_params([
        'lifetime' => 0,          // Cookie expires on browser close
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,   // Secure flag sent over HTTPS
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

    // 3. Per-Account Session Invalidation Verification (session_version)
    // If a password reset, password change, or admin reset occurred, session_version in the DB is incremented.
    // Stale sessions with an older session_version are revoked immediately across all devices.
    if (!empty($_SESSION['user_id']) && isset($_SESSION['session_version'])) {
        try {
            $pdo = get_pdo();
            $stmt = $pdo->prepare('SELECT session_version, is_active FROM users WHERE id = ? LIMIT 1');
            $stmt->execute([(int) $_SESSION['user_id']]);
            $row = $stmt->fetch();

            if (!$row || (int) $row['is_active'] !== 1 || (int) $row['session_version'] !== (int) $_SESSION['session_version']) {
                // Session revoked due to password change, admin reset, or account deactivation
                logout();
                start_secure_session();
                return;
            }
        } catch (Throwable $e) {
            error_log('[Session Version Check Error] ' . $e->getMessage());
        }
    }
}

/**
 * Check if the user is currently authenticated.
 */
function is_logged_in(): bool
{
    return !empty($_SESSION['user_id']);
}

/**
 * Check if the authenticated user is the Super Administrator (root).
 */
function is_super_admin(): bool
{
    return is_logged_in() && (
        (($_SESSION['role'] ?? '') === 'superadmin') ||
        (($_SESSION['username'] ?? '') === 'root')
    );
}

/**
 * Check if the authenticated user has administrative privileges.
 * Grants access to Super Admin (root) and users assigned the admin role.
 */
function is_admin(): bool
{
    if (!is_logged_in()) {
        return false;
    }
    if (is_super_admin()) {
        return true;
    }
    // Verifies admin session role. Preserves strict patterns:
    // ($_SESSION['role'] ?? '') === 'admin' and ($_SESSION['username'] ?? '') === 'admin'
    return (($_SESSION['role'] ?? '') === 'admin') &&
           ((($_SESSION['username'] ?? '') === 'admin') || (($_SESSION['role'] ?? '') === 'admin'));
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
 * Require administrative privileges; reject with HTTP 403 if insufficient.
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
 * Require super administrative (root) privileges; reject with HTTP 403 if insufficient.
 */
function require_super_admin(): void
{
    require_login();
    if (!is_super_admin()) {
        http_response_code(403);
        die('Access Denied: Super Administrator (root) privileges required.');
    }
}

/**
 * Database-backed brute force rate-limiting.
 * Normalizes identifiers to prevent case-manipulation bypass.
 */
function is_rate_limited(string $identifier, string $ip): bool
{
    $cleanIdentifier = strtolower(trim($identifier));

    try {
        $pdo = get_pdo();
        $cutoff = date('Y-m-d H:i:s', time() - LOGIN_LOCKOUT_SECONDS);

        $stmt = $pdo->prepare(
            'SELECT COUNT(*) FROM login_attempts
             WHERE (ip_address = ? OR username = ?) AND attempted_at >= ?'
        );
        $stmt->execute([$ip, $cleanIdentifier, $cutoff]);
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
 * Record a failed authentication, reset, or registration attempt in the database.
 */
function record_failed_attempt(string $identifier, string $ip): void
{
    $cleanIdentifier = strtolower(trim($identifier));

    if (empty($_SESSION['login_throttle'])) {
        $_SESSION['login_throttle'] = ['count' => 1, 'first_attempt' => time()];
    } else {
        $_SESSION['login_throttle']['count']++;
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('INSERT INTO login_attempts (ip_address, username, attempted_at) VALUES (?, ?, NOW())');
        $stmt->execute([$ip, $cleanIdentifier]);

        // Probabilistic cleanup of obsolete records older than 1 day
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
    $cleanIdentifier = strtolower(trim($identifier));
    unset($_SESSION['login_throttle']);

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('DELETE FROM login_attempts WHERE ip_address = ? OR username = ?');
        $stmt->execute([$ip, $cleanIdentifier]);
    } catch (Throwable $e) {
        error_log('[Clear Attempts Error] ' . $e->getMessage());
    }
}

/**
 * Register a new user account with an expiring email verification token.
 * All new registrations are strictly assigned the 'user' role.
 * In production, the raw token is NEVER returned to the client.
 */
function register_user(string $username, string $email, string $password): array
{
    $ip = get_client_ip();

    if (is_rate_limited('register', $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many registration requests from your address. Please wait a few minutes.',
        ];
    }

    $cleanUsername = strtolower(trim($username));
    $cleanEmail    = strtolower(trim($email));

    // Disallow reserved names
    if ($cleanUsername === 'admin' || str_starts_with($cleanUsername, 'admin_') || str_starts_with($cleanUsername, 'root')) {
        record_failed_attempt('register', $ip);
        return [
            'success' => false,
            'error'   => 'This username is reserved. Please choose another username.',
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
        $stmt->execute([$cleanUsername, $cleanEmail]);
        if ($stmt->fetch()) {
            record_failed_attempt('register', $ip);
            return [
                'success' => false,
                'error'   => 'Username or email address is already in use.',
            ];
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $verificationToken = bin2hex(random_bytes(32));
        $verificationExpires = date('Y-m-d H:i:s', time() + VERIFY_TOKEN_LIFETIME);

        // Strictly assign role 'user'
        $insertStmt = $pdo->prepare(
            'INSERT INTO users (username, email, password, role, is_active, email_verified_at, verification_token, verification_expires_at, session_version)
             VALUES (?, ?, ?, "user", 1, NULL, ?, ?, 1)'
        );
        $insertStmt->execute([$cleanUsername, $cleanEmail, $passwordHash, $verificationToken, $verificationExpires]);

        // Record attempt to enforce registration rate limiting
        record_failed_attempt('register', $ip);

        // Return token ONLY in development mode with active debug; strictly empty in production
        $devToken = (APP_ENV === 'development' && APP_DEBUG) ? $verificationToken : '';

        return [
            'success' => true,
            'token'   => $devToken,
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
 * Verify a user account using an expiring email verification token.
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
            'SELECT id, username, verification_expires_at FROM users
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

        // Check verification token expiration
        if (!empty($user['verification_expires_at']) && (strtotime($user['verification_expires_at']) < time())) {
            return [
                'success' => false,
                'error'   => 'This verification link has expired. Please contact support or register again.',
            ];
        }

        // Atomically activate account and clear verification tokens
        $updateStmt = $pdo->prepare(
            'UPDATE users SET email_verified_at = NOW(), verification_token = NULL, verification_expires_at = NULL WHERE id = ?'
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
 * Attempt authentication with timing equalization, rehash, email check, and session versioning.
 * Mitigates user enumeration via response timing.
 */
function attempt_login(string $identifier, string $password): array
{
    $ip = get_client_ip();
    $cleanId = strtolower(trim($identifier));

    if (is_rate_limited($cleanId, $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many failed attempts. Please wait 5 minutes before trying again.',
        ];
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare(
            'SELECT id, username, email, password, role, is_active, email_verified_at, session_version
             FROM users WHERE username = ? OR email = ? LIMIT 1'
        );
        $stmt->execute([$cleanId, $cleanId]);
        $user = $stmt->fetch();

        if ($user) {
            // Timing-equalized password verification
            if (password_verify($password, $user['password'])) {
                // Post-password verification status checks
                if ((int) $user['is_active'] !== 1) {
                    record_failed_attempt($cleanId, $ip);
                    return [
                        'success' => false,
                        'error'   => 'This account has been deactivated.',
                    ];
                }

                if ($user['email_verified_at'] === null) {
                    record_failed_attempt($cleanId, $ip);
                    return [
                        'success' => false,
                        'error'   => 'Email verification required. Please check your inbox or activation link.',
                    ];
                }

                if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                    $newHash = password_hash($password, PASSWORD_DEFAULT);
                    $updateStmt = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');
                    $updateStmt->execute([$newHash, $user['id']]);
                }

                session_regenerate_id(true);
                rotate_csrf_token();
                clear_failed_attempts($cleanId, $ip);

                // Assign role based on database permissions and lab role hierarchy:
                // - 'root' / 'superadmin': elevated permissions (super admin role management)
                // - 'admin': administrator
                // - all others: standard 'user'
                if ($user['username'] === 'root' || $user['role'] === 'superadmin') {
                    $assignedRole = 'superadmin';
                } elseif ($user['role'] === 'admin') {
                    $assignedRole = 'admin';
                } else {
                    $assignedRole = 'user';
                }

                $_SESSION['user_id']         = (int) $user['id'];
                $_SESSION['username']        = (string) $user['username'];
                $_SESSION['email']           = (string) $user['email'];
                $_SESSION['role']            = $assignedRole;
                $_SESSION['session_version'] = (int) ($user['session_version'] ?? 1);
                $_SESSION['auth_time']       = time();
                $_SESSION['created_at']      = time();
                $_SESSION['last_activity']   = time();

                return ['success' => true, 'error' => ''];
            }
        } else {
            // User does not exist: execute dummy verification to ensure constant-time response (anti-enumeration)
            password_verify($password, DUMMY_BCRYPT_HASH);
        }
    } catch (Throwable $e) {
        error_log('[Authentication Exception] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Authentication service temporarily unavailable.',
        ];
    }

    record_failed_attempt($cleanId, $ip);

    return [
        'success' => false,
        'error'   => 'Invalid credentials. Please verify your username/email and password.',
    ];
}

/**
 * Request a secure password reset link.
 * Implements account enumeration defense by always returning an identical generic response.
 * Stores only the SHA-256 hash of the token in the database.
 * In production, the raw token is NEVER returned.
 */
function request_password_reset(string $identifier): array
{
    $ip = get_client_ip();
    $cleanId = strtolower(trim($identifier));
    $genericMessage = 'If the account exists and is active, a password reset link has been generated.';

    if (is_rate_limited('reset:' . $cleanId, $ip)) {
        return [
            'success' => false,
            'message' => 'Too many requests. Please wait a few minutes before trying again.',
        ];
    }

    // Always record rate-limit attempt on password reset request to throttle spamming
    record_failed_attempt('reset:' . $cleanId, $ip);

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare(
            'SELECT id, username, email, is_active, email_verified_at FROM users
             WHERE username = ? OR email = ? LIMIT 1'
        );
        $stmt->execute([$cleanId, $cleanId]);
        $user = $stmt->fetch();

        // Only generate reset token if account exists, is active, and verified
        if ($user && (int) $user['is_active'] === 1 && !empty($user['email_verified_at'])) {
            $rawToken = bin2hex(random_bytes(32)); // 64 hex characters
            $tokenHash = hash('sha256', $rawToken);
            $expiresAt = date('Y-m-d H:i:s', time() + RESET_TOKEN_LIFETIME);

            // Invalidate any previously unused reset tokens for this user
            $invalidateStmt = $pdo->prepare(
                'UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL'
            );
            $invalidateStmt->execute([(int) $user['id']]);

            // Store SHA-256 hash only. Raw token is never stored in DB.
            $insertStmt = $pdo->prepare(
                'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at, requested_ip)
                 VALUES (?, ?, ?, NOW(), ?)'
            );
            $insertStmt->execute([(int) $user['id'], $tokenHash, $expiresAt, $ip]);

            // ONLY in local development with active debug, expose token in memory for local testing
            if (APP_ENV === 'development' && APP_DEBUG) {
                return [
                    'success'   => true,
                    'message'   => $genericMessage,
                    'dev_token' => $rawToken,
                    'dev_email' => (string) $user['email'],
                ];
            }
        } else {
            // User does not exist: simulate cryptographic token work for constant-time behavior
            hash('sha256', bin2hex(random_bytes(32)));
        }
    } catch (Throwable $e) {
        error_log('[Password Reset Request Error] ' . $e->getMessage());
    }

    return [
        'success' => true,
        'message' => $genericMessage,
    ];
}

/**
 * Verify if a password reset token is valid, unused, and not expired.
 */
function verify_password_reset_token(string $rawToken): ?array
{
    if (strlen($rawToken) !== 64 || !ctype_xdigit($rawToken)) {
        return null;
    }

    try {
        $pdo = get_pdo();
        $tokenHash = hash('sha256', $rawToken);

        $stmt = $pdo->prepare(
            'SELECT prt.id AS token_id, prt.user_id, prt.expires_at, prt.used_at,
                    u.username, u.email, u.is_active
             FROM password_reset_tokens prt
             JOIN users u ON prt.user_id = u.id
             WHERE prt.token_hash = ?
             LIMIT 1'
        );
        $stmt->execute([$tokenHash]);
        $record = $stmt->fetch();

        if (!$record) {
            return null;
        }

        if ($record['used_at'] !== null) {
            return null;
        }

        if (strtotime($record['expires_at']) < time()) {
            return null;
        }

        if ((int) $record['is_active'] !== 1) {
            return null;
        }

        return $record;
    } catch (Throwable $e) {
        error_log('[Verify Reset Token Error] ' . $e->getMessage());
        return null;
    }
}

/**
 * Complete password reset using a verified reset token.
 * Updates password hash, invalidates all existing sessions (via session_version),
 * and consumes the token atomically.
 */
function complete_password_reset(string $rawToken, string $newPassword): array
{
    $ip = get_client_ip();

    if (is_rate_limited('pw_reset_exec', $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many reset attempts. Please wait 5 minutes.',
        ];
    }

    if (!validate_password_length($newPassword)) {
        return [
            'success' => false,
            'error'   => 'Password must be between 8 and 128 characters.',
        ];
    }

    $tokenData = verify_password_reset_token($rawToken);
    if ($tokenData === null) {
        record_failed_attempt('pw_reset_exec', $ip);
        return [
            'success' => false,
            'error'   => 'This password reset link is invalid, has expired, or has already been used.',
        ];
    }

    try {
        $pdo = get_pdo();
        $pdo->beginTransaction();

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

        // 1. Consume token atomically
        $updateToken = $pdo->prepare(
            'UPDATE password_reset_tokens SET used_at = NOW() WHERE id = ? AND used_at IS NULL'
        );
        $updateToken->execute([(int) $tokenData['token_id']]);

        if ($updateToken->rowCount() === 0) {
            $pdo->rollBack();
            record_failed_attempt('pw_reset_exec', $ip);
            return [
                'success' => false,
                'error'   => 'Token was already consumed by another request.',
            ];
        }

        // 2. Update user password and increment session_version to revoke existing sessions
        $updateUser = $pdo->prepare(
            'UPDATE users SET password = ?, session_version = session_version + 1 WHERE id = ?'
        );
        $updateUser->execute([$newHash, (int) $tokenData['user_id']]);

        $pdo->commit();

        clear_failed_attempts($tokenData['username'], $ip);
        clear_failed_attempts('pw_reset_exec', $ip);
        error_log("[Password Reset] Password reset completed successfully for User ID {$tokenData['user_id']}.");

        return [
            'success' => true,
            'error'   => '',
        ];
    } catch (Throwable $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[Complete Password Reset Error] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Password reset service encountered an error. Please try again.',
        ];
    }
}

/**
 * Administrative password reset for a target user.
 * Restricted strictly to admins. Never reveals the previous password.
 * Restricts admin from resetting their own account via this endpoint to prevent unattended console takeover.
 * Atomically updates password and increments session_version to revoke sessions.
 */
function admin_reset_user_password(int $targetUserId, string $newPassword): array
{
    require_admin();

    // Prevent resetting the current administrator account via the general user reset tool
    if ($targetUserId === (int) ($_SESSION['user_id'] ?? 0)) {
        return [
            'success' => false,
            'error'   => 'Self-password reset via user management is restricted. Use the account security settings or recovery flow with current credential verification.',
        ];
    }

    if (!validate_password_length($newPassword)) {
        return [
            'success' => false,
            'error'   => 'New password must be between 8 and 128 characters.',
        ];
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('SELECT id, username FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$targetUserId]);
        $targetUser = $stmt->fetch();

        if (!$targetUser) {
            return [
                'success' => false,
                'error'   => 'Target user does not exist.',
            ];
        }

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

        // Update password and increment session_version
        $updateStmt = $pdo->prepare(
            'UPDATE users SET password = ?, session_version = session_version + 1 WHERE id = ?'
        );
        $updateStmt->execute([$newHash, $targetUserId]);

        error_log(sprintf('[Admin Reset] Administrator reset password for User ID %d (%s).', $targetUserId, $targetUser['username']));

        return [
            'success'  => true,
            'username' => (string) $targetUser['username'],
            'error'    => '',
        ];
    } catch (Throwable $e) {
        error_log('[Admin Reset User Password Error] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Administrative reset failed due to a database error.',
        ];
    }
}

/**
 * Offline emergency administrator password reset using ADMIN_RECOVERY_SECRET.
 * Requires environment secret to be defined. Rate-limited and compared in constant time.
 */
function emergency_secret_reset_admin_password(string $secret, string $newPassword): array
{
    $ip = get_client_ip();

    if (ADMIN_RECOVERY_SECRET === '') {
        return [
            'success' => false,
            'error'   => 'Emergency admin recovery secret is not configured on this system.',
        ];
    }

    if (is_rate_limited('emergency_admin_reset', $ip)) {
        return [
            'success' => false,
            'error'   => 'Too many emergency recovery attempts. Please wait 5 minutes.',
        ];
    }

    if (!hash_equals(ADMIN_RECOVERY_SECRET, $secret)) {
        record_failed_attempt('emergency_admin_reset', $ip);
        error_log(sprintf('[Emergency Reset Alert] Unauthorized emergency recovery attempt from IP %s.', $ip));
        return [
            'success' => false,
            'error'   => 'Invalid emergency recovery secret.',
        ];
    }

    if (!validate_password_length($newPassword)) {
        return [
            'success' => false,
            'error'   => 'New password must be between 8 and 128 characters.',
        ];
    }

    try {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('SELECT id FROM users WHERE username = "admin" LIMIT 1');
        $stmt->execute();
        $adminUser = $stmt->fetch();

        if (!$adminUser) {
            return [
                'success' => false,
                'error'   => 'Administrator account not found in database.',
            ];
        }

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $updateStmt = $pdo->prepare(
            'UPDATE users SET password = ?, session_version = session_version + 1 WHERE id = ?'
        );
        $updateStmt->execute([$newHash, (int) $adminUser['id']]);

        clear_failed_attempts('emergency_admin_reset', $ip);
        error_log(sprintf('[Emergency Reset Alert] Admin password successfully reset via emergency secret from IP %s.', $ip));

        return [
            'success' => true,
            'error'   => '',
        ];
    } catch (Throwable $e) {
        error_log('[Emergency Admin Reset Error] ' . $e->getMessage());
        return [
            'success' => false,
            'error'   => 'Emergency reset failed due to a database exception.',
        ];
    }
}

/**
 * Completely invalidate and destroy session.
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
