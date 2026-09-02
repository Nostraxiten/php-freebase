<?php
/**
 * config.php
 * -----------
 * Central configuration file for PHP FreeBase.
 * Production-Secure by Default: strictly enforces secure defaults, disables debug
 * output in production, and prevents information disclosure.
 * Direct access to this file is blocked by PHP guard and .htaccess.
 */

declare(strict_types=1);

if (!defined('APP_SECURE')) {
    http_response_code(403);
    die('Direct access not permitted.');
}

/**
 * Lightweight .env file parser (zero third-party dependencies).
 * Safely loads environment variables into $_ENV, $_SERVER, and putenv().
 */
(function (): void {
    $envFile = dirname(__DIR__) . '/.env';
    if (!is_readable($envFile)) {
        return;
    }

    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        $pos = strpos($line, '=');
        if ($pos === false) {
            continue;
        }

        $name  = trim(substr($line, 0, $pos));
        $value = trim(substr($line, $pos + 1));

        if (strlen($value) >= 2 && (
            (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
            (str_starts_with($value, "'") && str_ends_with($value, "'"))
        )) {
            $value = substr($value, 1, -1);
        }

        if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
            putenv("{$name}={$value}");
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
})();

// Helper to read env variables with fallback
function env_get(string $key, mixed $default = null): mixed
{
    $val = getenv($key);
    if ($val === false) {
        return $_ENV[$key] ?? $_SERVER[$key] ?? $default;
    }
    return $val;
}

// --- Environment & App Identity ---
// Secure default: if APP_ENV is unspecified or unrecognized, strictly enforce 'production'
$rawEnv = strtolower(trim((string) env_get('APP_ENV', 'production')));
define('APP_ENV', $rawEnv === 'development' ? 'development' : 'production');

// In production, APP_DEBUG is unconditionally FALSE regardless of any environment flag.
$rawDebug = (bool) env_get('APP_DEBUG', false);
define('APP_DEBUG', (APP_ENV === 'development') && $rawDebug);

define('APP_NAME', (string) env_get('APP_NAME', 'PHP FreeBase'));
define('APP_URL', (string) env_get('APP_URL', 'http://localhost:8000'));

// --- Production Environment Sanity Verification ---
if (APP_ENV === 'production') {
    $criticalMissing = [];
    if (env_get('DB_NAME') === null || env_get('DB_NAME') === '') {
        $criticalMissing[] = 'DB_NAME';
    }
    if (env_get('DB_USER') === null || env_get('DB_USER') === '') {
        $criticalMissing[] = 'DB_USER';
    }
    if (!empty($criticalMissing)) {
        error_log('[FATAL PRODUCTION CONFIG] Missing critical environment variables: ' . implode(', ', $criticalMissing));
        http_response_code(500);
        die('System configuration error. Service unavailable.');
    }
}

// --- Database Settings ---
define('DB_HOST', (string) env_get('DB_HOST', '127.0.0.1'));
define('DB_PORT', (int) env_get('DB_PORT', 3306));
define('DB_NAME', (string) env_get('DB_NAME', 'freebase'));
define('DB_USER', (string) env_get('DB_USER', 'root'));
define('DB_PASS', (string) env_get('DB_PASS', ''));
define('DB_CHARSET', (string) env_get('DB_CHARSET', 'utf8mb4'));

// --- Session & Security Settings ---
define('SESSION_NAME', (string) env_get('SESSION_NAME', 'freebase_sec_session'));
define('SESSION_LIFETIME', (int) env_get('SESSION_LIFETIME', 3600));          // Idle timeout (seconds)
define('SESSION_MAX_LIFETIME', (int) env_get('SESSION_MAX_LIFETIME', 28800)); // Absolute lifetime (8 hours)
define('LOGIN_MAX_ATTEMPTS', (int) env_get('LOGIN_MAX_ATTEMPTS', 5));
define('LOGIN_LOCKOUT_SECONDS', (int) env_get('LOGIN_LOCKOUT_SECONDS', 300)); // 5 minutes
define('RESET_TOKEN_LIFETIME', (int) env_get('RESET_TOKEN_LIFETIME', 3600));   // 1 hour
define('VERIFY_TOKEN_LIFETIME', (int) env_get('VERIFY_TOKEN_LIFETIME', 86400)); // 24 hours

// Emergency secret: strictly from environment, no default, never hardcoded
define('ADMIN_RECOVERY_SECRET', (string) env_get('ADMIN_RECOVERY_SECRET', ''));

// --- Error Reporting & Information Disclosure Defense ---
if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    // In production: zero error display, zero stack traces, log errors to server log only
    error_reporting(0);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

// --- Timezone ---
$tz = (string) env_get('APP_TIMEZONE', 'Europe/Madrid');
date_default_timezone_set(in_array($tz, timezone_identifiers_list(), true) ? $tz : 'UTC');
