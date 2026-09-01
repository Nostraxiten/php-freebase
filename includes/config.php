<?php
/**
 * config.php
 * -----------
 * Central configuration file. Edit these values to match your environment.
 * This file is blocked from direct web access via .htaccess (see root .htaccess).
 */

declare(strict_types=1);

// --- Database settings ---
define('DB_HOST', 'localhost');
define('DB_NAME', 'freebase');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// --- App settings ---
define('APP_NAME', 'PHP FreeBase');
define('APP_ENV', 'development'); // 'development' or 'production'
define('APP_DEBUG', APP_ENV === 'development');

// --- Session / security settings ---
define('SESSION_NAME', 'freebase_session');
define('SESSION_LIFETIME', 3600); // seconds (1 hour)
define('LOGIN_MAX_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_SECONDS', 300); // 5 minutes

// --- Error reporting ---
if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}

// Timezone (adjust as needed)
date_default_timezone_set('Europe/Madrid');
