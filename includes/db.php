<?php
/**
 * db.php
 * -------
 * Single PDO connection point with real prepared statements and secure exception handling.
 * Direct access to this file is blocked by PHP guard and .htaccess.
 */

declare(strict_types=1);

if (!defined('APP_SECURE')) {
    http_response_code(403);
    die('Direct access not permitted.');
}

require_once __DIR__ . '/config.php';

function get_pdo(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            DB_HOST,
            DB_PORT,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // Real prepared statements (No SQLi by design)
            PDO::ATTR_TIMEOUT            => 5,
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Always log the internal technical error safely on the server log
            error_log(sprintf('[DB Connection Error] %s in %s:%d', $e->getMessage(), $e->getFile(), $e->getLine()));

            http_response_code(500);

            // Never leak raw credentials or system paths to the browser (OWASP A05 / CWE-209)
            if (APP_DEBUG) {
                die('Database connection failed. Check your database credentials and server status in .env. (Details logged in server error log)');
            }

            die('Service temporarily unavailable. Please try again later.');
        }
    }

    return $pdo;
}

/**
 * Check if the database connection is currently alive without halting execution.
 */
function is_database_connected(): bool
{
    try {
        $pdo = get_pdo();
        return $pdo->query('SELECT 1')->fetchColumn() !== false;
    } catch (Throwable) {
        return false;
    }
}
