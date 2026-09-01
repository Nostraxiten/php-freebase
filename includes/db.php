<?php
/**
 * db.php
 * -------
 * Single PDO connection point. Using PDO + prepared statements everywhere
 * is the #1 defense against SQL injection (OWASP SQL Injection Prevention
 * Cheat Sheet, Defense Option 1).
 *
 * Never build queries with string concatenation. Always use
 * $stmt = $pdo->prepare(...); $stmt->execute([...]);
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function get_pdo(): PDO
{
    static $pdo = null;

    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // fail loud, never silently
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // use REAL prepared statements, not emulated ones
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Never leak DB credentials or raw exception details to the browser.
            if (APP_DEBUG) {
                die('DB connection failed: ' . $e->getMessage());
            }
            http_response_code(500);
            die('Service temporarily unavailable.');
        }
    }

    return $pdo;
}
