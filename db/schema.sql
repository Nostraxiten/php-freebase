-- =============================================================================
-- PHP FreeBase - Database Schema
-- =============================================================================
-- Import this file to initialize or upgrade the database:
-- Example: mysql -u root -p < db/schema.sql
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `freebase`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `freebase`;

-- -----------------------------------------------------------------------------
-- Users Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id`                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username`                VARCHAR(12)               NOT NULL UNIQUE, -- Min 4, Max 12 characters
    `email`                   VARCHAR(100)              NOT NULL UNIQUE,
    `password`                VARCHAR(255)              NOT NULL, -- Secure hash (bcrypt/argon2)
    `role`                    ENUM('admin', 'user')     NOT NULL DEFAULT 'user',
    `is_active`               TINYINT(1) UNSIGNED       NOT NULL DEFAULT 1,
    `email_verified_at`       TIMESTAMP                 NULL DEFAULT NULL,
    `verification_token`      VARCHAR(64)               NULL DEFAULT NULL,
    `verification_expires_at` TIMESTAMP                 NULL DEFAULT NULL,
    `session_version`         INT UNSIGNED              NOT NULL DEFAULT 1, -- Incremented on password reset
    `created_at`              TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`              TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`),
    INDEX `idx_token` (`verification_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Password Reset Tokens Table
-- -----------------------------------------------------------------------------
-- Stores SHA-256 hashes of reset tokens. Raw tokens are never stored in the DB.
-- Single-use enforced via used_at timestamp and atomic verification.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `password_reset_tokens` (
    `id`           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `user_id`      INT UNSIGNED NOT NULL,
    `token_hash`   CHAR(64) NOT NULL, -- SHA-256 hash of the 64-character raw hex token
    `expires_at`   TIMESTAMP NOT NULL,
    `used_at`      TIMESTAMP NULL DEFAULT NULL,
    `created_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `requested_ip` VARCHAR(45) NOT NULL,
    INDEX `idx_token_hash` (`token_hash`),
    INDEX `idx_user_expires` (`user_id`, `expires_at`),
    CONSTRAINT `fk_reset_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Persistent Rate Limiting Table (Brute-force protection)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `id`           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `ip_address`   VARCHAR(45)      NOT NULL, -- Supports IPv4 and IPv6
    `username`     VARCHAR(50)      NOT NULL,
    `attempted_at` TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_ip_attempted` (`ip_address`, `attempted_at`),
    INDEX `idx_user_attempted` (`username`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Default Admin User
-- -----------------------------------------------------------------------------
-- Username: "admin"
-- Password: "admin123" (Hash: bcrypt, cost 10)
-- Email: "admin@freebase.local" (Pre-verified)
-- -----------------------------------------------------------------------------
INSERT INTO `users` (`username`, `email`, `password`, `role`, `is_active`, `email_verified_at`, `session_version`)
VALUES ('admin', 'admin@freebase.local', '$2b$10$MAfUOW/eKLp4LJu0A/phIOjsu/BUfsIEEDr7Kx0aizq7ejwdKuXL2', 'admin', 1, CURRENT_TIMESTAMP, 1)
ON DUPLICATE KEY UPDATE
    `password` = VALUES(`password`),
    `role` = 'admin',
    `is_active` = 1,
    `email_verified_at` = COALESCE(`email_verified_at`, CURRENT_TIMESTAMP);

-- -----------------------------------------------------------------------------
-- Migration Notes (for existing databases):
-- -----------------------------------------------------------------------------
-- If you already have an earlier version of the database, run:
--
-- ALTER TABLE `users`
--   ADD COLUMN IF NOT EXISTS `verification_expires_at` TIMESTAMP NULL DEFAULT NULL AFTER `verification_token`,
--   ADD COLUMN IF NOT EXISTS `session_version` INT UNSIGNED NOT NULL DEFAULT 1 AFTER `verification_expires_at`;
--
-- CREATE TABLE IF NOT EXISTS `password_reset_tokens` (
--     `id`           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
--     `user_id`      INT UNSIGNED NOT NULL,
--     `token_hash`   CHAR(64) NOT NULL,
--     `expires_at`   TIMESTAMP NOT NULL,
--     `used_at`      TIMESTAMP NULL DEFAULT NULL,
--     `created_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
--     `requested_ip` VARCHAR(45) NOT NULL,
--     INDEX `idx_token_hash` (`token_hash`),
--     INDEX `idx_user_expires` (`user_id`, `expires_at`),
--     CONSTRAINT `fk_reset_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
