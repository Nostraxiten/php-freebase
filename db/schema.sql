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
    `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username`   VARCHAR(50)               NOT NULL UNIQUE,
    `password`   VARCHAR(255)              NOT NULL, -- bcrypt/argon2 hash, never plain text
    `role`       ENUM('admin', 'user')     NOT NULL DEFAULT 'user',
    `is_active`  TINYINT(1) UNSIGNED       NOT NULL DEFAULT 1,
    `created_at` TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username_active` (`username`, `is_active`)
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
-- Password: "admin" (Hash: bcrypt, cost 10)
-- -----------------------------------------------------------------------------
-- CRITICAL SECURITY NOTICE:
-- You MUST change this password immediately after the first login in any
-- shared or public environment.
-- -----------------------------------------------------------------------------
INSERT INTO `users` (`username`, `password`, `role`, `is_active`)
VALUES ('admin', '$2b$10$SLN20s.dggHCGf3qyABF8OnrOXKjoUph7cdVaFOxc1XwrgbKYgHm2', 'admin', 1)
ON DUPLICATE KEY UPDATE
    `role` = VALUES(`role`),
    `is_active` = VALUES(`is_active`);

-- -----------------------------------------------------------------------------
-- Migration Notes (for existing databases):
-- -----------------------------------------------------------------------------
-- If you already have an earlier version of the `users` table, run:
--
-- ALTER TABLE `users`
--   ADD COLUMN IF NOT EXISTS `role` ENUM('admin', 'user') NOT NULL DEFAULT 'user' AFTER `password`,
--   ADD COLUMN IF NOT EXISTS `is_active` TINYINT(1) UNSIGNED NOT NULL DEFAULT 1 AFTER `role`,
--   ADD COLUMN IF NOT EXISTS `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER `created_at`;
--
-- UPDATE `users` SET `role` = 'admin' WHERE `username` = 'admin';
