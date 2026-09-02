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
    `id`                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username`           VARCHAR(12)               NOT NULL UNIQUE, -- Min 4, Max 12 characters
    `email`              VARCHAR(100)              NOT NULL UNIQUE,
    `password`           VARCHAR(255)              NOT NULL, -- Secure hash (bcrypt/argon2)
    `role`               ENUM('admin', 'user')     NOT NULL DEFAULT 'user',
    `is_active`          TINYINT(1) UNSIGNED       NOT NULL DEFAULT 1,
    `email_verified_at`  TIMESTAMP                 NULL DEFAULT NULL,
    `verification_token` VARCHAR(64)               NULL DEFAULT NULL,
    `created_at`         TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`         TIMESTAMP                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`),
    INDEX `idx_token` (`verification_token`)
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
-- SECURITY NOTICE:
-- The default password is "admin123". Always update this credential before
-- production deployment.
-- -----------------------------------------------------------------------------
INSERT INTO `users` (`username`, `email`, `password`, `role`, `is_active`, `email_verified_at`)
VALUES ('admin', 'admin@freebase.local', '$2b$10$MAfUOW/eKLp4LJu0A/phIOjsu/BUfsIEEDr7Kx0aizq7ejwdKuXL2', 'admin', 1, CURRENT_TIMESTAMP)
ON DUPLICATE KEY UPDATE
    `password` = VALUES(`password`),
    `role` = 'admin',
    `is_active` = 1,
    `email_verified_at` = COALESCE(`email_verified_at`, CURRENT_TIMESTAMP);

-- -----------------------------------------------------------------------------
-- Migration Notes (for existing databases):
-- -----------------------------------------------------------------------------
-- If you already have an earlier version of the `users` table, run:
--
-- ALTER TABLE `users`
--   MODIFY COLUMN `username` VARCHAR(12) NOT NULL,
--   ADD COLUMN IF NOT EXISTS `email` VARCHAR(100) NOT NULL UNIQUE AFTER `username`,
--   ADD COLUMN IF NOT EXISTS `email_verified_at` TIMESTAMP NULL DEFAULT NULL AFTER `is_active`,
--   ADD COLUMN IF NOT EXISTS `verification_token` VARCHAR(64) NULL DEFAULT NULL AFTER `email_verified_at`;
--
-- UPDATE `users` SET `password` = '$2b$10$MAfUOW/eKLp4LJu0A/phIOjsu/BUfsIEEDr7Kx0aizq7ejwdKuXL2' WHERE `username` = 'admin';
