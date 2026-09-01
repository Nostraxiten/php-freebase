-- schema.sql
-- Import this file to bootstrap the database.
-- Example: mysql -u root -p < db/schema.sql

CREATE DATABASE IF NOT EXISTS `freebase`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `freebase`;

CREATE TABLE IF NOT EXISTS `users` (
    `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username`   VARCHAR(50)  NOT NULL UNIQUE,
    `password`   VARCHAR(255) NOT NULL,   -- bcrypt hash, never plain text
    `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Default admin user: username "admin", password "admin"
-- Hash generated with PHP's password_hash() (bcrypt, cost 10).
-- CHANGE THIS PASSWORD IMMEDIATELY after your first login.
INSERT INTO `users` (`username`, `password`)
VALUES ('admin', '$2b$10$SLN20s.dggHCGf3qyABF8OnrOXKjoUph7cdVaFOxc1XwrgbKYgHm2')
ON DUPLICATE KEY UPDATE `username` = `username`;

-- Add your own tables below this line.
