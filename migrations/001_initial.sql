-- Initial migration for KKMail
-- Run this after creating D1 database

-- Create admin user (password should be hashed)
INSERT OR IGNORE INTO users (email, password_hash, full_name, is_active)
VALUES ('admin@yourdomain.com', '$2a$10$placeholder_hash', 'Admin User', TRUE);

-- Create default email aliases
INSERT OR IGNORE INTO email_aliases (alias_email, target_email, is_active)
VALUES
    ('no-reply@yourdomain.com', 'admin@yourdomain.com', TRUE),
    ('support@yourdomain.com', 'admin@yourdomain.com', TRUE),
    ('contact@yourdomain.com', 'admin@yourdomain.com', TRUE);