-- Migration for temporary email functionality
-- Run this via: wrangler d1 execute kkmail-db --file=migrations/001_add_temp_emails.sql

-- Create temporary emails table
CREATE TABLE IF NOT EXISTS temp_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    access_token TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    purpose TEXT DEFAULT 'general', -- 'general', 'signup', 'verification'
    max_emails INTEGER DEFAULT 50,
    received_count INTEGER DEFAULT 0
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_temp_emails_email ON temp_emails(email);
CREATE INDEX IF NOT EXISTS idx_temp_emails_expires_at ON temp_emails(expires_at);
CREATE INDEX IF NOT EXISTS idx_temp_emails_active ON temp_emails(is_active, expires_at);

-- Create temp email usage tracking
CREATE TABLE IF NOT EXISTS temp_email_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    temp_email TEXT NOT NULL,
    action TEXT NOT NULL, -- 'created', 'accessed', 'email_received', 'extended'
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    FOREIGN KEY (temp_email) REFERENCES temp_emails(email) ON DELETE CASCADE
);

-- Create index for usage tracking
CREATE INDEX IF NOT EXISTS idx_temp_email_usage_email ON temp_email_usage(temp_email, timestamp);

-- Add columns to existing emails table for better temp email support
ALTER TABLE emails ADD COLUMN is_temp_email BOOLEAN DEFAULT FALSE;
ALTER TABLE emails ADD COLUMN temp_email_purpose TEXT;

-- Create view for active temp emails with stats
CREATE VIEW IF NOT EXISTS active_temp_emails AS
SELECT
    te.email,
    te.expires_at,
    te.created_at,
    te.purpose,
    te.max_emails,
    te.received_count,
    te.last_accessed_at,
    COUNT(e.id) as actual_email_count,
    MAX(e.created_at) as last_email_received
FROM temp_emails te
LEFT JOIN emails e ON te.email = e.to_email AND e.status != 'deleted'
WHERE te.is_active = 1 AND te.expires_at > datetime('now')
GROUP BY te.email;