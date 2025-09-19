-- KKMail Database Schema

-- Users table for managing email accounts
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Email messages table
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,
    from_email TEXT NOT NULL,
    to_email TEXT NOT NULL,
    cc_emails TEXT,
    bcc_emails TEXT,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    headers TEXT,
    attachments TEXT,
    status TEXT DEFAULT 'received', -- received, read, archived, deleted
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME
);

-- Email aliases/forwarding rules
CREATE TABLE IF NOT EXISTS email_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alias_email TEXT UNIQUE NOT NULL,
    target_email TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- API tokens for authentication
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT,
    permissions TEXT DEFAULT 'read',
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Email sending logs
CREATE TABLE IF NOT EXISTS send_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_email TEXT NOT NULL,
    to_email TEXT NOT NULL,
    subject TEXT,
    status TEXT NOT NULL, -- sent, failed, pending
    resend_id TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_emails_to_email ON emails(to_email);
CREATE INDEX IF NOT EXISTS idx_emails_from_email ON emails(from_email);
CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_send_logs_created_at ON send_logs(created_at);