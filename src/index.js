import { ResendService } from './resend.js';
import { AuthService } from './auth.js';
import { TempEmailService } from './temp-email.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        const resend = new ResendService(env.RESEND_API_KEY);
        const auth = new AuthService(env.JWT_SECRET, env.DB);
        const tempEmail = new TempEmailService(env.DB);

        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        if (method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
            if (path === '/api/init') {
                return await handleInit(env.DB, env.ADMIN_EMAIL, env);
            }


            if (path === '/api/auth/login') {
                return await handleLogin(request, auth, corsHeaders);
            }

            if (path === '/api/send') {
                return await handleSendEmail(request, resend, auth, env.DB, corsHeaders);
            }

            if (path === '/api/send-simple') {
                return await handleSendEmailSimple(request, resend, env.DB, env.API_TOKEN, corsHeaders);
            }

            if (path === '/api/emails') {
                return await handleGetEmails(request, auth, env.DB, corsHeaders);
            }

            if (path === '/api/users') {
                if (method === 'GET') {
                    return await handleGetUsers(request, auth, env.DB, corsHeaders);
                } else if (method === 'POST') {
                    return await handleCreateUser(request, auth, env.DB, corsHeaders);
                }
            }

            if (path === '/api/aliases') {
                if (method === 'GET') {
                    return await handleGetAliases(request, auth, env.DB, corsHeaders);
                } else if (method === 'POST') {
                    return await handleCreateAlias(request, auth, env.DB, corsHeaders);
                }
            }

            if (path.startsWith('/api/emails/')) {
                const emailId = path.split('/')[3];
                return await handleGetEmail(request, auth, env.DB, emailId, corsHeaders);
            }

            if (path === '/api/webhooks/resend') {
                return await handleResendWebhook(request, env.DB, corsHeaders);
            }

            if (path.startsWith('/api/emails/status/')) {
                const emailId = path.split('/')[4];
                return await handleEmailStatus(request, resend, auth, emailId, corsHeaders);
            }

            if (path === '/api/user-token') {
                return await handleGetUserToken(request, auth, env.DB, corsHeaders);
            }

            if (path === '/api/generate-token') {
                return await handleGenerateUserToken(request, auth, env.DB, corsHeaders);
            }

            if (path === '/api/all-user-tokens') {
                return await handleGetAllUserTokens(request, auth, env.DB, corsHeaders);
            }

            if (path.startsWith('/api/user-token/')) {
                const userId = path.split('/')[3];
                return await handleGetUserTokenById(request, auth, env.DB, userId, corsHeaders);
            }

            if (path.startsWith('/api/generate-token/')) {
                const userId = path.split('/')[3];
                return await handleGenerateUserTokenById(request, auth, env.DB, userId, corsHeaders);
            }

            if (path === '/api/usage-stats') {
                return await handleGetUsageStats(request, auth, env.DB, corsHeaders);
            }

            // Temporary Email endpoints
            if (path === '/api/temp-email/create') {
                return await handleCreateTempEmail(request, tempEmail, env.EMAIL_DOMAIN, corsHeaders);
            }

            if (path === '/api/temp-email/create-signup') {
                return await handleCreateSignupTempEmail(request, tempEmail, env.EMAIL_DOMAIN, corsHeaders);
            }

            if (path === '/api/temp-email/create-verification') {
                return await handleCreateVerificationTempEmail(request, tempEmail, env.EMAIL_DOMAIN, corsHeaders);
            }

            if (path.startsWith('/api/temp-email/')) {
                const pathParts = path.split('/');
                const email = decodeURIComponent(pathParts[3]);
                const action = pathParts[4];

                if (action === 'emails') {
                    return await handleGetTempEmails(request, tempEmail, email, corsHeaders);
                } else if (action === 'extend') {
                    return await handleExtendTempEmail(request, tempEmail, email, corsHeaders);
                } else if (action === 'stats') {
                    return await handleGetTempEmailStats(request, tempEmail, email, corsHeaders);
                } else if (action === 'mark-read') {
                    return await handleMarkTempEmailAsRead(request, tempEmail, email, corsHeaders);
                } else if (action === 'delete-email') {
                    return await handleDeleteTempEmail(request, tempEmail, email, corsHeaders);
                }
            }

            if (path === '/api/temp-email/admin/all') {
                return await handleGetAllTempEmails(request, auth, tempEmail, corsHeaders);
            }

            if (path === '/api/temp-email/admin/stats') {
                return await handleGetTempEmailAdminStats(request, auth, tempEmail, corsHeaders);
            }

            if (path === '/api/temp-email/admin/cleanup') {
                return await handleCleanupExpiredTempEmails(request, auth, tempEmail, corsHeaders);
            }

            if (path === '/temp-email' || path === '/temp') {
                return await handleTempEmailInterface();
            }

            if (path === '/admin' || path === '/') {
                return await handleAdminInterface(env);
            }

            return new Response('Not Found', { status: 404, headers: corsHeaders });

        } catch (error) {
            console.error('Error:', error);
            return new Response(JSON.stringify({
                error: 'Internal Server Error',
                message: error.message
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    },

    async email(message, env, ctx) {
        const tempEmail = new TempEmailService(env.DB);
        return await handleIncomingEmail(message, env.DB, tempEmail);
    }
};

async function handleInit(db, adminEmail, env) {
    try {
        const result = await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );

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
                status TEXT DEFAULT 'received',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                read_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS email_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias_email TEXT UNIQUE NOT NULL,
                target_email TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

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

            CREATE TABLE IF NOT EXISTS send_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_email TEXT NOT NULL,
                to_email TEXT NOT NULL,
                subject TEXT,
                status TEXT NOT NULL,
                resend_id TEXT,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS usage_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                limit_type TEXT NOT NULL, -- 'daily' or 'monthly'
                limit_value INTEGER NOT NULL,
                current_usage INTEGER DEFAULT 0,
                reset_date DATE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            INSERT OR IGNORE INTO users (email, password_hash, full_name, is_active)
            VALUES ('${adminEmail}', 'change_me', 'Admin User', TRUE);

            INSERT OR IGNORE INTO email_aliases (alias_email, target_email, is_active)
            VALUES
                ('no-reply@${env.EMAIL_DOMAIN || 'yourdomain.com'}', '${adminEmail}', TRUE),
                ('support@${env.EMAIL_DOMAIN || 'yourdomain.com'}', '${adminEmail}', TRUE),
                ('contact@${env.EMAIL_DOMAIN || 'yourdomain.com'}', '${adminEmail}', TRUE);

            INSERT OR IGNORE INTO usage_limits (limit_type, limit_value, reset_date)
            VALUES
                ('daily', 100, date('now')),
                ('monthly', 3000, date('now', 'start of month', '+1 month'));

            -- Create temp emails table if not exists
            CREATE TABLE IF NOT EXISTS temp_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                access_token TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_accessed_at DATETIME,
                is_active BOOLEAN DEFAULT TRUE,
                purpose TEXT DEFAULT 'general',
                max_emails INTEGER DEFAULT 50,
                received_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_temp_emails_email ON temp_emails(email);
            CREATE INDEX IF NOT EXISTS idx_temp_emails_expires_at ON temp_emails(expires_at);
            CREATE INDEX IF NOT EXISTS idx_temp_emails_active ON temp_emails(is_active, expires_at);

            CREATE TABLE IF NOT EXISTS temp_email_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                temp_email TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_temp_email_usage_email ON temp_email_usage(temp_email, timestamp);
        `);

        return new Response(JSON.stringify({
            success: true,
            message: 'Database initialized successfully'
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({
            error: 'Failed to initialize database',
            message: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function handleLogin(request, auth, corsHeaders) {
    try {
        const { email, password } = await request.json();

        const user = await auth.db.prepare(`
            SELECT id, email, password_hash, is_active
            FROM users WHERE email = ? AND is_active = 1
        `).bind(email).first();

        if (!user) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const isValidPassword = await auth.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = await auth.generateToken(user.id, 'admin');

        return new Response(JSON.stringify({
            success: true,
            token,
            user: { id: user.id, email: user.email }
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleSendEmail(request, resend, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 检查发送限制
        const limitCheck = await checkSendingLimits(db);
        if (!limitCheck.allowed) {
            return new Response(JSON.stringify({
                error: 'Sending limit exceeded',
                message: limitCheck.message
            }), {
                status: 429,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const emailData = await request.json();
        const result = await resend.sendEmail(emailData);

        // 如果发送成功，更新用量
        if (result.success) {
            await updateUsageCount(db);
        }

        await db.prepare(`
            INSERT INTO send_logs (from_email, to_email, subject, status, resend_id)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
            emailData.from,
            Array.isArray(emailData.to) ? emailData.to.join(',') : emailData.to,
            emailData.subject || '',
            result.success ? 'sent' : 'failed',
            result.id || null
        ).run();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetEmails(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;
        const status = url.searchParams.get('status');

        let query = `
            SELECT id, message_id, from_email, to_email, subject, status, created_at, read_at
            FROM emails
        `;

        const params = [];
        if (status) {
            query += ' WHERE status = ?';
            params.push(status);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const emails = await db.prepare(query).bind(...params).all();

        return new Response(JSON.stringify({
            success: true,
            emails: emails.results,
            total: emails.results.length
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleIncomingEmail(message, db, tempEmailService) {
    try {
        const messageId = message.headers.get('message-id') || `kkmail-${Date.now()}-${Math.random()}`;
        const from = message.from;
        const to = message.to;
        const subject = message.headers.get('subject') || '';

        let bodyText = '';
        let bodyHtml = '';

        try {
            bodyText = await new Response(message.raw).text();
        } catch (e) {
            console.error('Failed to get raw email:', e);
        }

        const headers = JSON.stringify(Object.fromEntries(message.headers));

        await db.prepare(`
            INSERT OR REPLACE INTO emails
            (message_id, from_email, to_email, subject, body_text, body_html, headers, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'received')
        `).bind(messageId, from, to, subject, bodyText, bodyHtml, headers).run();

        // Check if this is a temporary email
        await tempEmailService.onEmailReceived(to, from, subject);

        const aliases = await db.prepare(`
            SELECT target_email FROM email_aliases
            WHERE alias_email = ? AND is_active = 1
        `).bind(to).all();

        console.log(`Email received: ${from} -> ${to}, subject: ${subject}`);

        return;
    } catch (error) {
        console.error('Failed to process incoming email:', error);
        return;
    }
}

async function handleGetUsers(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const users = await db.prepare(`
            SELECT id, email, full_name, created_at, is_active
            FROM users
            ORDER BY created_at DESC
        `).all();

        return new Response(JSON.stringify({
            success: true,
            users: users.results
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateUser(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid || authResult.user.permissions !== 'admin') {
            return new Response(JSON.stringify({ error: 'Admin access required' }), {
                status: 403,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const { email, password, fullName } = await request.json();

        if (!email || !password) {
            return new Response(JSON.stringify({ error: 'Email and password required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await auth.createUser(email, password, fullName || '');

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAliases(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const aliases = await db.prepare(`
            SELECT alias_email, target_email, created_at, is_active
            FROM email_aliases
            ORDER BY created_at DESC
        `).all();

        return new Response(JSON.stringify({
            success: true,
            aliases: aliases.results
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateAlias(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid || authResult.user.permissions !== 'admin') {
            return new Response(JSON.stringify({ error: 'Admin access required' }), {
                status: 403,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const { aliasEmail, targetEmail } = await request.json();

        if (!aliasEmail || !targetEmail) {
            return new Response(JSON.stringify({ error: 'Alias email and target email required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        await db.prepare(`
            INSERT INTO email_aliases (alias_email, target_email, is_active)
            VALUES (?, ?, 1)
        `).bind(aliasEmail, targetEmail).run();

        return new Response(JSON.stringify({
            success: true,
            message: 'Email alias created successfully'
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleAdminInterface(env) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KKMail 管理界面</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(45deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .nav-tabs {
            display: flex;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }

        .nav-tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 16px;
            transition: all 0.3s;
        }

        .nav-tab.active {
            background: white;
            border-bottom: 3px solid #4facfe;
            color: #4facfe;
        }

        .tab-content {
            display: none;
            padding: 30px;
        }

        .tab-content.active {
            display: block;
        }

        .login-form {
            max-width: 400px;
            margin: 50px auto;
            padding: 30px;
            background: #f8f9fa;
            border-radius: 10px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }

        .form-control:focus {
            outline: none;
            border-color: #4facfe;
            box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s;
            margin-right: 10px;
            margin-bottom: 10px;
        }

        .btn-primary {
            background: linear-gradient(45deg, #4facfe 0%, #00f2fe 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(79, 172, 254, 0.3);
        }

        .btn-success {
            background: #28a745;
            color: white;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }

        .card-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
        }

        .card-body {
            padding: 20px;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .table th,
        .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .hidden {
            display: none;
        }

        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-label {
            font-size: 1rem;
            opacity: 0.9;
        }

        .logout-btn:hover {
            background: rgba(255,255,255,0.3) !important;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>📧 KKMail 管理界面</h1>
                    <p>自定义域名邮箱服务管理</p>
                </div>
                <button onclick="logout()" class="logout-btn" style="background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); padding: 8px 16px; border-radius: 20px; cursor: pointer; backdrop-filter: blur(10px); transition: all 0.3s;">退出登录</button>
            </div>
        </div>

        <!-- 登录界面 -->
        <div id="loginSection">
            <div class="login-form">
                <h2 style="text-align: center; margin-bottom: 30px;">管理员登录</h2>
                <div class="form-group">
                    <label>邮箱地址</label>
                    <input type="email" id="email" class="form-control" placeholder="请输入邮箱地址">
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" id="password" class="form-control" placeholder="请输入密码">
                </div>
                <button onclick="login()" class="btn btn-primary" style="width: 100%;">登录</button>
                <div id="loginError" class="alert alert-danger hidden" style="margin-top: 15px;"></div>
            </div>
        </div>

        <!-- 主界面 -->
        <div id="mainSection" class="hidden">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('dashboard')">仪表板</button>
                <button class="nav-tab" onclick="showTab('emails')">邮件管理</button>
                <button class="nav-tab" onclick="showTab('users')">用户管理</button>
                <button class="nav-tab" onclick="showTab('aliases')">邮件别名</button>
                <button class="nav-tab" onclick="showTab('temp-emails')">临时邮箱</button>
                <button class="nav-tab" onclick="showTab('send')">发送邮件</button>
            </div>

            <!-- 仪表板 -->
            <div id="dashboard" class="tab-content active">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number" id="userCount">-</div>
                        <div class="stat-label">注册用户</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="aliasCount">-</div>
                        <div class="stat-label">邮件别名</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="emailCount">-</div>
                        <div class="stat-label">邮件总数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="todayUsage">-</div>
                        <div class="stat-label">今日发送</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="monthUsage">-</div>
                        <div class="stat-label">本月发送</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="tempEmailCount">-</div>
                        <div class="stat-label">活跃临时邮箱</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">系统信息</div>
                    <div class="card-body">
                        <p><strong>服务地址:</strong> https://${env.DOMAIN || 'mail.yourdomain.com'}</p>
                        <p><strong>邮件域名:</strong> ${env.EMAIL_DOMAIN || 'yourdomain.com'}</p>
                        <p><strong>状态:</strong> <span style="color: #28a745;">✅ 运行正常</span></p>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">发送限制 (Resend 免费套餐)</div>
                    <div class="card-body">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div>
                                <p><strong>每日限制:</strong> <span id="dailyLimitInfo">100 封</span></p>
                                <div style="background: #f0f0f0; border-radius: 10px; height: 10px; margin-top: 5px;">
                                    <div id="dailyProgressBar" style="background: linear-gradient(45deg, #4facfe 0%, #00f2fe 100%); height: 100%; border-radius: 10px; width: 0%; transition: width 0.3s;"></div>
                                </div>
                                <small id="dailyUsageText">今日已发送: 0 / 100</small>
                            </div>
                            <div>
                                <p><strong>每月限制:</strong> <span id="monthlyLimitInfo">3,000 封</span></p>
                                <div style="background: #f0f0f0; border-radius: 10px; height: 10px; margin-top: 5px;">
                                    <div id="monthlyProgressBar" style="background: linear-gradient(45deg, #667eea 0%, #764ba2 100%); height: 100%; border-radius: 10px; width: 0%; transition: width 0.3s;"></div>
                                </div>
                                <small id="monthlyUsageText">本月已发送: 0 / 3,000</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 邮件管理 -->
            <div id="emails" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        邮件列表
                        <button onclick="loadEmails()" class="btn btn-primary" style="float: right;">刷新</button>
                    </div>
                    <div class="card-body">
                        <div id="emailsList" class="loading">加载中...</div>
                    </div>
                </div>
            </div>

            <!-- 用户管理 -->
            <div id="users" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        用户管理
                        <button onclick="showAddUserForm()" class="btn btn-success" style="float: right;">添加用户</button>
                    </div>
                    <div class="card-body">
                        <div id="addUserForm" class="hidden" style="margin-bottom: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                            <h4 style="margin-bottom: 15px;">添加新用户</h4>
                            <div class="form-group">
                                <label>邮箱地址</label>
                                <input type="email" id="newUserEmail" class="form-control" placeholder="user@${env.EMAIL_DOMAIN || 'yourdomain.com'}">
                            </div>
                            <div class="form-group">
                                <label>密码</label>
                                <input type="password" id="newUserPassword" class="form-control" placeholder="设置密码">
                            </div>
                            <div class="form-group">
                                <label>姓名</label>
                                <input type="text" id="newUserName" class="form-control" placeholder="用户姓名">
                            </div>
                            <button onclick="createUser()" class="btn btn-success">创建用户</button>
                            <button onclick="hideAddUserForm()" class="btn btn-secondary">取消</button>
                        </div>
                        <div id="usersList" class="loading">加载中...</div>
                    </div>
                </div>
            </div>

            <!-- 邮件别名 -->
            <div id="aliases" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        邮件别名管理
                        <button onclick="showAddAliasForm()" class="btn btn-success" style="float: right;">添加别名</button>
                    </div>
                    <div class="card-body">
                        <div id="addAliasForm" class="hidden" style="margin-bottom: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                            <h4 style="margin-bottom: 15px;">添加邮件别名</h4>
                            <div class="form-group">
                                <label>别名邮箱</label>
                                <input type="email" id="aliasEmail" class="form-control" placeholder="support@${env.EMAIL_DOMAIN || 'yourdomain.com'}">
                            </div>
                            <div class="form-group">
                                <label>目标邮箱</label>
                                <input type="email" id="targetEmail" class="form-control" placeholder="${env.ADMIN_EMAIL || 'admin@yourdomain.com'}">
                            </div>
                            <button onclick="createAlias()" class="btn btn-success">创建别名</button>
                            <button onclick="hideAddAliasForm()" class="btn btn-secondary">取消</button>
                        </div>
                        <div id="aliasesList" class="loading">加载中...</div>
                    </div>
                </div>
            </div>

            <!-- 临时邮箱 -->
            <div id="temp-emails" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        临时邮箱管理
                        <button onclick="showCreateTempEmailForm()" class="btn btn-success" style="float: right;">创建临时邮箱</button>
                    </div>
                    <div class="card-body">
                        <div id="createTempEmailForm" class="hidden" style="margin-bottom: 20px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
                            <h4 style="margin-bottom: 15px;">创建临时邮箱</h4>
                            <div class="form-group">
                                <label>用途类型</label>
                                <select id="tempEmailPurpose" class="form-control">
                                    <option value="general">通用</option>
                                    <option value="signup">注册验证</option>
                                    <option value="verification">邮箱验证</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>有效期（小时）</label>
                                <input type="number" id="tempEmailExpiry" class="form-control" value="24" min="1" max="168">
                            </div>
                            <div class="form-group">
                                <label>最大邮件数</label>
                                <input type="number" id="tempEmailMaxEmails" class="form-control" value="50" min="1" max="100">
                            </div>
                            <div class="form-group" id="serviceNameGroup" style="display: none;">
                                <label>服务名称（可选）</label>
                                <input type="text" id="tempEmailServiceName" class="form-control" placeholder="例如：GitHub, Gmail等">
                            </div>
                            <button onclick="createTempEmail()" class="btn btn-success">创建</button>
                            <button onclick="hideCreateTempEmailForm()" class="btn btn-secondary">取消</button>
                        </div>
                        <div id="tempEmailsList" class="loading">加载中...</div>
                    </div>
                </div>

                <!-- 临时邮箱查看器 -->
                <div class="card" style="margin-top: 20px;">
                    <div class="card-header">临时邮箱查看器</div>
                    <div class="card-body">
                        <div class="form-group">
                            <label>临时邮箱地址</label>
                            <input type="email" id="viewTempEmail" class="form-control" placeholder="输入临时邮箱地址">
                        </div>
                        <div class="form-group">
                            <label>访问令牌</label>
                            <input type="text" id="viewTempEmailToken" class="form-control" placeholder="输入访问令牌">
                        </div>
                        <button onclick="viewTempEmailEmails()" class="btn btn-primary">查看邮件</button>
                        <button onclick="extendTempEmailTime()" class="btn btn-warning">延长时间</button>
                        <button onclick="showTempEmailStats()" class="btn btn-info">查看统计</button>
                    </div>
                </div>

                <!-- 邮件列表显示区域 -->
                <div id="tempEmailViewer" class="card hidden" style="margin-top: 20px;">
                    <div class="card-header">
                        <span id="tempEmailViewerTitle">邮件列表</span>
                        <button onclick="refreshTempEmails()" class="btn btn-primary" style="float: right;">刷新</button>
                    </div>
                    <div class="card-body">
                        <div id="tempEmailEmailsList">
                        </div>
                    </div>
                </div>
            </div>

            <!-- 发送邮件 -->
            <div id="send" class="tab-content">
                <div class="card">
                    <div class="card-header">发送邮件</div>
                    <div class="card-body">
                        <div class="form-group">
                            <label>发件人</label>
                            <input type="email" id="sendFrom" class="form-control" value="${env.ADMIN_EMAIL || 'admin@yourdomain.com'}">
                        </div>
                        <div class="form-group">
                            <label>收件人</label>
                            <input type="email" id="sendTo" class="form-control" placeholder="recipient@example.com">
                        </div>
                        <div class="form-group">
                            <label>主题</label>
                            <input type="text" id="sendSubject" class="form-control" placeholder="邮件主题">
                        </div>
                        <div class="form-group">
                            <label>内容</label>
                            <textarea id="sendContent" class="form-control" rows="6" placeholder="邮件内容"></textarea>
                        </div>
                        <button onclick="sendEmail()" class="btn btn-primary">发送邮件</button>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        let authToken = '';
        const API_BASE = '/api';

        // 登录
        async function login() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch(\`\${API_BASE}/auth/login\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (data.success) {
                    authToken = data.token;
                    // 保存 token 到 localStorage
                    localStorage.setItem('authToken', authToken);
                    document.getElementById('loginSection').classList.add('hidden');
                    document.getElementById('mainSection').classList.remove('hidden');
                    // 初始化路由，根据当前 hash 显示页面
                    handleHashChange();
                } else {
                    showError('loginError', data.error || '登录失败');
                }
            } catch (error) {
                showError('loginError', '网络错误: ' + error.message);
            }
        }

        // 显示错误信息
        function showError(elementId, message) {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.classList.remove('hidden');
        }

        // 显示成功信息
        function showSuccess(message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-success';
            alertDiv.textContent = message;
            document.body.appendChild(alertDiv);
            setTimeout(() => alertDiv.remove(), 3000);
        }

        // 切换标签页
        function showTab(tabName, updateHash = true) {
            // 隐藏所有标签页
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // 显示选中的标签页
            document.getElementById(tabName).classList.add('active');

            // 激活对应的导航按钮
            const navButtons = document.querySelectorAll('.nav-tab');
            navButtons.forEach(button => {
                if (button.textContent.includes(getTabDisplayName(tabName))) {
                    button.classList.add('active');
                }
            });

            // 更新 URL hash
            if (updateHash) {
                window.location.hash = tabName;
            }

            // 加载对应数据
            if (tabName === 'dashboard') loadDashboard();
            else if (tabName === 'emails') loadEmails();
            else if (tabName === 'users') loadUsers();
            else if (tabName === 'aliases') loadAliases();
            else if (tabName === 'temp-emails') loadTempEmails();
        }

        // 获取标签页显示名称
        function getTabDisplayName(tabName) {
            const nameMap = {
                'dashboard': '仪表板',
                'emails': '邮件管理',
                'users': '用户管理',
                'aliases': '邮件别名',
                'temp-emails': '临时邮箱',
                'send': '发送邮件'
            };
            return nameMap[tabName] || tabName;
        }

        // 加载仪表板
        async function loadDashboard() {
            try {
                const [users, aliases, usageStats, tempEmailStats] = await Promise.all([
                    apiRequest('/users'),
                    apiRequest('/aliases'),
                    apiRequest('/usage-stats'),
                    apiRequest('/temp-email/admin/stats')
                ]);

                document.getElementById('userCount').textContent = users.users?.length || 0;
                document.getElementById('aliasCount').textContent = aliases.aliases?.length || 0;
                document.getElementById('emailCount').textContent = usageStats.usage?.total || 0;
                document.getElementById('todayUsage').textContent = usageStats.usage?.today || 0;
                document.getElementById('monthUsage').textContent = usageStats.usage?.month || 0;
                document.getElementById('tempEmailCount').textContent = tempEmailStats.stats?.activeTempEmails || 0;

                // 更新发送限制进度条
                if (usageStats.success) {
                    const dailyUsage = usageStats.usage.today || 0;
                    const monthlyUsage = usageStats.usage.month || 0;
                    const dailyLimit = usageStats.resend_limits.daily_limit || 100;
                    const monthlyLimit = usageStats.resend_limits.monthly_limit || 3000;

                    // 每日进度
                    const dailyPercent = Math.min((dailyUsage / dailyLimit) * 100, 100);
                    document.getElementById('dailyProgressBar').style.width = dailyPercent + '%';
                    document.getElementById('dailyUsageText').textContent = \`今日已发送: \${dailyUsage} / \${dailyLimit}\`;

                    // 每月进度
                    const monthlyPercent = Math.min((monthlyUsage / monthlyLimit) * 100, 100);
                    document.getElementById('monthlyProgressBar').style.width = monthlyPercent + '%';
                    document.getElementById('monthlyUsageText').textContent = \`本月已发送: \${monthlyUsage} / \${monthlyLimit}\`;

                    // 如果接近限制，改变颜色
                    if (dailyPercent > 80) {
                        document.getElementById('dailyProgressBar').style.background = 'linear-gradient(45deg, #ff6b6b 0%, #ee5a24 100%)';
                    }
                    if (monthlyPercent > 80) {
                        document.getElementById('monthlyProgressBar').style.background = 'linear-gradient(45deg, #ff6b6b 0%, #ee5a24 100%)';
                    }
                }
            } catch (error) {
                console.error('Failed to load dashboard:', error);
            }
        }

        // 加载邮件列表
        async function loadEmails() {
            try {
                const response = await apiRequest('/emails');
                const emailsDiv = document.getElementById('emailsList');

                if (response.emails && response.emails.length > 0) {
                    emailsDiv.innerHTML = \`
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>发件人</th>
                                    <th>收件人</th>
                                    <th>主题</th>
                                    <th>状态</th>
                                    <th>时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${response.emails.map(email => \`
                                    <tr>
                                        <td>\${email.from_email}</td>
                                        <td>\${email.to_email}</td>
                                        <td>\${email.subject || '无主题'}</td>
                                        <td>\${email.status}</td>
                                        <td>\${new Date(email.created_at).toLocaleString()}</td>
                                    </tr>
                                \`).join('')}
                            </tbody>
                        </table>
                    \`;
                } else {
                    emailsDiv.innerHTML = '<p>暂无邮件记录</p>';
                }
            } catch (error) {
                document.getElementById('emailsList').innerHTML = '<p style="color: red;">加载失败: ' + error.message + '</p>';
            }
        }

        // 加载用户列表
        async function loadUsers() {
            try {
                console.log('Loading users...');
                const usersResponse = await apiRequest('/users');
                console.log('Users response:', usersResponse);

                let tokensResponse;
                try {
                    tokensResponse = await apiRequest('/all-user-tokens');
                    console.log('Tokens response:', tokensResponse);
                } catch (tokenError) {
                    console.error('Token loading error:', tokenError);
                    tokensResponse = { success: false, tokens: {} };
                }

                const usersDiv = document.getElementById('usersList');

                if (usersResponse.users && usersResponse.users.length > 0) {
                    const userTokens = tokensResponse.success ? tokensResponse.tokens : {};

                    usersDiv.innerHTML = \`
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>邮箱</th>
                                    <th>姓名</th>
                                    <th>状态</th>
                                    <th>API Token</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${usersResponse.users.map(user => {
                                    const hasToken = userTokens[user.id];
                                    return \`
                                    <tr>
                                        <td>\${user.id}</td>
                                        <td>\${user.email}</td>
                                        <td>\${user.full_name || '-'}</td>
                                        <td>\${user.is_active ? '活跃' : '禁用'}</td>
                                        <td>
                                            \${hasToken ?
                                                \`<code style="font-size: 12px;">\${hasToken.substring(0, 20)}...</code>\` :
                                                '<span style="color: #666;">未生成</span>'
                                            }
                                        </td>
                                        <td>
                                            <button onclick="manageUserApi(\${user.id}, '\${user.email}')" class="btn btn-primary" style="font-size: 12px; padding: 4px 8px;">API管理</button>
                                        </td>
                                    </tr>\`;
                                }).join('')}
                            </tbody>
                        </table>
                    \`;
                } else {
                    usersDiv.innerHTML = '<p>暂无用户</p>';
                }
            } catch (error) {
                console.error('Load users error:', error);
                document.getElementById('usersList').innerHTML = '<p style="color: red;">加载失败: ' + error.message + '</p>';
            }
        }

        // 加载别名列表
        async function loadAliases() {
            try {
                const response = await apiRequest('/aliases');
                const aliasesDiv = document.getElementById('aliasesList');

                if (response.aliases && response.aliases.length > 0) {
                    aliasesDiv.innerHTML = \`
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>别名邮箱</th>
                                    <th>目标邮箱</th>
                                    <th>状态</th>
                                    <th>创建时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${response.aliases.map(alias => \`
                                    <tr>
                                        <td>\${alias.alias_email}</td>
                                        <td>\${alias.target_email}</td>
                                        <td>\${alias.is_active ? '活跃' : '禁用'}</td>
                                        <td>\${new Date(alias.created_at).toLocaleString()}</td>
                                    </tr>
                                \`).join('')}
                            </tbody>
                        </table>
                    \`;
                } else {
                    aliasesDiv.innerHTML = '<p>暂无邮件别名</p>';
                }
            } catch (error) {
                document.getElementById('aliasesList').innerHTML = '<p style="color: red;">加载失败: ' + error.message + '</p>';
            }
        }

        // 显示添加用户表单
        function showAddUserForm() {
            document.getElementById('addUserForm').classList.remove('hidden');
        }

        function hideAddUserForm() {
            document.getElementById('addUserForm').classList.add('hidden');
        }

        // 创建用户
        async function createUser() {
            const email = document.getElementById('newUserEmail').value;
            const password = document.getElementById('newUserPassword').value;
            const fullName = document.getElementById('newUserName').value;

            try {
                const response = await apiRequest('/users', 'POST', {
                    email, password, fullName
                });

                if (response.success) {
                    showSuccess('用户创建成功');
                    hideAddUserForm();
                    loadUsers();
                } else {
                    alert('创建失败: ' + response.error);
                }
            } catch (error) {
                alert('创建失败: ' + error.message);
            }
        }

        // 显示添加别名表单
        function showAddAliasForm() {
            document.getElementById('addAliasForm').classList.remove('hidden');
        }

        function hideAddAliasForm() {
            document.getElementById('addAliasForm').classList.add('hidden');
        }

        // 创建别名
        async function createAlias() {
            const aliasEmail = document.getElementById('aliasEmail').value;
            const targetEmail = document.getElementById('targetEmail').value;

            try {
                const response = await apiRequest('/aliases', 'POST', {
                    aliasEmail, targetEmail
                });

                if (response.success) {
                    showSuccess('别名创建成功');
                    hideAddAliasForm();
                    loadAliases();
                } else {
                    alert('创建失败: ' + response.error);
                }
            } catch (error) {
                alert('创建失败: ' + error.message);
            }
        }

        // 发送邮件
        async function sendEmail() {
            const from = document.getElementById('sendFrom').value;
            const to = document.getElementById('sendTo').value;
            const subject = document.getElementById('sendSubject').value;
            const text = document.getElementById('sendContent').value;

            try {
                const response = await apiRequest('/send', 'POST', {
                    from, to, subject, text
                });

                if (response.success) {
                    showSuccess('邮件发送成功！邮件ID: ' + response.id);
                    // 清空表单
                    document.getElementById('sendSubject').value = '';
                    document.getElementById('sendContent').value = '';
                } else {
                    alert('发送失败: ' + response.error);
                }
            } catch (error) {
                alert('发送失败: ' + error.message);
            }
        }

        // 管理用户API
        async function manageUserApi(userId, userEmail) {
            // 创建弹窗
            const modal = document.createElement('div');
            modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';

            modal.innerHTML = \`
                <div style="background: white; border-radius: 10px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;">
                    <div style="padding: 20px; border-bottom: 1px solid #eee;">
                        <h3>\${userEmail} 的 API 管理</h3>
                        <button onclick="this.closest('div[style*=position]').remove()" style="float: right; margin-top: -30px; border: none; background: none; font-size: 20px; cursor: pointer;">×</button>
                    </div>
                    <div style="padding: 20px;">
                        <div style="margin-bottom: 20px;">
                            <strong>当前API Token:</strong>
                            <div id="userToken_\${userId}" style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 5px; font-family: monospace; font-size: 12px;">
                                加载中...
                            </div>
                        </div>

                        <div style="margin-bottom: 20px;">
                            <button onclick="generateUserToken(\${userId})" class="btn btn-primary">生成新Token</button>
                            <button onclick="testUserApi(\${userId})" class="btn btn-success">测试API</button>
                            <button onclick="showApiDocModal()" class="btn btn-secondary">查看API文档</button>
                        </div>

                        <div id="testArea_\${userId}" style="display: none; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                            <h5>API测试</h5>
                            <div style="margin-bottom: 10px;">
                                <label>收件人:</label>
                                <input type="email" id="testTo_\${userId}" style="width: 100%; padding: 8px; margin-top: 5px;" placeholder="test@example.com">
                            </div>
                            <div style="margin-bottom: 10px;">
                                <label>主题:</label>
                                <input type="text" id="testSubject_\${userId}" style="width: 100%; padding: 8px; margin-top: 5px;" value="API测试邮件">
                            </div>
                            <div style="margin-bottom: 10px;">
                                <label>内容:</label>
                                <textarea id="testContent_\${userId}" style="width: 100%; padding: 8px; margin-top: 5px;" rows="3">这是通过API发送的测试邮件</textarea>
                            </div>
                            <button onclick="executeApiTest(\${userId})" class="btn btn-success">发送测试</button>
                            <div id="testResult_\${userId}" style="margin-top: 10px;"></div>
                        </div>
                    </div>
                </div>
            \`;

            document.body.appendChild(modal);

            // 加载用户的token
            loadUserToken(userId);
        }

        // 加载特定用户的Token
        async function loadUserToken(userId) {
            try {
                const response = await apiRequest(\`/user-token/\${userId}\`);
                const tokenDiv = document.getElementById(\`userToken_\${userId}\`);
                if (response.success && response.token) {
                    tokenDiv.innerHTML = response.token;
                } else {
                    tokenDiv.innerHTML = '<span style="color: #666;">暂未生成</span>';
                }
            } catch (error) {
                const tokenDiv = document.getElementById(\`userToken_\${userId}\`);
                tokenDiv.innerHTML = '<span style="color: red;">加载失败</span>';
            }
        }

        // 生成用户Token
        async function generateUserToken(userId) {
            try {
                const response = await apiRequest(\`/generate-token/\${userId}\`, 'POST');
                if (response.success) {
                    document.getElementById(\`userToken_\${userId}\`).innerHTML = response.token;
                    showSuccess('API Token已生成');
                    loadUsers(); // 刷新用户列表
                } else {
                    alert('生成失败: ' + response.error);
                }
            } catch (error) {
                alert('生成失败: ' + error.message);
            }
        }

        // 显示测试区域
        function testUserApi(userId) {
            const testArea = document.getElementById(\`testArea_\${userId}\`);
            testArea.style.display = testArea.style.display === 'none' ? 'block' : 'none';
        }

        // 执行API测试
        async function executeApiTest(userId) {
            const to = document.getElementById(\`testTo_\${userId}\`).value;
            const subject = document.getElementById(\`testSubject_\${userId}\`).value;
            const text = document.getElementById(\`testContent_\${userId}\`).value;
            const resultDiv = document.getElementById(\`testResult_\${userId}\`);

            if (!to || !subject || !text) {
                resultDiv.innerHTML = '<div style="color: red; padding: 10px;">请填写完整信息</div>';
                return;
            }

            try {
                const tokenResponse = await apiRequest(\`/user-token/\${userId}\`);
                if (!tokenResponse.success || !tokenResponse.token) {
                    resultDiv.innerHTML = '<div style="color: red; padding: 10px;">请先生成API Token</div>';
                    return;
                }

                const response = await fetch(\`\${API_BASE}/send-simple\`, {
                    method: 'POST',
                    headers: {
                        'X-API-Token': tokenResponse.token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ to, subject, text })
                });

                const result = await response.json();

                if (result.success) {
                    resultDiv.innerHTML = '<div style="color: green; padding: 10px;">✅ 测试成功！邮件ID: ' + result.id + '</div>';
                } else {
                    resultDiv.innerHTML = '<div style="color: red; padding: 10px;">❌ 测试失败: ' + result.error + '</div>';
                }
            } catch (error) {
                resultDiv.innerHTML = '<div style="color: red; padding: 10px;">❌ 测试失败: ' + error.message + '</div>';
            }
        }

        // 显示API文档弹窗
        function showApiDocModal() {
            const docModal = document.createElement('div');
            docModal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1001; display: flex; align-items: center; justify-content: center;';

            docModal.innerHTML = \`
                <div style="background: white; border-radius: 10px; width: 90%; max-width: 800px; max-height: 80vh; overflow-y: auto;">
                    <div style="padding: 20px; border-bottom: 1px solid #eee;">
                        <h3>API 使用文档</h3>
                        <button onclick="this.closest('div[style*=position]').remove()" style="float: right; margin-top: -30px; border: none; background: none; font-size: 20px; cursor: pointer;">×</button>
                    </div>
                    <div style="padding: 20px;">
                        <h5>简单邮件发送API</h5>
                        <p><strong>端点:</strong> <code>POST https://${env.DOMAIN || 'mail.yourdomain.com'}/api/send-simple</code></p>

                        <h6>请求头:</h6>
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">X-API-Token: YOUR_API_TOKEN
Content-Type: application/json</pre>

                        <h6>请求体:</h6>
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">{
  "to": "recipient@example.com",
  "subject": "邮件主题",
  "text": "邮件内容（纯文本）",
  "html": "邮件内容（HTML格式）（可选）"
}</pre>
                        <p><strong>注意:</strong> 发件人将自动使用API Token对应用户的邮箱地址</p>

                        <h6>响应示例:</h6>
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">{
  "success": true,
  "id": "email-id-here",
  "data": {...}
}</pre>

                        <h6>cURL示例:</h6>
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">curl -X POST https://${env.DOMAIN || 'mail.yourdomain.com'}/api/send-simple \\\\
  -H "X-API-Token: YOUR_API_TOKEN" \\\\
  -H "Content-Type: application/json" \\\\
  -d '{
    "to": "recipient@example.com",
    "subject": "测试邮件",
    "text": "这是测试邮件内容"
  }'</pre>
                    </div>
                </div>
            \`;

            document.body.appendChild(docModal);
        }

        // API 请求工具函数
        async function apiRequest(endpoint, method = 'GET', data = null) {
            const options = {
                method,
                headers: {
                    'Authorization': \`Bearer \${authToken}\`,
                    'Content-Type': 'application/json'
                }
            };

            if (data) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(\`\${API_BASE}\${endpoint}\`, options);
            return await response.json();
        }

        // Hash 路由处理
        function handleHashChange() {
            const hash = window.location.hash.replace('#', '');
            const validTabs = ['dashboard', 'emails', 'users', 'aliases', 'temp-emails', 'send'];

            if (validTabs.includes(hash)) {
                showTab(hash, false); // 不更新 hash，避免循环
            } else {
                // 默认显示仪表板
                showTab('dashboard', false);
            }
        }

        // 监听 hash 变化
        window.addEventListener('hashchange', handleHashChange);

        // 页面加载完成后的操作
        document.addEventListener('DOMContentLoaded', function() {
            // 初始化路由
            handleHashChange();

            // 检查是否有保存的登录状态
            const savedToken = localStorage.getItem('authToken');
            if (savedToken) {
                authToken = savedToken;
                // 验证 token 是否仍然有效
                validateSavedToken();
            }
        });

        // 验证保存的 token
        async function validateSavedToken() {
            try {
                const response = await apiRequest('/usage-stats');
                if (response.success) {
                    // Token 有效，显示主界面
                    document.getElementById('loginSection').classList.add('hidden');
                    document.getElementById('mainSection').classList.remove('hidden');
                    handleHashChange(); // 加载当前 hash 对应的页面
                } else {
                    // Token 无效，清除并显示登录界面
                    localStorage.removeItem('authToken');
                    authToken = '';
                }
            } catch (error) {
                // Token 无效，清除并显示登录界面
                localStorage.removeItem('authToken');
                authToken = '';
            }
        }

        // 临时邮箱相关函数
        async function loadTempEmails() {
            try {
                const response = await apiRequest('/temp-email/admin/all');
                const tempEmailsDiv = document.getElementById('tempEmailsList');

                if (response.tempEmails && response.tempEmails.length > 0) {
                    tempEmailsDiv.innerHTML = \`
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>邮箱地址</th>
                                    <th>用途</th>
                                    <th>创建时间</th>
                                    <th>过期时间</th>
                                    <th>收件数</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${response.tempEmails.map(tempEmail => \`
                                    <tr>
                                        <td><code style="font-size: 12px;">\${tempEmail.email}</code></td>
                                        <td>\${getPurposeText(tempEmail.purpose)}</td>
                                        <td>\${new Date(tempEmail.created_at).toLocaleString()}</td>
                                        <td>\${new Date(tempEmail.expires_at).toLocaleString()}</td>
                                        <td>\${tempEmail.email_count || 0}</td>
                                        <td>
                                            <button onclick="viewTempEmailDetails('\${tempEmail.email}')" class="btn btn-primary" style="font-size: 12px; padding: 4px 8px;">查看</button>
                                            <button onclick="cleanupTempEmail('\${tempEmail.email}')" class="btn btn-danger" style="font-size: 12px; padding: 4px 8px;">清理</button>
                                        </td>
                                    </tr>
                                \`).join('')}
                            </tbody>
                        </table>
                    \`;
                } else {
                    tempEmailsDiv.innerHTML = '<p>暂无临时邮箱</p>';
                }
            } catch (error) {
                document.getElementById('tempEmailsList').innerHTML = '<p style="color: red;">加载失败: ' + error.message + '</p>';
            }
        }

        function getPurposeText(purpose) {
            const purposeMap = {
                'general': '通用',
                'signup': '注册验证',
                'verification': '邮箱验证'
            };
            return purposeMap[purpose] || purpose;
        }

        function showCreateTempEmailForm() {
            document.getElementById('createTempEmailForm').classList.remove('hidden');
            // 当选择注册验证时显示服务名称字段
            document.getElementById('tempEmailPurpose').addEventListener('change', function() {
                const serviceGroup = document.getElementById('serviceNameGroup');
                if (this.value === 'signup') {
                    serviceGroup.style.display = 'block';
                } else {
                    serviceGroup.style.display = 'none';
                }
            });
        }

        function hideCreateTempEmailForm() {
            document.getElementById('createTempEmailForm').classList.add('hidden');
        }

        async function createTempEmail() {
            const purpose = document.getElementById('tempEmailPurpose').value;
            const expiryHours = parseInt(document.getElementById('tempEmailExpiry').value);
            const maxEmails = parseInt(document.getElementById('tempEmailMaxEmails').value);
            const serviceName = document.getElementById('tempEmailServiceName').value;

            try {
                let endpoint = '/temp-email/create';
                let requestBody = { expiryHours, purpose, maxEmails };

                if (purpose === 'signup') {
                    endpoint = '/temp-email/create-signup';
                    requestBody = { serviceName };
                } else if (purpose === 'verification') {
                    endpoint = '/temp-email/create-verification';
                    requestBody = { verificationType: 'email' };
                }

                const response = await apiRequest(endpoint, 'POST', requestBody);

                if (response.success) {
                    showSuccess('临时邮箱创建成功！');
                    showTempEmailResult(response);
                    hideCreateTempEmailForm();
                    loadTempEmails();
                } else {
                    alert('创建失败: ' + response.error);
                }
            } catch (error) {
                alert('创建失败: ' + error.message);
            }
        }

        function showTempEmailResult(result) {
            const modal = document.createElement('div');
            modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';

            modal.innerHTML = \`
                <div style="background: white; border-radius: 10px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;">
                    <div style="padding: 20px; border-bottom: 1px solid #eee;">
                        <h3>✅ 临时邮箱创建成功</h3>
                        <button onclick="this.closest('div[style*=position]').remove()" style="float: right; margin-top: -30px; border: none; background: none; font-size: 20px; cursor: pointer;">×</button>
                    </div>
                    <div style="padding: 20px;">
                        <div style="margin-bottom: 15px;">
                            <strong>邮箱地址:</strong>
                            <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 5px; font-family: monospace; font-size: 14px; word-break: break-all;">
                                \${result.email}
                            </div>
                        </div>

                        <div style="margin-bottom: 15px;">
                            <strong>访问令牌:</strong>
                            <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 5px; font-family: monospace; font-size: 12px; word-break: break-all;">
                                \${result.accessToken}
                            </div>
                        </div>

                        <div style="margin-bottom: 15px;">
                            <strong>过期时间:</strong> \${new Date(result.expiresAt).toLocaleString()}
                        </div>

                        <div style="margin-bottom: 15px;">
                            <strong>用途:</strong> \${getPurposeText(result.purpose)}
                        </div>

                        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-top: 15px;">
                            <strong>⚠️ 重要提示:</strong><br>
                            请妥善保存邮箱地址和访问令牌，访问令牌用于查看收到的邮件。邮箱将在过期时间后自动失效。
                        </div>

                        <div style="margin-top: 20px;">
                            <button onclick="copyToClipboard('\${result.email}')" class="btn btn-primary">复制邮箱地址</button>
                            <button onclick="copyToClipboard('\${result.accessToken}')" class="btn btn-secondary">复制访问令牌</button>
                            <button onclick="setViewerData('\${result.email}', '\${result.accessToken}')" class="btn btn-success">在查看器中打开</button>
                        </div>
                    </div>
                </div>
            \`;

            document.body.appendChild(modal);
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showSuccess('已复制到剪贴板');
            }).catch(() => {
                // 备用方法
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showSuccess('已复制到剪贴板');
            });
        }

        function setViewerData(email, token) {
            document.getElementById('viewTempEmail').value = email;
            document.getElementById('viewTempEmailToken').value = token;
            // 关闭模态框
            const modal = document.querySelector('div[style*="position: fixed"]');
            if (modal) modal.remove();
            showSuccess('数据已填入查看器');
        }

        async function viewTempEmailEmails() {
            const email = document.getElementById('viewTempEmail').value;
            const token = document.getElementById('viewTempEmailToken').value;

            if (!email || !token) {
                alert('请输入邮箱地址和访问令牌');
                return;
            }

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(email)}/emails?token=\${encodeURIComponent(token)}\`);
                const result = await response.json();

                if (result.success) {
                    showTempEmailEmails(result.emails, email);
                } else {
                    alert('获取邮件失败: ' + result.error);
                }
            } catch (error) {
                alert('获取邮件失败: ' + error.message);
            }
        }

        function showTempEmailEmails(emails, tempEmail) {
            const viewer = document.getElementById('tempEmailViewer');
            const title = document.getElementById('tempEmailViewerTitle');
            const emailsList = document.getElementById('tempEmailEmailsList');

            title.textContent = \`邮件列表 - \${tempEmail}\`;

            if (emails && emails.length > 0) {
                emailsList.innerHTML = \`
                    <table class="table">
                        <thead>
                            <tr>
                                <th>发件人</th>
                                <th>主题</th>
                                <th>时间</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            \${emails.map(email => \`
                                <tr>
                                    <td>\${email.from_email}</td>
                                    <td>\${email.subject || '无主题'}</td>
                                    <td>\${new Date(email.created_at).toLocaleString()}</td>
                                    <td>
                                        <button onclick="viewEmailContent('\${email.message_id}', '\${tempEmail}')" class="btn btn-primary" style="font-size: 12px; padding: 4px 8px;">查看</button>
                                        <button onclick="markTempEmailAsRead('\${email.message_id}', '\${tempEmail}')" class="btn btn-success" style="font-size: 12px; padding: 4px 8px;">标记已读</button>
                                        <button onclick="deleteTempEmail('\${email.message_id}', '\${tempEmail}')" class="btn btn-danger" style="font-size: 12px; padding: 4px 8px;">删除</button>
                                    </td>
                                </tr>
                            \`).join('')}
                        </tbody>
                    </table>
                \`;
            } else {
                emailsList.innerHTML = '<p>暂无邮件</p>';
            }

            viewer.classList.remove('hidden');
        }

        function viewEmailContent(messageId, tempEmail) {
            // 这里可以实现邮件内容查看功能
            alert('邮件内容查看功能 - Message ID: ' + messageId);
        }

        async function markTempEmailAsRead(messageId, tempEmail) {
            const token = document.getElementById('viewTempEmailToken').value;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(tempEmail)}/mark-read\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: token, messageId })
                });

                const result = await response.json();

                if (result.success) {
                    showSuccess('邮件已标记为已读');
                    viewTempEmailEmails(); // 刷新列表
                } else {
                    alert('操作失败: ' + result.error);
                }
            } catch (error) {
                alert('操作失败: ' + error.message);
            }
        }

        async function deleteTempEmail(messageId, tempEmail) {
            if (!confirm('确认删除此邮件？')) return;

            const token = document.getElementById('viewTempEmailToken').value;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(tempEmail)}/delete-email\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: token, messageId })
                });

                const result = await response.json();

                if (result.success) {
                    showSuccess('邮件已删除');
                    viewTempEmailEmails(); // 刷新列表
                } else {
                    alert('删除失败: ' + result.error);
                }
            } catch (error) {
                alert('删除失败: ' + error.message);
            }
        }

        async function extendTempEmailTime() {
            const email = document.getElementById('viewTempEmail').value;
            const token = document.getElementById('viewTempEmailToken').value;

            if (!email || !token) {
                alert('请输入邮箱地址和访问令牌');
                return;
            }

            const additionalHours = prompt('延长多少小时？', '24');
            if (!additionalHours || isNaN(additionalHours)) return;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(email)}/extend\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: token, additionalHours: parseInt(additionalHours) })
                });

                const result = await response.json();

                if (result.success) {
                    showSuccess('时间延长成功，新过期时间: ' + new Date(result.newExpiryDate).toLocaleString());
                } else {
                    alert('延长失败: ' + result.error);
                }
            } catch (error) {
                alert('延长失败: ' + error.message);
            }
        }

        async function showTempEmailStats() {
            const email = document.getElementById('viewTempEmail').value;
            const token = document.getElementById('viewTempEmailToken').value;

            if (!email || !token) {
                alert('请输入邮箱地址和访问令牌');
                return;
            }

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(email)}/stats?token=\${encodeURIComponent(token)}\`);
                const result = await response.json();

                if (result.success) {
                    const modal = document.createElement('div');
                    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center;';

                    modal.innerHTML = \`
                        <div style="background: white; border-radius: 10px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;">
                            <div style="padding: 20px; border-bottom: 1px solid #eee;">
                                <h3>📊 临时邮箱统计</h3>
                                <button onclick="this.closest('div[style*=position]').remove()" style="float: right; margin-top: -30px; border: none; background: none; font-size: 20px; cursor: pointer;">×</button>
                            </div>
                            <div style="padding: 20px;">
                                <div style="margin-bottom: 15px;">
                                    <strong>邮箱地址:</strong> \${result.tempEmail.email}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>用途:</strong> \${getPurposeText(result.tempEmail.purpose)}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>创建时间:</strong> \${new Date(result.tempEmail.created_at).toLocaleString()}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>过期时间:</strong> \${new Date(result.tempEmail.expires_at).toLocaleString()}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>最大邮件数:</strong> \${result.tempEmail.max_emails}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>已收邮件数:</strong> \${result.tempEmail.received_count}
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <strong>使用记录:</strong>
                                    <div style="max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 5px;">
                                        \${result.usage.map(record => \`
                                            <div style="margin-bottom: 5px; font-size: 12px;">
                                                \${new Date(record.timestamp).toLocaleString()} - \${record.action}
                                                \${record.details ? \`: \${record.details}\` : ''}
                                            </div>
                                        \`).join('')}
                                    </div>
                                </div>
                            </div>
                        </div>
                    \`;

                    document.body.appendChild(modal);
                } else {
                    alert('获取统计失败: ' + result.error);
                }
            } catch (error) {
                alert('获取统计失败: ' + error.message);
            }
        }

        function refreshTempEmails() {
            viewTempEmailEmails();
        }

        async function viewTempEmailDetails(email) {
            // 这里可以实现临时邮箱详情查看
            alert('查看临时邮箱详情: ' + email);
        }

        async function cleanupTempEmail(email) {
            if (!confirm('确认清理此临时邮箱？此操作将使其失效。')) return;

            try {
                const response = await apiRequest('/temp-email/admin/cleanup', 'POST');
                if (response.success) {
                    showSuccess('清理完成');
                    loadTempEmails();
                } else {
                    alert('清理失败: ' + response.error);
                }
            } catch (error) {
                alert('清理失败: ' + error.message);
            }
        }

        // 退出登录
        function logout() {
            // 清除 token
            authToken = '';
            localStorage.removeItem('authToken');

            // 显示登录界面
            document.getElementById('mainSection').classList.add('hidden');
            document.getElementById('loginSection').classList.remove('hidden');

            // 清空表单
            document.getElementById('email').value = '';
            document.getElementById('password').value = '';

            // 清除可能显示的错误信息
            const errorDiv = document.getElementById('loginError');
            if (errorDiv) {
                errorDiv.classList.add('hidden');
            }

            // 重置 hash 到首页
            window.location.hash = '';
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

async function handleTempEmailInterface() {
    // 读取临时邮箱HTML文件内容
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>临时邮箱 - KKMail</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(45deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .main-content {
            padding: 30px;
        }

        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }

        .section h3 {
            margin-bottom: 15px;
            color: #333;
            border-bottom: 2px solid #4facfe;
            padding-bottom: 5px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }

        .form-control:focus {
            outline: none;
            border-color: #4facfe;
            box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s;
            margin-right: 10px;
            margin-bottom: 10px;
            text-decoration: none;
            display: inline-block;
        }

        .btn-primary {
            background: linear-gradient(45deg, #4facfe 0%, #00f2fe 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(79, 172, 254, 0.3);
        }

        .btn-success {
            background: #28a745;
            color: white;
        }

        .btn-warning {
            background: #ffc107;
            color: #212529;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .email-display {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #4facfe;
            font-family: monospace;
            font-size: 18px;
            font-weight: bold;
            color: #4facfe;
            word-break: break-all;
            margin: 15px 0;
            position: relative;
        }

        .copy-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 5px 10px;
            font-size: 12px;
        }

        .token-display {
            background: #fff3cd;
            border: 2px solid #ffeaa7;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            word-break: break-all;
            margin: 15px 0;
            position: relative;
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }

        .hidden {
            display: none;
        }

        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }

        .email-item {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            transition: all 0.3s;
        }

        .email-item:hover {
            border-color: #4facfe;
            box-shadow: 0 2px 10px rgba(79, 172, 254, 0.1);
        }

        .email-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }

        .email-from {
            font-weight: bold;
            color: #333;
        }

        .email-time {
            color: #666;
            font-size: 14px;
        }

        .email-subject {
            font-size: 16px;
            color: #4facfe;
            margin-bottom: 10px;
        }

        .email-preview {
            color: #666;
            font-size: 14px;
            line-height: 1.4;
            max-height: 60px;
            overflow: hidden;
        }

        .email-actions {
            margin-top: 10px;
            text-align: right;
        }

        .countdown {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            border-radius: 8px;
            margin: 15px 0;
            text-align: center;
            font-weight: bold;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .stat-item {
            background: linear-gradient(45deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
        }

        .stat-label {
            font-size: 14px;
            opacity: 0.9;
        }

        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 2rem;
            }

            .main-content {
                padding: 20px;
            }

            .email-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .email-actions {
                text-align: left;
            }

            .copy-btn {
                position: static;
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 临时邮箱服务</h1>
            <p>一次性邮箱地址，用于注册验证和接收临时邮件</p>
        </div>

        <div class="main-content">
            <!-- 创建临时邮箱 -->
            <div class="section">
                <h3>🆕 创建临时邮箱</h3>
                <div class="form-group">
                    <label>邮箱用途</label>
                    <select id="purposeSelect" class="form-control">
                        <option value="general">通用临时邮箱 (24小时)</option>
                        <option value="signup">注册验证邮箱 (1小时)</option>
                        <option value="verification">邮箱验证 (2小时)</option>
                    </select>
                </div>
                <div id="serviceNameGroup" class="form-group hidden">
                    <label>服务名称 (可选)</label>
                    <input type="text" id="serviceName" class="form-control" placeholder="例如：GitHub, Gmail, Facebook">
                </div>
                <button onclick="createTempEmail()" class="btn btn-primary">创建临时邮箱</button>
            </div>

            <!-- 当前邮箱信息 -->
            <div id="emailSection" class="section hidden">
                <h3>📨 当前邮箱</h3>
                <div id="emailDisplay" class="email-display">
                    <button onclick="copyEmail()" class="btn btn-secondary copy-btn">复制</button>
                </div>
                <div id="tokenDisplay" class="token-display">
                    <strong>访问令牌：</strong><span id="tokenText"></span>
                    <button onclick="copyToken()" class="btn btn-secondary copy-btn">复制</button>
                </div>
                <div id="countdown" class="countdown"></div>

                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-number" id="emailCount">0</div>
                        <div class="stat-label">收到邮件</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" id="maxEmails">-</div>
                        <div class="stat-label">最大邮件数</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" id="remainingTime">-</div>
                        <div class="stat-label">剩余时间</div>
                    </div>
                </div>

                <div style="text-align: center; margin: 20px 0;">
                    <button onclick="refreshEmails()" class="btn btn-primary">刷新邮件</button>
                    <button onclick="extendTime()" class="btn btn-warning">延长时间</button>
                    <button onclick="showStats()" class="btn btn-secondary">查看统计</button>
                    <button onclick="resetEmail()" class="btn btn-danger">创建新邮箱</button>
                </div>
            </div>

            <!-- 邮件列表 -->
            <div id="emailsSection" class="section hidden">
                <h3>📬 收件箱</h3>
                <div id="emailsList" class="loading">暂无邮件</div>
            </div>

            <!-- 查看现有邮箱 -->
            <div class="section">
                <h3>🔍 查看现有邮箱</h3>
                <div class="form-group">
                    <label>邮箱地址</label>
                    <input type="email" id="existingEmail" class="form-control" placeholder="输入临时邮箱地址">
                </div>
                <div class="form-group">
                    <label>访问令牌</label>
                    <input type="text" id="existingToken" class="form-control" placeholder="输入访问令牌">
                </div>
                <button onclick="loadExistingEmail()" class="btn btn-primary">查看邮箱</button>
            </div>

            <!-- 使用说明 -->
            <div class="section">
                <h3>📖 使用说明</h3>
                <div class="alert alert-info">
                    <strong>🛡️ 隐私保护：</strong><br>
                    • 临时邮箱会在过期时间后自动删除<br>
                    • 不会存储任何个人信息<br>
                    • 请勿用于重要账户注册<br><br>

                    <strong>📝 使用步骤：</strong><br>
                    1. 选择邮箱用途并点击"创建临时邮箱"<br>
                    2. 复制生成的邮箱地址用于注册或验证<br>
                    3. 返回此页面查看收到的邮件<br>
                    4. 妥善保存访问令牌以便后续查看<br><br>

                    <strong>⚠️ 重要提示：</strong><br>
                    • 邮箱过期后无法恢复<br>
                    • 访问令牌用于邮件查看权限<br>
                    • 建议及时处理重要邮件
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentEmail = '';
        let currentToken = '';
        let expiresAt = null;
        let countdownInterval = null;
        const API_BASE = '/api';

        // 监听用途选择变化
        document.getElementById('purposeSelect').addEventListener('change', function() {
            const serviceGroup = document.getElementById('serviceNameGroup');
            if (this.value === 'signup') {
                serviceGroup.classList.remove('hidden');
            } else {
                serviceGroup.classList.add('hidden');
            }
        });

        // 创建临时邮箱
        async function createTempEmail() {
            const purpose = document.getElementById('purposeSelect').value;
            const serviceName = document.getElementById('serviceName').value;

            try {
                let endpoint = '/temp-email/create';
                let requestBody = {};

                if (purpose === 'signup') {
                    endpoint = '/temp-email/create-signup';
                    requestBody = { serviceName: serviceName || 'Unknown Service' };
                } else if (purpose === 'verification') {
                    endpoint = '/temp-email/create-verification';
                    requestBody = { verificationType: 'email' };
                } else {
                    endpoint = '/temp-email/create';
                    requestBody = {
                        expiryHours: 24,
                        purpose: 'general',
                        maxEmails: 50
                    };
                }

                const response = await fetch(API_BASE + endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(requestBody)
                });

                const result = await response.json();

                if (result.success) {
                    setupEmail(result.email, result.accessToken, result.expiresAt, result.maxEmails);
                    showSuccess('临时邮箱创建成功！');
                } else {
                    showError('创建失败: ' + result.error);
                }
            } catch (error) {
                showError('创建失败: ' + error.message);
            }
        }

        // 设置邮箱信息
        function setupEmail(email, token, expires, maxEmails) {
            currentEmail = email;
            currentToken = token;
            expiresAt = new Date(expires);

            document.getElementById('emailDisplay').firstChild.textContent = email;
            document.getElementById('tokenText').textContent = token;
            document.getElementById('maxEmails').textContent = maxEmails || 50;

            document.getElementById('emailSection').classList.remove('hidden');
            document.getElementById('emailsSection').classList.remove('hidden');

            startCountdown();
            refreshEmails();

            // 滚动到邮箱区域
            document.getElementById('emailSection').scrollIntoView({ behavior: 'smooth' });
        }

        // 开始倒计时
        function startCountdown() {
            if (countdownInterval) {
                clearInterval(countdownInterval);
            }

            countdownInterval = setInterval(() => {
                const now = new Date();
                const timeLeft = expiresAt - now;

                if (timeLeft <= 0) {
                    document.getElementById('countdown').innerHTML = '⏰ 邮箱已过期';
                    document.getElementById('remainingTime').textContent = '已过期';
                    clearInterval(countdownInterval);
                    return;
                }

                const hours = Math.floor(timeLeft / (1000 * 60 * 60));
                const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);

                document.getElementById('countdown').innerHTML =
                    \`⏰ 邮箱将在 <strong>\${hours}小时 \${minutes}分钟 \${seconds}秒</strong> 后过期\`;
                document.getElementById('remainingTime').textContent = \`\${hours}:\${minutes.toString().padStart(2, '0')}\`;
            }, 1000);
        }

        // 刷新邮件
        async function refreshEmails() {
            if (!currentEmail || !currentToken) return;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(currentEmail)}/emails?token=\${encodeURIComponent(currentToken)}\`);
                const result = await response.json();

                if (result.success) {
                    displayEmails(result.emails);
                    document.getElementById('emailCount').textContent = result.emails.length;
                } else {
                    showError('获取邮件失败: ' + result.error);
                }
            } catch (error) {
                showError('获取邮件失败: ' + error.message);
            }
        }

        // 显示邮件列表
        function displayEmails(emails) {
            const emailsList = document.getElementById('emailsList');

            if (!emails || emails.length === 0) {
                emailsList.innerHTML = '<div class="alert alert-info">暂无邮件，请等待邮件到达...</div>';
                return;
            }

            emailsList.innerHTML = emails.map(email => \`
                <div class="email-item">
                    <div class="email-header">
                        <div class="email-from">来自: \${email.from_email}</div>
                        <div class="email-time">\${new Date(email.created_at).toLocaleString()}</div>
                    </div>
                    <div class="email-subject">\${email.subject || '无主题'}</div>
                    <div class="email-preview">\${getEmailPreview(email.body_text)}</div>
                    <div class="email-actions">
                        <button onclick="viewEmail('\${email.message_id}')" class="btn btn-primary">查看详情</button>
                        <button onclick="markAsRead('\${email.message_id}')" class="btn btn-success">标记已读</button>
                        <button onclick="deleteEmail('\${email.message_id}')" class="btn btn-danger">删除</button>
                    </div>
                </div>
            \`).join('');
        }

        // 获取邮件预览
        function getEmailPreview(text) {
            if (!text) return '(无内容)';
            return text.length > 200 ? text.substring(0, 200) + '...' : text;
        }

        // 查看邮件详情
        function viewEmail(messageId) {
            alert('查看邮件详情功能 - Message ID: ' + messageId);
            // 这里可以实现邮件详情弹窗
        }

        // 标记已读
        async function markAsRead(messageId) {
            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(currentEmail)}/mark-read\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: currentToken, messageId })
                });

                const result = await response.json();

                if (result.success) {
                    showSuccess('邮件已标记为已读');
                    refreshEmails();
                } else {
                    showError('操作失败: ' + result.error);
                }
            } catch (error) {
                showError('操作失败: ' + error.message);
            }
        }

        // 删除邮件
        async function deleteEmail(messageId) {
            if (!confirm('确认删除此邮件？')) return;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(currentEmail)}/delete-email\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: currentToken, messageId })
                });

                const result = await response.json();

                if (result.success) {
                    showSuccess('邮件已删除');
                    refreshEmails();
                } else {
                    showError('删除失败: ' + result.error);
                }
            } catch (error) {
                showError('删除失败: ' + error.message);
            }
        }

        // 延长时间
        async function extendTime() {
            const hours = prompt('延长多少小时？(1-48)', '24');
            if (!hours || isNaN(hours) || hours < 1 || hours > 48) return;

            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(currentEmail)}/extend\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ accessToken: currentToken, additionalHours: parseInt(hours) })
                });

                const result = await response.json();

                if (result.success) {
                    expiresAt = new Date(result.newExpiryDate);
                    showSuccess(\`时间延长成功！新过期时间: \${expiresAt.toLocaleString()}\`);
                    startCountdown();
                } else {
                    showError('延长失败: ' + result.error);
                }
            } catch (error) {
                showError('延长失败: ' + error.message);
            }
        }

        // 查看统计
        async function showStats() {
            try {
                const response = await fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(currentEmail)}/stats?token=\${encodeURIComponent(currentToken)}\`);
                const result = await response.json();

                if (result.success) {
                    const statsText = \`
邮箱地址: \${result.tempEmail.email}
创建时间: \${new Date(result.tempEmail.created_at).toLocaleString()}
过期时间: \${new Date(result.tempEmail.expires_at).toLocaleString()}
最大邮件数: \${result.tempEmail.max_emails}
已收邮件数: \${result.tempEmail.received_count}
用途: \${getPurposeText(result.tempEmail.purpose)}

最近使用记录:
\${result.usage.slice(0, 5).map(record =>
    \`\${new Date(record.timestamp).toLocaleString()} - \${record.action}\`
).join('\\n')}
                    \`;
                    alert(statsText);
                } else {
                    showError('获取统计失败: ' + result.error);
                }
            } catch (error) {
                showError('获取统计失败: ' + error.message);
            }
        }

        // 重置邮箱
        function resetEmail() {
            if (!confirm('确认创建新的临时邮箱？当前邮箱信息将丢失。')) return;

            currentEmail = '';
            currentToken = '';
            expiresAt = null;

            if (countdownInterval) {
                clearInterval(countdownInterval);
            }

            document.getElementById('emailSection').classList.add('hidden');
            document.getElementById('emailsSection').classList.add('hidden');
        }

        // 加载现有邮箱
        function loadExistingEmail() {
            const email = document.getElementById('existingEmail').value.trim();
            const token = document.getElementById('existingToken').value.trim();

            if (!email || !token) {
                showError('请输入邮箱地址和访问令牌');
                return;
            }

            // 简单验证邮箱格式
            if (!email.includes('@')) {
                showError('请输入有效的邮箱地址');
                return;
            }

            currentEmail = email;
            currentToken = token;

            // 尝试获取邮箱信息
            refreshEmails().then(() => {
                // 如果成功获取邮件，显示邮箱区域
                document.getElementById('emailDisplay').firstChild.textContent = email;
                document.getElementById('tokenText').textContent = token;
                document.getElementById('emailSection').classList.remove('hidden');
                document.getElementById('emailsSection').classList.remove('hidden');

                // 尝试获取统计信息来确定过期时间
                fetch(\`\${API_BASE}/temp-email/\${encodeURIComponent(email)}/stats?token=\${encodeURIComponent(token)}\`)
                    .then(response => response.json())
                    .then(result => {
                        if (result.success) {
                            expiresAt = new Date(result.tempEmail.expires_at);
                            document.getElementById('maxEmails').textContent = result.tempEmail.max_emails;
                            startCountdown();
                        }
                    })
                    .catch(() => {
                        // 如果无法获取统计信息，使用默认设置
                        document.getElementById('maxEmails').textContent = '未知';
                        document.getElementById('remainingTime').textContent = '未知';
                    });

                showSuccess('邮箱加载成功！');
                document.getElementById('emailSection').scrollIntoView({ behavior: 'smooth' });
            }).catch(() => {
                showError('无法加载邮箱，请检查邮箱地址和访问令牌');
            });
        }

        // 复制邮箱地址
        function copyEmail() {
            copyToClipboard(currentEmail, '邮箱地址已复制到剪贴板');
        }

        // 复制访问令牌
        function copyToken() {
            copyToClipboard(currentToken, '访问令牌已复制到剪贴板');
        }

        // 复制到剪贴板
        function copyToClipboard(text, message) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showSuccess(message);
                }).catch(() => {
                    fallbackCopy(text, message);
                });
            } else {
                fallbackCopy(text, message);
            }
        }

        // 备用复制方法
        function fallbackCopy(text, message) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                showSuccess(message);
            } catch (err) {
                showError('复制失败，请手动复制');
            }
            document.body.removeChild(textArea);
        }

        // 显示成功消息
        function showSuccess(message) {
            showMessage(message, 'success');
        }

        // 显示错误消息
        function showError(message) {
            showMessage(message, 'danger');
        }

        // 显示消息
        function showMessage(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = \`alert alert-\${type}\`;
            alertDiv.textContent = message;
            alertDiv.style.position = 'fixed';
            alertDiv.style.top = '20px';
            alertDiv.style.right = '20px';
            alertDiv.style.zIndex = '9999';
            alertDiv.style.minWidth = '300px';
            alertDiv.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';

            document.body.appendChild(alertDiv);

            setTimeout(() => {
                alertDiv.remove();
            }, 4000);
        }

        // 获取用途文本
        function getPurposeText(purpose) {
            const purposeMap = {
                'general': '通用',
                'signup': '注册验证',
                'verification': '邮箱验证'
            };
            return purposeMap[purpose] || purpose;
        }

        // 页面加载时的自动刷新
        setInterval(() => {
            if (currentEmail && currentToken) {
                refreshEmails();
            }
        }, 30000); // 每30秒自动刷新一次
    </script>
</body>
</html>`;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

async function handleGetEmail(request, auth, db, emailId, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const email = await db.prepare(`
            SELECT * FROM emails WHERE id = ?
        `).bind(emailId).first();

        if (!email) {
            return new Response(JSON.stringify({ error: 'Email not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        return new Response(JSON.stringify({
            success: true,
            email
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleSendEmailSimple(request, resend, db, apiToken, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 检查API Token
        const authHeader = request.headers.get('X-API-Token') || request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'API Token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const providedToken = authHeader.replace('Bearer ', '').replace('Token ', '');

        // 查找token对应的用户
        const userToken = await db.prepare(`
            SELECT u.id, u.email, u.is_active
            FROM users u
            JOIN api_tokens at ON u.id = at.user_id
            WHERE at.token_hash = ? AND u.is_active = 1
              AND (at.expires_at IS NULL OR at.expires_at > datetime('now'))
        `).bind(await hashString(providedToken)).first();

        if (!userToken) {
            return new Response(JSON.stringify({ error: 'Invalid API Token' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const emailData = await request.json();

        // 验证必需字段
        if (!emailData.to || !emailData.subject) {
            return new Response(JSON.stringify({ error: 'Missing required fields: to, subject' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 检查发送限制
        const limitCheck = await checkSendingLimits(db);
        if (!limitCheck.allowed) {
            return new Response(JSON.stringify({
                error: 'Sending limit exceeded',
                message: limitCheck.message
            }), {
                status: 429,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 使用token对应用户的邮箱作为发件人
        emailData.from = userToken.email;

        const result = await resend.sendEmail(emailData);

        // 如果发送成功，更新用量
        if (result.success) {
            await updateUsageCount(db);
        }

        // 记录发送日志
        await db.prepare(`
            INSERT INTO send_logs (from_email, to_email, subject, status, resend_id)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
            emailData.from,
            Array.isArray(emailData.to) ? emailData.to.join(',') : emailData.to,
            emailData.subject || '',
            result.success ? 'sent' : 'failed',
            result.id || null
        ).run();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleEmailStatus(request, resend, auth, emailId, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await resend.getEmail(emailId);

        return new Response(JSON.stringify(result), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetUserToken(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 查找用户的API token
        const apiToken = await db.prepare(`
            SELECT name FROM api_tokens
            WHERE user_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
            ORDER BY created_at DESC LIMIT 1
        `).bind(authResult.user.id).first();

        return new Response(JSON.stringify({
            success: true,
            token: apiToken ? apiToken.name : null
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGenerateUserToken(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 生成新的API token
        const newToken = generateRandomToken();
        const tokenHash = await hashString(newToken);

        // 删除旧的token
        await db.prepare(`DELETE FROM api_tokens WHERE user_id = ?`).bind(authResult.user.id).run();

        // 插入新的token
        await db.prepare(`
            INSERT INTO api_tokens (token_hash, user_id, name, permissions)
            VALUES (?, ?, ?, 'api')
        `).bind(tokenHash, authResult.user.id, newToken).run();

        return new Response(JSON.stringify({
            success: true,
            token: newToken
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllUserTokens(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 获取所有用户的API token
        const tokens = await db.prepare(`
            SELECT user_id, name FROM api_tokens
            WHERE expires_at IS NULL OR expires_at > datetime('now')
        `).all();

        const tokenMap = {};
        if (tokens.results) {
            tokens.results.forEach(token => {
                tokenMap[token.user_id] = token.name;
            });
        }

        return new Response(JSON.stringify({
            success: true,
            tokens: tokenMap
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetUserTokenById(request, auth, db, userId, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 获取指定用户的API token
        const apiToken = await db.prepare(`
            SELECT name FROM api_tokens
            WHERE user_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
            ORDER BY created_at DESC LIMIT 1
        `).bind(userId).first();

        return new Response(JSON.stringify({
            success: true,
            token: apiToken ? apiToken.name : null
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGenerateUserTokenById(request, auth, db, userId, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 生成新的API token
        const newToken = generateRandomToken();
        const tokenHash = await hashString(newToken);

        // 删除旧的token
        await db.prepare(`DELETE FROM api_tokens WHERE user_id = ?`).bind(userId).run();

        // 插入新的token
        await db.prepare(`
            INSERT INTO api_tokens (token_hash, user_id, name, permissions)
            VALUES (?, ?, ?, 'api')
        `).bind(tokenHash, userId, newToken).run();

        return new Response(JSON.stringify({
            success: true,
            token: newToken
        }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleResendWebhook(request, db, corsHeaders) {
    try {
        const webhook = await request.json();
        const { type, data } = webhook;

        if (data && data.email_id) {
            await db.prepare(`
                UPDATE send_logs
                SET status = ?, error_message = ?
                WHERE resend_id = ?
            `).bind(
                type.includes('delivered') ? 'delivered' :
                type.includes('bounced') ? 'bounced' :
                type.includes('failed') ? 'failed' : 'sent',
                data.error?.message || null,
                data.email_id
            ).run();
        }

        return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// 辅助函数
function generateRandomToken() {
    return 'kkmail_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 检查发送限制
async function checkSendingLimits(db) {
    try {
        // 获取当前限制设置
        const limits = await db.prepare(`
            SELECT * FROM usage_limits
            ORDER BY limit_type
        `).all();

        if (!limits.results || limits.results.length === 0) {
            return { allowed: true };
        }

        const today = new Date().toISOString().split('T')[0];
        const thisMonth = new Date().toISOString().slice(0, 7);

        // 检查每日和每月限制
        for (const limit of limits.results) {
            // 检查是否需要重置计数
            if (limit.limit_type === 'daily' && limit.reset_date !== today) {
                await db.prepare(`
                    UPDATE usage_limits
                    SET current_usage = 0, reset_date = ?, updated_at = datetime('now')
                    WHERE limit_type = 'daily'
                `).bind(today).run();
                limit.current_usage = 0;
            } else if (limit.limit_type === 'monthly' && !limit.reset_date.startsWith(thisMonth)) {
                const nextMonth = new Date();
                nextMonth.setMonth(nextMonth.getMonth() + 1, 1);
                const nextMonthStr = nextMonth.toISOString().split('T')[0];

                await db.prepare(`
                    UPDATE usage_limits
                    SET current_usage = 0, reset_date = ?, updated_at = datetime('now')
                    WHERE limit_type = 'monthly'
                `).bind(nextMonthStr).run();
                limit.current_usage = 0;
            }

            // 检查是否超出限制
            if (limit.current_usage >= limit.limit_value) {
                return {
                    allowed: false,
                    message: `${limit.limit_type === 'daily' ? '每日' : '每月'}发送限制已达上限 (${limit.limit_value} 封)`
                };
            }
        }

        return { allowed: true };
    } catch (error) {
        console.error('Check limits error:', error);
        return { allowed: true }; // 出错时允许发送，避免完全阻断
    }
}

// 更新用量计数
async function updateUsageCount(db) {
    try {
        // 更新每日用量
        await db.prepare(`
            UPDATE usage_limits
            SET current_usage = current_usage + 1, updated_at = datetime('now')
            WHERE limit_type = 'daily'
        `).run();

        // 更新每月用量
        await db.prepare(`
            UPDATE usage_limits
            SET current_usage = current_usage + 1, updated_at = datetime('now')
            WHERE limit_type = 'monthly'
        `).run();
    } catch (error) {
        console.error('Update usage count error:', error);
    }
}

// 获取用量统计
async function handleGetUsageStats(request, auth, db, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // 获取用量限制信息
        const limits = await db.prepare(`
            SELECT * FROM usage_limits
            ORDER BY limit_type
        `).all();

        // 获取今日发送统计
        const todayStats = await db.prepare(`
            SELECT COUNT(*) as count
            FROM send_logs
            WHERE date(created_at) = date('now') AND status = 'sent'
        `).first();

        // 获取本月发送统计
        const monthStats = await db.prepare(`
            SELECT COUNT(*) as count
            FROM send_logs
            WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now') AND status = 'sent'
        `).first();

        // 获取总发送统计
        const totalStats = await db.prepare(`
            SELECT
                COUNT(*) as total_sent,
                COUNT(CASE WHEN status = 'sent' THEN 1 END) as successful_sent,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_sent
            FROM send_logs
        `).first();

        const result = {
            success: true,
            limits: limits.results || [],
            usage: {
                today: todayStats?.count || 0,
                month: monthStats?.count || 0,
                total: totalStats?.total_sent || 0,
                successful: totalStats?.successful_sent || 0,
                failed: totalStats?.failed_sent || 0
            },
            resend_limits: {
                daily_limit: 100,
                monthly_limit: 3000,
                plan: 'Free'
            }
        };

        return new Response(JSON.stringify(result), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// Temporary Email Handler Functions
async function handleCreateTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { expiryHours = 24, purpose = 'general', maxEmails = 50 } = body;

        const result = await tempEmailService.createTempEmail(domain, {
            expiryHours,
            purpose,
            maxEmails
        });

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateSignupTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { serviceName } = body;

        const result = await tempEmailService.createSignupTempEmail(domain, serviceName);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCreateVerificationTempEmail(request, tempEmailService, domain, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json().catch(() => ({}));
        const { verificationType = 'email' } = body;

        const result = await tempEmailService.createVerificationTempEmail(domain, verificationType);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmails(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmails(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExtendTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, additionalHours = 24 } = body;

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.extendTempEmail(email, accessToken, additionalHours);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailStats(request, tempEmailService, email, corsHeaders) {
    try {
        const url = new URL(request.url);
        const accessToken = url.searchParams.get('token') || request.headers.get('X-Access-Token');

        if (!accessToken) {
            return new Response(JSON.stringify({ error: 'Access token required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getUsageStats(email, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleMarkTempEmailAsRead(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.markEmailAsRead(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDeleteTempEmail(request, tempEmailService, email, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { accessToken, messageId } = body;

        if (!accessToken || !messageId) {
            return new Response(JSON.stringify({ error: 'Access token and message ID required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.deleteEmail(email, messageId, accessToken);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetAllTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const limit = parseInt(url.searchParams.get('limit')) || 50;
        const offset = parseInt(url.searchParams.get('offset')) || 0;

        const result = await tempEmailService.getAllTempEmails(limit, offset);

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetTempEmailAdminStats(request, auth, tempEmailService, corsHeaders) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.getTempEmailStats();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleCleanupExpiredTempEmails(request, auth, tempEmailService, corsHeaders) {
    try {
        if (request.method !== 'POST') {
            return new Response(JSON.stringify({ error: 'Method not allowed' }), {
                status: 405,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'Authorization required' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const token = authHeader.replace('Bearer ', '');
        const authResult = await auth.validateToken(token);

        if (!authResult.valid) {
            return new Response(JSON.stringify({ error: authResult.error }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        const result = await tempEmailService.cleanupExpiredEmails();

        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}