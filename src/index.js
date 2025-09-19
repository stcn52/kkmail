import { ResendService } from './resend.js';
import { AuthService } from './auth.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        const resend = new ResendService(env.RESEND_API_KEY);
        const auth = new AuthService(env.JWT_SECRET, env.DB);

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
                return await handleInit(env.DB, env.ADMIN_EMAIL);
            }

            if (path === '/api/auth/login') {
                return await handleLogin(request, auth, corsHeaders);
            }

            if (path === '/api/send') {
                return await handleSendEmail(request, resend, auth, env.DB, corsHeaders);
            }

            if (path === '/api/emails') {
                return await handleGetEmails(request, auth, env.DB, corsHeaders);
            }

            if (path.startsWith('/api/emails/')) {
                const emailId = path.split('/')[3];
                return await handleGetEmail(request, auth, env.DB, emailId, corsHeaders);
            }

            if (path === '/api/webhooks/resend') {
                return await handleResendWebhook(request, env.DB, corsHeaders);
            }

            if (path === '/email') {
                return await handleEmailRouting(request, env.DB, corsHeaders);
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
        return await handleIncomingEmail(message, env.DB);
    }
};

async function handleInit(db, adminEmail) {
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

            INSERT OR IGNORE INTO users (email, password_hash, full_name, is_active)
            VALUES ('${adminEmail}', 'change_me', 'Admin User', TRUE);

            INSERT OR IGNORE INTO email_aliases (alias_email, target_email, is_active)
            VALUES
                ('no-reply@yourdomain.com', '${adminEmail}', TRUE),
                ('support@yourdomain.com', '${adminEmail}', TRUE),
                ('contact@yourdomain.com', '${adminEmail}', TRUE);
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

        const emailData = await request.json();
        const result = await resend.sendEmail(emailData);

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

async function handleIncomingEmail(message, db) {
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