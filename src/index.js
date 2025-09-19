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

            if (path === '/admin' || path === '/') {
                return await handleAdminInterface();
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

async function handleAdminInterface() {
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 KKMail 管理界面</h1>
            <p>自定义域名邮箱服务管理</p>
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
                </div>

                <div class="card">
                    <div class="card-header">系统信息</div>
                    <div class="card-body">
                        <p><strong>服务地址:</strong> https://mail.yourdomain.com</p>
                        <p><strong>邮件域名:</strong> yourdomain.com</p>
                        <p><strong>状态:</strong> <span style="color: #28a745;">✅ 运行正常</span></p>
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
                                <input type="email" id="newUserEmail" class="form-control" placeholder="user@yourdomain.com">
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
                                <input type="email" id="aliasEmail" class="form-control" placeholder="support@yourdomain.com">
                            </div>
                            <div class="form-group">
                                <label>目标邮箱</label>
                                <input type="email" id="targetEmail" class="form-control" placeholder="admin@yourdomain.com">
                            </div>
                            <button onclick="createAlias()" class="btn btn-success">创建别名</button>
                            <button onclick="hideAddAliasForm()" class="btn btn-secondary">取消</button>
                        </div>
                        <div id="aliasesList" class="loading">加载中...</div>
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
                            <input type="email" id="sendFrom" class="form-control" value="admin@yourdomain.com">
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
        const API_BASE = 'https://mail.yourdomain.com/api';

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
                    document.getElementById('loginSection').classList.add('hidden');
                    document.getElementById('mainSection').classList.remove('hidden');
                    loadDashboard();
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
        function showTab(tabName) {
            // 隐藏所有标签页
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // 显示选中的标签页
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');

            // 加载对应数据
            if (tabName === 'dashboard') loadDashboard();
            else if (tabName === 'emails') loadEmails();
            else if (tabName === 'users') loadUsers();
            else if (tabName === 'aliases') loadAliases();
        }

        // 加载仪表板
        async function loadDashboard() {
            try {
                const [users, aliases] = await Promise.all([
                    apiRequest('/users'),
                    apiRequest('/aliases')
                ]);

                document.getElementById('userCount').textContent = users.users?.length || 0;
                document.getElementById('aliasCount').textContent = aliases.aliases?.length || 0;
                document.getElementById('emailCount').textContent = '0';
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
                        <p><strong>端点:</strong> <code>POST https://mail.yourdomain.com/api/send-simple</code></p>

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
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">curl -X POST https://mail.yourdomain.com/api/send-simple \\\\
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

        // 页面加载完成后的操作
        document.addEventListener('DOMContentLoaded', function() {
            // 可以在这里添加初始化代码
        });
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

        // 使用token对应用户的邮箱作为发件人
        emailData.from = userToken.email;

        const result = await resend.sendEmail(emailData);

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