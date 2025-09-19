import { sign, verify } from './jwt.js';

export class AuthService {
    constructor(jwtSecret, db) {
        this.jwtSecret = jwtSecret;
        this.db = db;
    }

    async generateToken(userId, permissions = 'read', expiresIn = '7d') {
        const payload = {
            userId,
            permissions,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.parseExpiry(expiresIn)
        };

        const token = await sign(payload, this.jwtSecret);
        const tokenHash = await this.hashToken(token);

        await this.db.prepare(`
            INSERT INTO api_tokens (token_hash, user_id, permissions, expires_at)
            VALUES (?, ?, ?, datetime('now', '+${expiresIn}'))
        `).bind(tokenHash, userId, permissions).run();

        return token;
    }

    async validateToken(token) {
        try {
            const payload = await verify(token, this.jwtSecret);
            const tokenHash = await this.hashToken(token);

            const tokenRecord = await this.db.prepare(`
                SELECT t.*, u.email, u.is_active
                FROM api_tokens t
                JOIN users u ON t.user_id = u.id
                WHERE t.token_hash = ? AND t.expires_at > datetime('now') AND u.is_active = 1
            `).bind(tokenHash).first();

            if (!tokenRecord) {
                return { valid: false, error: 'Token not found or expired' };
            }

            await this.db.prepare(`
                UPDATE api_tokens SET last_used_at = datetime('now')
                WHERE token_hash = ?
            `).bind(tokenHash).run();

            return {
                valid: true,
                user: {
                    id: tokenRecord.user_id,
                    email: tokenRecord.email,
                    permissions: tokenRecord.permissions
                }
            };
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    async hashToken(token) {
        const encoder = new TextEncoder();
        const data = encoder.encode(token);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    parseExpiry(expiresIn) {
        const units = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
            'w': 604800
        };

        const match = expiresIn.match(/^(\d+)([smhdw])$/);
        if (!match) return 604800; // default 7 days

        const [, value, unit] = match;
        return parseInt(value) * units[unit];
    }

    async revokeToken(token) {
        const tokenHash = await this.hashToken(token);

        const result = await this.db.prepare(`
            DELETE FROM api_tokens WHERE token_hash = ?
        `).bind(tokenHash).run();

        return result.changes > 0;
    }

    async createUser(email, password, fullName = '') {
        const passwordHash = await this.hashPassword(password);

        try {
            const result = await this.db.prepare(`
                INSERT INTO users (email, password_hash, full_name)
                VALUES (?, ?, ?)
            `).bind(email, passwordHash, fullName).run();

            return { success: true, userId: result.meta.last_row_id };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async verifyPassword(password, hashedPassword) {
        const passwordHash = await this.hashPassword(password);
        return passwordHash === hashedPassword;
    }
}