export class EmailRouter {
    constructor(db) {
        this.db = db;
    }

    async routeEmail(message) {
        const to = message.to;
        const from = message.from;
        const subject = message.headers.get('subject') || '';

        const aliases = await this.db.prepare(`
            SELECT target_email, alias_email
            FROM email_aliases
            WHERE alias_email = ? AND is_active = 1
        `).bind(to).all();

        if (aliases.results && aliases.results.length > 0) {
            for (const alias of aliases.results) {
                console.log(`Routing ${from} -> ${alias.alias_email} to ${alias.target_email}`);
            }
        }

        const messageId = message.headers.get('message-id') || `kkmail-${Date.now()}-${Math.random()}`;
        const headers = JSON.stringify(Object.fromEntries(message.headers));

        let bodyText = '';
        let bodyHtml = '';

        try {
            if (message.raw) {
                bodyText = await new Response(message.raw).text();
            }
        } catch (e) {
            console.error('Failed to get raw email:', e);
        }

        try {
            await this.db.prepare(`
                INSERT OR REPLACE INTO emails
                (message_id, from_email, to_email, subject, body_text, body_html, headers, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'received')
            `).bind(messageId, from, to, subject, bodyText, bodyHtml, headers).run();

            console.log(`Email stored: ${messageId} from ${from} to ${to}`);
        } catch (error) {
            console.error('Failed to store email:', error);
        }

        return { success: true, messageId };
    }

    async createAlias(aliasEmail, targetEmail) {
        try {
            await this.db.prepare(`
                INSERT INTO email_aliases (alias_email, target_email, is_active)
                VALUES (?, ?, 1)
            `).bind(aliasEmail, targetEmail).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async removeAlias(aliasEmail) {
        try {
            await this.db.prepare(`
                UPDATE email_aliases SET is_active = 0
                WHERE alias_email = ?
            `).bind(aliasEmail).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async getAliases() {
        try {
            const aliases = await this.db.prepare(`
                SELECT alias_email, target_email, created_at
                FROM email_aliases
                WHERE is_active = 1
                ORDER BY created_at DESC
            `).all();

            return { success: true, aliases: aliases.results };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async getEmailsByRecipient(email, limit = 50, offset = 0) {
        try {
            const emails = await this.db.prepare(`
                SELECT id, message_id, from_email, to_email, subject, status, created_at, read_at
                FROM emails
                WHERE to_email = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            `).bind(email, limit, offset).all();

            return { success: true, emails: emails.results };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async markEmailAsRead(messageId) {
        try {
            await this.db.prepare(`
                UPDATE emails
                SET status = 'read', read_at = datetime('now')
                WHERE message_id = ?
            `).bind(messageId).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async deleteEmail(messageId) {
        try {
            await this.db.prepare(`
                UPDATE emails
                SET status = 'deleted'
                WHERE message_id = ?
            `).bind(messageId).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}