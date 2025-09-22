export class TempEmailService {
    constructor(db) {
        this.db = db;
    }

    generateTempEmail(domain, purpose = 'general') {
        const randomStr = Math.random().toString(36).substring(2, 10);
        const timestamp = Date.now().toString(36).substring(2, 8);

        const prefix = purpose === 'signup' ? 'signup' :
                      purpose === 'verification' ? 'verify' : 'temp';

        return `${prefix}-${randomStr}-${timestamp}@${domain}`;
    }

    async createTempEmail(domain, options = {}) {
        const {
            expiryHours = 24,
            purpose = 'general',
            maxEmails = 50
        } = options;

        const tempEmail = this.generateTempEmail(domain, purpose);
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + expiryHours);

        try {
            await this.db.prepare(`
                INSERT INTO temp_emails (email, expires_at, purpose, max_emails, created_at, is_active)
                VALUES (?, ?, ?, ?, datetime('now'), 1)
            `).bind(tempEmail, expiresAt.toISOString(), purpose, maxEmails).run();

            const accessToken = await this.generateAccessToken(tempEmail);

            await this.logUsage(tempEmail, 'created', JSON.stringify({
                purpose,
                expiryHours,
                maxEmails
            }));

            return {
                success: true,
                email: tempEmail,
                expiresAt: expiresAt.toISOString(),
                accessToken,
                purpose,
                maxEmails
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async generateAccessToken(email) {
        const token = 'temp_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        const tokenHash = await this.hashString(token);

        await this.db.prepare(`
            UPDATE temp_emails
            SET access_token = ?
            WHERE email = ?
        `).bind(tokenHash, email).run();

        return token;
    }

    async hashString(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async validateTempEmail(email) {
        const tempEmail = await this.db.prepare(`
            SELECT email, expires_at, is_active
            FROM temp_emails
            WHERE email = ? AND is_active = 1
        `).bind(email).first();

        if (!tempEmail) {
            return { valid: false, reason: 'not_found' };
        }

        const now = new Date();
        const expiresAt = new Date(tempEmail.expires_at);

        if (now > expiresAt) {
            await this.deactivateTempEmail(email);
            return { valid: false, reason: 'expired' };
        }

        return { valid: true };
    }

    async validateAccessToken(email, token) {
        const tokenHash = await this.hashString(token);

        const tempEmail = await this.db.prepare(`
            SELECT email, expires_at, is_active
            FROM temp_emails
            WHERE email = ? AND access_token = ? AND is_active = 1
        `).bind(email, tokenHash).first();

        if (!tempEmail) {
            return { valid: false };
        }

        const validation = await this.validateTempEmail(email);
        return validation;
    }

    async getTempEmails(email, accessToken) {
        const tokenValidation = await this.validateAccessToken(email, accessToken);
        if (!tokenValidation.valid) {
            return { success: false, error: 'Invalid access token or expired email' };
        }

        try {
            const emails = await this.db.prepare(`
                SELECT id, message_id, from_email, subject, body_text, body_html, headers, created_at, read_at
                FROM emails
                WHERE to_email = ?
                ORDER BY created_at DESC
                LIMIT 50
            `).bind(email).all();

            return {
                success: true,
                emails: emails.results || [],
                tempEmail: email
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async markEmailAsRead(email, messageId, accessToken) {
        const tokenValidation = await this.validateAccessToken(email, accessToken);
        if (!tokenValidation.valid) {
            return { success: false, error: 'Invalid access token or expired email' };
        }

        try {
            await this.db.prepare(`
                UPDATE emails
                SET read_at = datetime('now')
                WHERE message_id = ? AND to_email = ?
            `).bind(messageId, email).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async deleteEmail(email, messageId, accessToken) {
        const tokenValidation = await this.validateAccessToken(email, accessToken);
        if (!tokenValidation.valid) {
            return { success: false, error: 'Invalid access token or expired email' };
        }

        try {
            await this.db.prepare(`
                UPDATE emails
                SET status = 'deleted'
                WHERE message_id = ? AND to_email = ?
            `).bind(messageId, email).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async extendTempEmail(email, accessToken, additionalHours = 24) {
        const tokenValidation = await this.validateAccessToken(email, accessToken);
        if (!tokenValidation.valid) {
            return { success: false, error: 'Invalid access token or expired email' };
        }

        try {
            const currentEmail = await this.db.prepare(`
                SELECT expires_at FROM temp_emails WHERE email = ?
            `).bind(email).first();

            const newExpiryDate = new Date(currentEmail.expires_at);
            newExpiryDate.setHours(newExpiryDate.getHours() + additionalHours);

            await this.db.prepare(`
                UPDATE temp_emails
                SET expires_at = ?
                WHERE email = ?
            `).bind(newExpiryDate.toISOString(), email).run();

            return {
                success: true,
                newExpiryDate: newExpiryDate.toISOString()
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async deactivateTempEmail(email) {
        try {
            await this.db.prepare(`
                UPDATE temp_emails
                SET is_active = 0
                WHERE email = ?
            `).bind(email).run();

            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async cleanupExpiredEmails() {
        try {
            await this.db.prepare(`
                UPDATE temp_emails
                SET is_active = 0
                WHERE expires_at < datetime('now') AND is_active = 1
            `).run();

            const result = await this.db.prepare(`
                UPDATE emails
                SET status = 'expired'
                WHERE to_email IN (
                    SELECT email FROM temp_emails
                    WHERE expires_at < datetime('now') AND is_active = 0
                ) AND status != 'expired'
            `).run();

            return {
                success: true,
                cleanedCount: result.changes || 0
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async getTempEmailStats() {
        try {
            const activeCount = await this.db.prepare(`
                SELECT COUNT(*) as count
                FROM temp_emails
                WHERE is_active = 1 AND expires_at > datetime('now')
            `).first();

            const totalEmails = await this.db.prepare(`
                SELECT COUNT(*) as count
                FROM emails
                WHERE to_email IN (
                    SELECT email FROM temp_emails
                )
            `).first();

            const todayEmails = await this.db.prepare(`
                SELECT COUNT(*) as count
                FROM emails
                WHERE to_email IN (
                    SELECT email FROM temp_emails
                ) AND date(created_at) = date('now')
            `).first();

            return {
                success: true,
                stats: {
                    activeTempEmails: activeCount?.count || 0,
                    totalReceivedEmails: totalEmails?.count || 0,
                    todayReceivedEmails: todayEmails?.count || 0
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async getAllTempEmails(limit = 50, offset = 0) {
        try {
            const tempEmails = await this.db.prepare(`
                SELECT email, expires_at, created_at, is_active,
                       (SELECT COUNT(*) FROM emails WHERE to_email = temp_emails.email) as email_count
                FROM temp_emails
                WHERE is_active = 1
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            `).bind(limit, offset).all();

            return {
                success: true,
                tempEmails: tempEmails.results || []
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async logUsage(tempEmail, action, details = null) {
        try {
            await this.db.prepare(`
                INSERT INTO temp_email_usage (temp_email, action, details)
                VALUES (?, ?, ?)
            `).bind(tempEmail, action, details).run();
        } catch (error) {
            console.error('Failed to log temp email usage:', error);
        }
    }

    async onEmailReceived(toEmail, fromEmail, subject) {
        try {
            const tempEmail = await this.db.prepare(`
                SELECT email, max_emails, received_count, purpose
                FROM temp_emails
                WHERE email = ? AND is_active = 1 AND expires_at > datetime('now')
            `).bind(toEmail).first();

            if (tempEmail) {
                await this.db.prepare(`
                    UPDATE temp_emails
                    SET received_count = received_count + 1,
                        last_accessed_at = datetime('now')
                    WHERE email = ?
                `).bind(toEmail).run();

                await this.db.prepare(`
                    UPDATE emails
                    SET is_temp_email = 1,
                        temp_email_purpose = ?
                    WHERE to_email = ? AND from_email = ? AND subject = ?
                `).bind(tempEmail.purpose, toEmail, fromEmail, subject).run();

                await this.logUsage(toEmail, 'email_received', JSON.stringify({
                    from: fromEmail,
                    subject: subject
                }));

                if (tempEmail.received_count + 1 >= tempEmail.max_emails) {
                    await this.logUsage(toEmail, 'max_emails_reached', null);
                }

                return { success: true, isTempEmail: true };
            }

            return { success: true, isTempEmail: false };
        } catch (error) {
            console.error('Failed to handle temp email reception:', error);
            return { success: false, error: error.message };
        }
    }

    async createSignupTempEmail(domain, serviceName = null) {
        const options = {
            expiryHours: 1, // 注册邮件通常1小时足够
            purpose: 'signup',
            maxEmails: 10 // 注册邮件不需要太多
        };

        const result = await this.createTempEmail(domain, options);

        if (result.success && serviceName) {
            await this.logUsage(result.email, 'signup_created', JSON.stringify({
                serviceName: serviceName
            }));
        }

        return result;
    }

    async createVerificationTempEmail(domain, verificationType = 'email') {
        const options = {
            expiryHours: 2, // 验证邮件2小时有效期
            purpose: 'verification',
            maxEmails: 5
        };

        const result = await this.createTempEmail(domain, options);

        if (result.success) {
            await this.logUsage(result.email, 'verification_created', JSON.stringify({
                verificationType: verificationType
            }));
        }

        return result;
    }

    async getUsageStats(email, accessToken) {
        const tokenValidation = await this.validateAccessToken(email, accessToken);
        if (!tokenValidation.valid) {
            return { success: false, error: 'Invalid access token or expired email' };
        }

        try {
            const tempEmail = await this.db.prepare(`
                SELECT email, expires_at, created_at, purpose, max_emails, received_count
                FROM temp_emails
                WHERE email = ?
            `).bind(email).first();

            const usage = await this.db.prepare(`
                SELECT action, timestamp, details
                FROM temp_email_usage
                WHERE temp_email = ?
                ORDER BY timestamp DESC
                LIMIT 20
            `).bind(email).all();

            return {
                success: true,
                tempEmail: tempEmail,
                usage: usage.results || []
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}