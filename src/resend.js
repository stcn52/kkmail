export class ResendService {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseURL = 'https://api.resend.com';
    }

    async sendEmail(options) {
        const {
            from,
            to,
            subject,
            html,
            text,
            cc,
            bcc,
            replyTo,
            attachments
        } = options;

        const payload = {
            from,
            to: Array.isArray(to) ? to : [to],
            subject,
        };

        if (html) payload.html = html;
        if (text) payload.text = text;
        if (cc) payload.cc = Array.isArray(cc) ? cc : [cc];
        if (bcc) payload.bcc = Array.isArray(bcc) ? bcc : [bcc];
        if (replyTo) payload.reply_to = replyTo;
        if (attachments) payload.attachments = attachments;

        try {
            const response = await fetch(`${this.baseURL}/emails`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(`Resend API error: ${result.message || response.statusText}`);
            }

            return {
                success: true,
                id: result.id,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                data: null
            };
        }
    }

    async getEmail(emailId) {
        try {
            const response = await fetch(`${this.baseURL}/emails/${emailId}`, {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                },
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(`Resend API error: ${result.message || response.statusText}`);
            }

            return {
                success: true,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                data: null
            };
        }
    }

    async setupWebhook(url, events = ['email.sent', 'email.delivered', 'email.bounced']) {
        try {
            const response = await fetch(`${this.baseURL}/webhooks`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    endpoint: url,
                    events
                }),
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(`Resend API error: ${result.message || response.statusText}`);
            }

            return {
                success: true,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                data: null
            };
        }
    }

    async verifyDomain(domain) {
        try {
            const response = await fetch(`${this.baseURL}/domains`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: domain
                }),
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(`Resend API error: ${result.message || response.statusText}`);
            }

            return {
                success: true,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                data: null
            };
        }
    }
}