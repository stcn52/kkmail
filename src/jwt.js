export async function sign(payload, secret) {
    const header = {
        alg: 'HS256',
        typ: 'JWT'
    };

    const encoder = new TextEncoder();
    const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const data = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    return `${data}.${signatureB64}`;
}

export async function verify(token, secret) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const data = `${headerB64}.${payloadB64}`;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
    );

    const signature = Uint8Array.from(
        atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );

    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!isValid) {
        throw new Error('Invalid JWT signature');
    }

    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('JWT expired');
    }

    return payload;
}