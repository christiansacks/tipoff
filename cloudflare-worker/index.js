/**
 * TipOff – Stripe webhook handler
 * Cloudflare Worker
 *
 * Secrets required (set via Cloudflare dashboard → Worker → Settings → Variables):
 *   STRIPE_WEBHOOK_SECRET   whsec_... from Stripe dashboard
 *   ED25519_PRIVATE_KEY_PEM full PEM text of keygen/private_key.pem
 *   RESEND_API_KEY          re_... from resend.com
 */

const PLAN_FEATURES = {
  pro: ['pdf', 'email_digest', 'hibp'],
  msp: ['pdf', 'email_digest', 'hibp', 'multi_tenant', 'white_label'],
};

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const body = await request.text();
    const sig  = request.headers.get('stripe-signature');

    if (!await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET)) {
      return new Response('Invalid signature', { status: 400 });
    }

    const event = JSON.parse(body);

    try {
      if (event.type === 'checkout.session.completed') {
        await handleCheckout(event.data.object, env);
      } else if (event.type === 'invoice.payment_succeeded') {
        await handleRenewal(event.data.object, env);
      }
    } catch (err) {
      console.error('Handler error:', err);
      return new Response('Internal error', { status: 500 });
    }

    return new Response('OK', { status: 200 });
  },
};

// ── Checkout handler (initial purchase) ──────────────────────────────────────

async function handleCheckout(session, env) {
  const email  = session.customer_details?.email;
  if (!email) return;

  // Determine plan from amount_total (in pence)
  // £9.00 = 900p monthly, £79.00 = 7900p annual
  const amount = session.amount_total ?? 0;
  const days   = amount >= 7900 ? 370 : 35;

  const key = await generateLicenceKey(email, 'pro', days, env);
  await sendLicenceEmail(email, key, days, env);
}

// ── Renewal handler (subscription renews each period) ────────────────────────

async function handleRenewal(invoice, env) {
  // Skip the initial invoice — that's already handled by checkout.session.completed
  if (invoice.billing_reason === 'subscription_create') return;

  const email  = invoice.customer_email;
  if (!email) return;

  const amount = invoice.amount_paid ?? 0;
  const days   = amount >= 7900 ? 370 : 35;

  const key = await generateLicenceKey(email, 'pro', days, env);
  await sendLicenceEmail(email, key, days, env);
}

// ── Licence key generation ────────────────────────────────────────────────────

async function generateLicenceKey(email, plan, days, env) {
  const today   = new Date();
  const expires = new Date(today.getTime() + days * 86_400_000);

  // Must match Python's json.dumps(payload, separators=(",",":")) key order exactly
  const payload = {
    email,
    plan,
    features: PLAN_FEATURES[plan],
    issued:   today.toISOString().slice(0, 10),
    expires:  expires.toISOString().slice(0, 10),
  };

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const payloadB64   = toBase64Url(payloadBytes);

  const privateKey = await importEd25519PrivateKey(env.ED25519_PRIVATE_KEY_PEM);
  const sigBytes   = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, payloadBytes));
  const sigB64     = toBase64Url(sigBytes);

  return `CR-${payloadB64}.${sigB64}`;
}

function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function importEd25519PrivateKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
}

// ── Email via Resend ──────────────────────────────────────────────────────────

async function sendLicenceEmail(email, key, days, env) {
  const expires = new Date(Date.now() + days * 86_400_000)
    .toISOString().slice(0, 10);

  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      from:    'TipOff <hello@tipoff.cc>',
      to:      [email],
      subject: 'Your TipOff Pro licence key',
      html: `
        <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
          <h2 style="color:#f59e0b">TipOff Pro</h2>
          <p>Thanks for subscribing! Here's your licence key:</p>
          <pre style="background:#1e1e2e;color:#a6e3a1;padding:1rem;border-radius:6px;
                      font-size:13px;word-break:break-all;white-space:pre-wrap">${key}</pre>
          <p><strong>Valid until:</strong> ${expires}</p>
          <p>To activate:</p>
          <ol>
            <li>Open your TipOff dashboard</li>
            <li>Go to <strong>Settings → Licence</strong></li>
            <li>Paste the key above and click Save</li>
          </ol>
          <p style="color:#888;font-size:12px">
            Need help? Reply to this email.<br>
            — The TipOff team
          </p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend error ${res.status}: ${body}`);
  }
}

// ── Stripe signature verification ─────────────────────────────────────────────

async function verifyStripeSignature(body, sigHeader, secret) {
  if (!sigHeader || !secret) return false;

  const parts = {};
  for (const part of sigHeader.split(',')) {
    const [k, v] = part.split('=');
    parts[k] = v;
  }
  const { t, v1 } = parts;
  if (!t || !v1) return false;

  const signed   = `${t}.${body}`;
  const keyBytes = new TextEncoder().encode(secret);
  const msgBytes = new TextEncoder().encode(signed);

  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msgBytes));
  const hex = Array.from(mac).map(b => b.toString(16).padStart(2, '0')).join('');

  return hex === v1;
}
