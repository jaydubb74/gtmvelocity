/**
 * GTMVelocity.ai — Contact Form API Worker
 *
 * Required secrets (set via: wrangler secret put <NAME>):
 *   RESEND_API_KEY        — resend.com API key for email delivery
 *   TURNSTILE_SECRET_KEY  — Cloudflare Turnstile secret key
 *
 * Optional secrets:
 *   SLACK_WEBHOOK_URL     — Slack incoming webhook URL
 *   CONTACT_EMAIL         — Override destination (default: josh@gtmvelocity.ai)
 *
 * Optional KV binding (for rate limiting):
 *   RATE_LIMIT_KV         — KV namespace binding (see wrangler.toml)
 */

// ══════════════════════════════════════════════════════════════════
// CONFIGURATION — edit this section to change behavior
// ══════════════════════════════════════════════════════════════════

const CONFIG = {
  defaultContactEmail: 'josh@gtmvelocity.ai',
  fromEmail:           'GTMVelocity Contact <noreply@gtmvelocity.ai>',
  rateLimit: {
    enabled:        true,
    maxRequests:    5,     // max form submissions per IP
    windowSeconds:  3600,  // per 1-hour window
  },
  allowedOrigins: [
    'https://gtmvelocity.ai',
    'https://www.gtmvelocity.ai',
  ],
};

/**
 * Inquiry-type routing.
 * To send different inquiry types to different addresses,
 * change the `to` value for each key.
 */
const INQUIRY_ROUTING = {
  phase1:   { label: 'Phase I — Customer Intelligence & GTM Architecture', to: 'josh@gtmvelocity.ai' },
  phase2:   { label: 'Phase II — AI-Native Acceleration',                  to: 'josh@gtmvelocity.ai' },
  full:     { label: 'Full 180-Day Engagement',                            to: 'josh@gtmvelocity.ai' },
  advisory: { label: 'Advisory / Strategic Discussion',                    to: 'josh@gtmvelocity.ai' },
  other:    { label: 'Something Else',                                     to: 'josh@gtmvelocity.ai' },
};

/** Server-side validation rules. Mirror these in the client-side JS. */
const FIELD_RULES = {
  fullName:        { required: true,  minLen: 2,   maxLen: 100, label: 'Full name'   },
  workEmail:       { required: true,  email: true, maxLen: 254, label: 'Work email'  },
  companyName:     { required: true,  minLen: 1,   maxLen: 100, label: 'Company'     },
  helpDescription: { required: true,  minLen: 10,  maxLen: 2000, label: 'Description' },
  phone:           { required: false,              maxLen: 30,  label: 'Phone'       },
  inquiryType:     { required: false, allowedValues: Object.keys(INQUIRY_ROUTING), label: 'Inquiry type' },
};

const MESSAGES = {
  success:         'Thanks — we received your inquiry. We typically reply within 1 business day.',
  serverError:     'Something went wrong. Please try again or email us directly.',
  validationError: 'Please check the fields below and try again.',
  rateLimited:     'Too many submissions from this address. Please try again in an hour.',
  spamDetected:    'Your submission was flagged as spam. Please try again.',
  badRequest:      'Invalid request.',
};

// ══════════════════════════════════════════════════════════════════
// WORKER ENTRY POINT
// ══════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return corsResponse(new Response(null, { status: 204 }), request);
    }

    // Contact API
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      return corsResponse(await handleContact(request, env), request);
    }

    // Static assets — serve everything else from the assets directory
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not found', { status: 404 });
  },
};

// ══════════════════════════════════════════════════════════════════
// CONTACT HANDLER
// ══════════════════════════════════════════════════════════════════

async function handleContact(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, message: MESSAGES.badRequest }, 400);
  }

  // ── Honeypot ────────────────────────────────────────────────────
  if (typeof body._hp === 'string' && body._hp.trim() !== '') {
    // Return 200 silently to confuse bots; don't process the submission
    return jsonResponse({ success: true, message: MESSAGES.success });
  }

  // ── Rate limiting ───────────────────────────────────────────────
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Real-IP') ||
             'unknown';

  if (CONFIG.rateLimit.enabled) {
    const limited = await checkRateLimit(env, ip);
    if (limited) {
      return jsonResponse({ success: false, message: MESSAGES.rateLimited }, 429);
    }
  }

  // ── Turnstile verification ──────────────────────────────────────
  if (env.TURNSTILE_SECRET_KEY) {
    const token = body.turnstileToken || '';
    const valid = await verifyTurnstile(token, env.TURNSTILE_SECRET_KEY, ip);
    if (!valid) {
      return jsonResponse({ success: false, message: MESSAGES.spamDetected }, 403);
    }
  }

  // ── Server-side validation ──────────────────────────────────────
  const errors = validate(body);
  if (Object.keys(errors).length > 0) {
    return jsonResponse({ success: false, message: MESSAGES.validationError, errors }, 422);
  }

  // ── Sanitize & enrich ───────────────────────────────────────────
  const data = sanitize(body);

  // ── Resolve routing ─────────────────────────────────────────────
  const route = INQUIRY_ROUTING[data.inquiryType] ?? {
    label: 'General Inquiry',
    to:    env.CONTACT_EMAIL || CONFIG.defaultContactEmail,
  };

  // ── Notifications (parallel, non-blocking on CRM) ───────────────
  const [emailResult, slackResult] = await Promise.allSettled([
    sendEmail(env, data, route),
    sendSlackNotification(env, data, route),
    syncToCRM(env, data), // fire-and-forget stub
  ]);

  // Log outcomes
  console.log(JSON.stringify({
    event: 'contact_submission',
    email: emailResult.status,
    slack: slackResult.status,
    inquiryType: data.inquiryType,
    company: data.companyName,
  }));

  // Email is the critical path; Slack failure is non-fatal
  if (emailResult.status === 'rejected') {
    console.error('Email delivery failed:', emailResult.reason);
    return jsonResponse({ success: false, message: MESSAGES.serverError }, 500);
  }

  return jsonResponse({ success: true, message: MESSAGES.success });
}

// ══════════════════════════════════════════════════════════════════
// VALIDATION
// ══════════════════════════════════════════════════════════════════

function validate(data) {
  const errors = {};

  for (const [field, rules] of Object.entries(FIELD_RULES)) {
    const raw   = data[field];
    const value = (raw == null ? '' : String(raw)).trim();

    if (rules.required && value === '') {
      errors[field] = `${rules.label} is required.`;
      continue;
    }
    if (!rules.required && value === '') continue;

    if (rules.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      errors[field] = 'Please enter a valid email address.';
      continue;
    }
    if (rules.minLen != null && value.length < rules.minLen) {
      errors[field] = `${rules.label} must be at least ${rules.minLen} characters.`;
      continue;
    }
    if (rules.maxLen != null && value.length > rules.maxLen) {
      errors[field] = `${rules.label} must be under ${rules.maxLen} characters.`;
      continue;
    }
    if (rules.allowedValues && !rules.allowedValues.includes(value)) {
      errors[field] = `Invalid ${rules.label}.`;
    }
  }

  return errors;
}

function sanitize(body) {
  const clean = {};
  for (const [field, rules] of Object.entries(FIELD_RULES)) {
    const max   = rules.maxLen ?? 2000;
    clean[field] = (body[field] == null ? '' : String(body[field])).trim().slice(0, max + 10);
  }
  clean.submittedAt = new Date().toISOString();
  return clean;
}

// ══════════════════════════════════════════════════════════════════
// RATE LIMITING (Cloudflare KV)
// ══════════════════════════════════════════════════════════════════

async function checkRateLimit(env, ip) {
  if (!env.RATE_LIMIT_KV) return false; // KV not configured — skip silently

  const key = `rl:contact:${ip}`;
  const { windowSeconds, maxRequests } = CONFIG.rateLimit;

  try {
    const raw   = await env.RATE_LIMIT_KV.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= maxRequests) return true;
    await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: windowSeconds });
    return false;
  } catch (err) {
    console.error('Rate limit KV error (failing open):', err);
    return false; // Fail open — don't block legit users if KV is down
  }
}

// ══════════════════════════════════════════════════════════════════
// TURNSTILE VERIFICATION
// ══════════════════════════════════════════════════════════════════

async function verifyTurnstile(token, secret, ip) {
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ secret, response: token, remoteip: ip }),
    });
    const result = await res.json();
    return result.success === true;
  } catch (err) {
    console.error('Turnstile verification failed (failing open):', err);
    return true; // Fail open if Turnstile is unreachable
  }
}

// ══════════════════════════════════════════════════════════════════
// EMAIL — Resend (resend.com)
// ══════════════════════════════════════════════════════════════════

async function sendEmail(env, data, route) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    // Log clearly during setup so the problem is obvious
    console.warn(
      'RESEND_API_KEY is not set. Email was NOT sent. ' +
      'Add it via: wrangler secret put RESEND_API_KEY'
    );
    return; // Don't throw — treat as optional during initial setup
  }

  const to      = env.CONTACT_EMAIL || route.to;
  const subject = `New Inquiry: ${data.companyName} — GTMVelocity.ai`;

  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      Authorization:  `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from:     CONFIG.fromEmail,
      to:       [to],
      reply_to: data.workEmail,
      subject,
      html:     buildEmailHtml(data, route),
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend ${res.status}: ${body}`);
  }
}

function buildEmailHtml(data, route) {
  const phone = data.phone
    ? `<tr>
        <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
          <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Phone</div>
          <div style="font-size:15px;color:#111;">${esc(data.phone)}</div>
        </td>
      </tr>`
    : '';

  const submittedAt = new Date(data.submittedAt).toLocaleString('en-US', {
    timeZone: 'America/Los_Angeles',
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F0F0F0;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F0F0F0;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" border="0"
             style="background:#fff;border-radius:12px;overflow:hidden;max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:#06091A;padding:28px 40px;">
            <div style="font-size:20px;font-weight:700;color:#2D9CDB;font-family:Arial,sans-serif;letter-spacing:-0.3px;">
              GTMVelocity<span style="color:#2D9CDB;">.ai</span>
            </div>
            <div style="font-size:12px;color:#8B93B0;margin-top:6px;letter-spacing:1px;text-transform:uppercase;">
              New Contact Inquiry
            </div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:32px 40px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
                  <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Name</div>
                  <div style="font-size:15px;color:#111;">${esc(data.fullName)}</div>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
                  <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Email</div>
                  <div style="font-size:15px;">
                    <a href="mailto:${esc(data.workEmail)}" style="color:#2D9CDB;text-decoration:none;">${esc(data.workEmail)}</a>
                  </div>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
                  <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Company</div>
                  <div style="font-size:15px;color:#111;">${esc(data.companyName)}</div>
                </td>
              </tr>
              ${phone}
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
                  <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Inquiry Type</div>
                  <div style="font-size:15px;color:#111;">${esc(route.label)}</div>
                </td>
              </tr>
              <tr>
                <td style="padding:16px 0 0;">
                  <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:10px;">What They Need Help With</div>
                  <div style="background:#F7F7F7;border-radius:8px;padding:18px;font-size:15px;color:#333;line-height:1.7;white-space:pre-wrap;">${esc(data.helpDescription)}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Reply CTA -->
        <tr>
          <td style="padding:28px 40px 32px;">
            <a href="mailto:${esc(data.workEmail)}?subject=Re%3A%20Your%20GTMVelocity.ai%20Inquiry"
               style="display:inline-block;padding:13px 28px;background:#2D9CDB;color:#fff;font-size:14px;font-weight:700;text-decoration:none;border-radius:8px;">
              Reply to ${esc(data.fullName)} →
            </a>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#06091A;padding:18px 40px;">
            <div style="font-size:12px;color:#5A6380;">
              Submitted ${submittedAt} PT · via GTMVelocity.ai contact form
            </div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════════
// SLACK NOTIFICATION
// ══════════════════════════════════════════════════════════════════

async function sendSlackNotification(env, data, route) {
  const webhookUrl = env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) {
    console.log('SLACK_WEBHOOK_URL not configured — Slack notification skipped.');
    return;
  }

  const phoneField = data.phone
    ? [{ type: 'mrkdwn', text: `*📞 Phone*\n${data.phone}` }]
    : [];

  const payload = {
    text: `🚀 New contact inquiry — GTMVelocity.ai`,
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: '🚀 New Contact Inquiry — GTMVelocity.ai', emoji: true },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*👤 Name*\n${data.fullName}` },
          { type: 'mrkdwn', text: `*🏢 Company*\n${data.companyName}` },
          { type: 'mrkdwn', text: `*✉️ Email*\n<mailto:${data.workEmail}|${data.workEmail}>` },
          { type: 'mrkdwn', text: `*🏷️ Interest*\n${route.label}` },
          ...phoneField,
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*💬 What they need help with*\n>${data.helpDescription.replace(/\n/g, '\n>')}`,
        },
      },
      {
        type: 'actions',
        elements: [
          {
            type: 'button',
            text:  { type: 'plain_text', text: 'Reply via Email', emoji: true },
            url:   `mailto:${data.workEmail}?subject=Re: Your GTMVelocity.ai Inquiry`,
            style: 'primary',
          },
        ],
      },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `Submitted ${data.submittedAt} · GTMVelocity.ai` },
        ],
      },
    ],
  };

  const res = await fetch(webhookUrl, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error(`Slack webhook error ${res.status}: ${await res.text()}`);
  }
}

// ══════════════════════════════════════════════════════════════════
// CRM INTEGRATION STUB
// Replace the body of this function to integrate with HubSpot, Salesforce, etc.
// ══════════════════════════════════════════════════════════════════

async function syncToCRM(env, data) {
  // ── HubSpot example ────────────────────────────────────────────
  // if (!env.HUBSPOT_API_KEY) return;
  // const nameParts = data.fullName.trim().split(/\s+/);
  // await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
  //   method: 'POST',
  //   headers: {
  //     Authorization: `Bearer ${env.HUBSPOT_API_KEY}`,
  //     'Content-Type': 'application/json',
  //   },
  //   body: JSON.stringify({
  //     properties: {
  //       email:      data.workEmail,
  //       firstname:  nameParts[0] ?? '',
  //       lastname:   nameParts.slice(1).join(' ') ?? '',
  //       company:    data.companyName,
  //       phone:      data.phone,
  //       message:    data.helpDescription,
  //     },
  //   }),
  // });

  // ── Salesforce example ─────────────────────────────────────────
  // Similar pattern — get OAuth token, POST to Lead object endpoint.

  console.log('CRM stub: add your integration here. Received from:', data.companyName);
}

// ══════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function corsResponse(response, request) {
  const origin  = request.headers.get('Origin') || '';
  const allowed = CONFIG.allowedOrigins.includes(origin) || origin === '';
  const headers = new Headers(response.headers);
  if (allowed) {
    headers.set('Access-Control-Allow-Origin', origin || '*');
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  return new Response(response.body, { status: response.status, headers });
}

/** Basic HTML escaping for use in email templates. */
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
