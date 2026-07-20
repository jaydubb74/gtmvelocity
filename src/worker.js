/**
 * GTMVelocity.ai — Contact Form API Worker
 *
 * Email is sent via Cloudflare's built-in email binding (no third-party service).
 *
 * One-time Cloudflare dashboard setup (both free):
 *   1. Email → Email Routing → Enable for gtmvelocity.ai
 *   2. Email → Email Routing → Destination addresses → Add josh@gtmvelocity.ai → Verify
 *
 * Required secret (run once, never commit the value):
 *   wrangler secret put TURNSTILE_SECRET_KEY
 *   → paste the secret key from the Cloudflare Turnstile dashboard (never commit it)
 *
 * Optional secrets:
 *   wrangler secret put SLACK_WEBHOOK_URL   (Slack incoming webhook URL)
 *   wrangler secret put CONTACT_EMAIL       (override destination, default: josh@gtmvelocity.ai)
 *
 * Bindings configured in wrangler.toml:
 *   SEND_EMAIL   — Cloudflare send_email binding (see wrangler.toml)
 *   ASSETS       — Static asset serving
 *   RATE_LIMIT_KV — (optional) KV namespace for rate limiting
 */

import { EmailMessage } from "cloudflare:email";

// ══════════════════════════════════════════════════════════════════
// CONFIGURATION — edit this section to change behavior
// ══════════════════════════════════════════════════════════════════

const CONFIG = {
  defaultContactEmail: 'josh@gtmvelocity.ai',
  fromEmail:           'noreply@gtmvelocity.ai',
  fromName:            'GTMVelocity Contact Form',
  rateLimit: {
    enabled:       true,
    maxRequests:   5,     // max submissions per IP
    windowSeconds: 3600,  // per 1-hour window
  },
  allowedOrigins: [
    'https://gtmvelocity.ai',
    'https://www.gtmvelocity.ai',
  ],
};

/**
 * Inquiry-type routing.
 * To route different inquiry types to different people, change `to` per key.
 */
const INQUIRY_ROUTING = {
  phase1:   { label: 'Phase I — Customer Intelligence & GTM Architecture', to: 'josh@gtmvelocity.ai' },
  phase2:   { label: 'Phase II — AI-Native Acceleration',                  to: 'josh@gtmvelocity.ai' },
  full:     { label: 'Full 180-Day Engagement',                            to: 'josh@gtmvelocity.ai' },
  advisory: { label: 'Advisory / Strategic Discussion',                    to: 'josh@gtmvelocity.ai' },
  other:    { label: 'Something Else',                                     to: 'josh@gtmvelocity.ai' },
};

/** Server-side validation rules. Keep in sync with client-side RULES in contact.html. */
const FIELD_RULES = {
  fullName:        { required: true,  minLen: 2,   maxLen: 100,  label: 'Full name'   },
  workEmail:       { required: true,  email: true, maxLen: 254,  label: 'Work email'  },
  companyName:     { required: true,  minLen: 1,   maxLen: 100,  label: 'Company'     },
  helpDescription: { required: true,  minLen: 10,  maxLen: 2000, label: 'Description' },
  phone:           { required: false,              maxLen: 30,   label: 'Phone'       },
  inquiryType:     { required: false, allowedValues: Object.keys(INQUIRY_ROUTING), label: 'Inquiry type' },
};

const MESSAGES = {
  success:         'Thanks — we received your inquiry. We typically reply within 1 business day.',
  serverError:     'Something went wrong. Please try again or email us directly.',
  validationError: 'Please check the fields below and try again.',
  rateLimited:     'Too many submissions from this address. Please try again in an hour.',
  spamDetected:    'Your submission was flagged. Please try again.',
  badRequest:      'Invalid request.',
};

// ══════════════════════════════════════════════════════════════════
// WORKER ENTRY POINT
// ══════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return corsResponse(new Response(null, { status: 204 }), request);
    }

    // Contact API
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      return corsResponse(await handleContact(request, env), request);
    }

    // Static assets
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

  // Honeypot — return 200 silently to confuse bots
  if (typeof body._hp === 'string' && body._hp.trim() !== '') {
    return jsonResponse({ success: true, message: MESSAGES.success });
  }

  // Rate limiting
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Real-IP') ||
             'unknown';
  if (CONFIG.rateLimit.enabled) {
    const limited = await checkRateLimit(env, ip);
    if (limited) {
      return jsonResponse({ success: false, message: MESSAGES.rateLimited }, 429);
    }
  }

  // Turnstile verification
  if (env.TURNSTILE_SECRET_KEY) {
    const valid = await verifyTurnstile(
      body.turnstileToken || '',
      env.TURNSTILE_SECRET_KEY,
      ip
    );
    if (!valid) {
      return jsonResponse({ success: false, message: MESSAGES.spamDetected }, 403);
    }
  }

  // Server-side validation
  const errors = validate(body);
  if (Object.keys(errors).length > 0) {
    return jsonResponse({ success: false, message: MESSAGES.validationError, errors }, 422);
  }

  // Sanitize + enrich
  const data  = sanitize(body);
  const route = INQUIRY_ROUTING[data.inquiryType] ?? {
    label: 'General Inquiry',
    to:    env.CONTACT_EMAIL || CONFIG.defaultContactEmail,
  };

  // Send notifications — all in parallel; only email is critical path
  const [emailResult, slackResult] = await Promise.allSettled([
    sendEmail(env, data, route),
    sendSlackNotification(env, data, route),
    syncToCRM(env, data),
  ]);

  console.log(JSON.stringify({
    event:       'contact_submission',
    email:       emailResult.status,
    slack:       slackResult.status,
    inquiryType: data.inquiryType,
    company:     data.companyName,
  }));

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
    const value = (data[field] == null ? '' : String(data[field])).trim();

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
    const max = rules.maxLen ?? 2000;
    clean[field] = (body[field] == null ? '' : String(body[field])).trim().slice(0, max);
  }
  clean.submittedAt = new Date().toISOString();
  return clean;
}

// ══════════════════════════════════════════════════════════════════
// RATE LIMITING (Cloudflare KV)
// ══════════════════════════════════════════════════════════════════

async function checkRateLimit(env, ip) {
  if (!env.RATE_LIMIT_KV) return false; // KV not bound — skip silently

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
    return false;
  }
}

// ══════════════════════════════════════════════════════════════════
// TURNSTILE VERIFICATION
// ══════════════════════════════════════════════════════════════════

async function verifyTurnstile(token, secret, ip) {
  try {
    const res    = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ secret, response: token, remoteip: ip }),
    });
    const result = await res.json();
    return result.success === true;
  } catch (err) {
    console.error('Turnstile verification error (failing open):', err);
    return true; // Fail open if Turnstile is unreachable
  }
}

// ══════════════════════════════════════════════════════════════════
// EMAIL — Cloudflare Email Routing (no third-party service needed)
//
// Setup (one time, in Cloudflare dashboard):
//   1. Email → Email Routing → Enable for gtmvelocity.ai
//   2. Email → Email Routing → Destination addresses → Add + verify josh@gtmvelocity.ai
// ══════════════════════════════════════════════════════════════════

async function sendEmail(env, data, route) {
  if (!env.SEND_EMAIL) {
    console.warn(
      'SEND_EMAIL binding is not configured. ' +
      'Add [[send_email]] to wrangler.toml and enable Cloudflare Email Routing.'
    );
    // Don't throw — let the form appear to work during initial setup/testing
    return;
  }

  const to      = env.CONTACT_EMAIL || route.to;
  const subject = `New Inquiry: ${data.companyName} — GTMVelocity.ai`;
  const from    = CONFIG.fromEmail;

  const raw = buildRawMimeEmail({
    from:    `${CONFIG.fromName} <${from}>`,
    to,
    replyTo: data.workEmail,
    subject,
    html:    buildEmailHtml(data, route),
  });

  const message = new EmailMessage(from, to, new Response(raw).body);
  await env.SEND_EMAIL.send(message);
}

/**
 * Builds a raw MIME email string.
 * Uses base64 encoding for the body to handle UTF-8 safely and
 * keep all lines within the 998-octet MIME limit.
 */
function buildRawMimeEmail({ from, to, replyTo, subject, html }) {
  const encodedBody = base64MimeEncode(html);
  return [
    'MIME-Version: 1.0',
    `Message-ID: <${crypto.randomUUID()}@gtmvelocity.ai>`,
    `Date: ${new Date().toUTCString()}`,
    `From: ${from}`,
    `To: ${to}`,
    `Reply-To: ${replyTo}`,
    `Subject: ${subject}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    encodedBody,
  ].join('\r\n');
}

/** Base64-encodes a UTF-8 string with 76-char line wrapping per RFC 2045. */
function base64MimeEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary  = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return b64.match(/.{1,76}/g)?.join('\r\n') ?? b64;
}

function buildEmailHtml(data, route) {
  const phoneRow = data.phone ? `
    <tr>
      <td style="padding:10px 0;border-bottom:1px solid #E8E8E8;">
        <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#999;margin-bottom:4px;">Phone</div>
        <div style="font-size:15px;color:#111;">${esc(data.phone)}</div>
      </td>
    </tr>` : '';

  const submittedAt = new Date(data.submittedAt).toLocaleString('en-US', {
    timeZone:  'America/Los_Angeles',
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

        <tr>
          <td style="background:#06091A;padding:28px 40px;">
            <div style="font-size:20px;font-weight:700;color:#2D9CDB;font-family:Arial,sans-serif;">GTMVelocity.ai</div>
            <div style="font-size:12px;color:#8B93B0;margin-top:6px;letter-spacing:1px;text-transform:uppercase;">New Contact Inquiry</div>
          </td>
        </tr>

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
              ${phoneRow}
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

        <tr>
          <td style="padding:28px 40px 32px;">
            <a href="mailto:${esc(data.workEmail)}?subject=Re%3A%20Your%20GTMVelocity.ai%20Inquiry"
               style="display:inline-block;padding:13px 28px;background:#2D9CDB;color:#fff;font-size:14px;font-weight:700;text-decoration:none;border-radius:8px;">
              Reply to ${esc(data.fullName)} →
            </a>
          </td>
        </tr>

        <tr>
          <td style="background:#06091A;padding:18px 40px;">
            <div style="font-size:12px;color:#5A6380;">Submitted ${submittedAt} PT · via GTMVelocity.ai contact form</div>
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
    console.log('SLACK_WEBHOOK_URL not set — Slack notification skipped.');
    return;
  }

  const phoneField = data.phone
    ? [{ type: 'mrkdwn', text: `*📞 Phone*\n${slackEsc(data.phone)}` }]
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
          { type: 'mrkdwn', text: `*👤 Name*\n${slackEsc(data.fullName)}` },
          { type: 'mrkdwn', text: `*🏢 Company*\n${slackEsc(data.companyName)}` },
          { type: 'mrkdwn', text: `*✉️ Email*\n<mailto:${slackEsc(data.workEmail)}|${slackEsc(data.workEmail)}>` },
          { type: 'mrkdwn', text: `*🏷️ Interest*\n${slackEsc(route.label)}` },
          ...phoneField,
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*💬 What they need help with*\n>${slackEsc(data.helpDescription).replace(/\n/g, '\n>')}`,
        },
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
    throw new Error(`Slack webhook ${res.status}: ${await res.text()}`);
  }
}

// ══════════════════════════════════════════════════════════════════
// CRM INTEGRATION STUB
// Replace the body of this function to connect HubSpot, Salesforce, etc.
// ══════════════════════════════════════════════════════════════════

async function syncToCRM(env, data) {
  // ── HubSpot example ────────────────────────────────────────────
  // if (!env.HUBSPOT_API_KEY) return;
  // const [first, ...rest] = data.fullName.trim().split(/\s+/);
  // await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
  //   method: 'POST',
  //   headers: {
  //     Authorization: `Bearer ${env.HUBSPOT_API_KEY}`,
  //     'Content-Type': 'application/json',
  //   },
  //   body: JSON.stringify({
  //     properties: {
  //       email:     data.workEmail,
  //       firstname: first ?? '',
  //       lastname:  rest.join(' ') ?? '',
  //       company:   data.companyName,
  //       phone:     data.phone,
  //       message:   data.helpDescription,
  //     },
  //   }),
  // });
  console.log('CRM stub called. Implement integration here. Company:', data.companyName);
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
  headers.set('Vary', 'Origin');
  if (allowed) {
    headers.set('Access-Control-Allow-Origin', origin || '*');
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  return new Response(response.body, { status: response.status, headers });
}

/** Escapes the three characters Slack mrkdwn treats as control characters. */
function slackEsc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
