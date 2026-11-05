import { randomBytes } from '@noble/hashes/utils.js';
import { b64url } from './passkey.ts';
import { recipientLabel } from './resolve.ts';

export type Page = { body: string; headers: Record<string, string> };

export function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ] ?? c,
  );
}

function jsonForScript(v: unknown): string {
  return JSON.stringify(v)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const STYLE = `
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #f5f5f7; --card: #fff; --muted: #6e6e73; --ok: #1a7f37; --bad: #c0362c; --line: #d2d2d7; }
@media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --bg: #1c1c1e; --card: #2c2c2e; --muted: #a1a1a6; --ok: #3fb950; --bad: #ff6b5e; --line: #3a3a3c; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; font: 15px/1.5 system-ui, -apple-system, sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 560px; margin: 0 auto; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 24px; }
h1 { font-size: 20px; margin: 0 0 4px; }
.muted { color: var(--muted); font-size: 13px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 20px 0; }
dt { color: var(--muted); }
dd { margin: 0; font-family: ui-monospace, monospace; font-size: 13px; overflow-wrap: anywhere; }
.amount { font-size: 28px; font-weight: 600; margin: 16px 0 0; }
.actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
.actions button { min-width: 140px; }
.service { font-size: 22px; font-weight: 600; margin: 16px 0 0; overflow-wrap: anywhere; }
.note { background: var(--bg); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; font-size: 13px; }
button { flex: 1; font: inherit; font-weight: 600; padding: 12px; border-radius: 10px; border: 1px solid var(--line); cursor: pointer; background: transparent; color: var(--fg); }
button.primary { background: var(--ok); border-color: var(--ok); color: #fff; }
button:disabled { opacity: .5; cursor: default; }
#status { margin-top: 16px; min-height: 1.5em; }
#status.bad { color: var(--bad); }
#status.ok { color: var(--ok); }
`;

const CODEC = `
const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const cfg = JSON.parse(document.getElementById('cfg').textContent);
const statusEl = document.getElementById('status');
const say = (text, cls) => { statusEl.textContent = text; statusEl.className = cls || ''; };
const buttons = () => document.querySelectorAll('button');
const lock = (v) => buttons().forEach((b) => { b.disabled = v; });
`;

function shell(
  title: string,
  content: string,
  cfg: unknown,
  script: string,
): Page {
  const nonce = b64url(randomBytes(16));
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style></head>
<body><main>${content}<p id="status" role="status"></p></main>
<script type="application/json" id="cfg">${jsonForScript(cfg)}</script>
<script nonce="${nonce}">${CODEC}${script}</script></body></html>`;
  return {
    body,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  };
}

export type ApprovalView = {
  id: string;
  agent: string;
  status: string;
  expiresAt: number;
  intent: Record<string, unknown>;
  usd: string | null;
  pending: boolean;
  newRecipient?: boolean;
  resourceUrl?: string | null;
};

export function approvalPage(
  view: ApprovalView,
  cfg: {
    rpId: string;
    challenges: Record<string, string>;
    credentials: string[];
    userVerification: string;
  },
): Page {
  const intent = view.intent;
  const row = (k: string, v: unknown) =>
    v === undefined
      ? ''
      : `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`;
  const fee = intent['fee'] as { amount?: string } | undefined;
  const pending = view.pending;
  const fresh = view.newRecipient === true;
  const title = fresh
    ? 'New service wants to be paid'
    : `Approve $${view.usd ?? ''} payment`;
  const amount =
    view.usd === null ? '' : `<p class="amount">$${escapeHtml(view.usd)}</p>`;
  const header = fresh
    ? `<h1>${title}</h1>
<p class="muted">Agent <b>${escapeHtml(view.agent)}</b> wants to pay a recipient that is not on your list yet.</p>
<p class="service">${escapeHtml(recipientLabel(view.resourceUrl ?? null))}</p>
${amount}
<p class="note">“Always allow” adds this recipient on this chain to your list. Later payments to it still follow every limit, and amounts above your approval threshold still ask you. Remove it any time with <code>bursar recipients remove</code>.</p>`
    : `<h1>Payment approval</h1>
<p class="muted">Agent <b>${escapeHtml(view.agent)}</b> asks to pay. Check the details, then confirm with your passkey.</p>
${amount}`;
  const buttons = fresh
    ? `<div class="actions"><button class="primary" id="remember" type="button">Always allow this service</button><button id="approve" type="button">Allow once</button><button id="deny" type="button">Deny</button></div>`
    : `<div class="actions"><button class="primary" id="approve" type="button">Approve with passkey</button><button id="deny" type="button">Deny</button></div>`;
  const content = `
${header}
<dl>
${fresh && view.resourceUrl ? row('Resource', view.resourceUrl) : ''}
${row('Recipient', intent['recipient'])}
${row('Chain', intent['chain'])}
${row('Asset', intent['asset'])}
${row('Amount (base units)', intent['amount'])}
${row('Protocol', intent['protocol'])}
${fee?.amount === undefined ? '' : row('Max network fee (base units)', fee.amount)}
${row('Resource hash', intent['resourceHash'])}
${row('Approval', view.id)}
${row('Expires', new Date(view.expiresAt).toISOString())}
${row('Status', pending ? 'pending' : view.status === 'pending' ? 'expired' : view.status)}
</dl>
${
  pending
    ? buttons
    : '<p class="muted">This request can no longer be changed.</p>'
}`;
  const script = `
if (cfg.credentials.length === 0) say('No passkey is registered. Run: bursar passkey add', 'bad');
async function decide(decision) {
  lock(true);
  say('Waiting for your passkey...');
  try {
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: fromB64(cfg.challenges[decision]),
      rpId: cfg.rpId,
      allowCredentials: cfg.credentials.map((id) => ({ type: 'public-key', id: fromB64(id) })),
      userVerification: cfg.userVerification,
      timeout: 120000,
    } });
    const r = cred.response;
    const res = await fetch(location.pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision, credentialId: toB64(cred.rawId), clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.authenticatorData), signature: toB64(r.signature) }),
    });
    const out = await res.json();
    const done = { approved: 'Approved. The agent will complete the payment on its next retry.', remember: 'Approved, and this service is now on your list. The agent will complete the payment on its next retry.', denied: 'Denied.' };
    if (res.ok) { say(done[decision], 'ok'); return; }
    say('Rejected: ' + out.error, 'bad');
  } catch (err) {
    say('Cancelled: ' + err.message, 'bad');
  }
  lock(false);
}
document.getElementById('approve')?.addEventListener('click', () => decide('approved'));
document.getElementById('deny')?.addEventListener('click', () => decide('denied'));
document.getElementById('remember')?.addEventListener('click', () => decide('remember'));
`;
  return shell(title, content, cfg, script);
}

export function registrationPage(cfg: {
  rpId: string;
  challenge: string;
  userId: string;
  name: string;
  userVerification: string;
  exclude: string[];
}): Page {
  const content = `
<h1>Register a passkey for bursar</h1>
<p class="muted">This passkey will be required to approve payments above the approval threshold. The page works once and closes after registration.</p>
<dl>${`<dt>Name</dt><dd>${escapeHtml(cfg.name)}</dd><dt>Relying party</dt><dd>${escapeHtml(cfg.rpId)}</dd>`}</dl>
<div class="actions"><button class="primary" id="register" type="button">Create passkey</button></div>`;
  const script = `
document.getElementById('register').addEventListener('click', async () => {
  lock(true);
  say('Follow your browser prompt...');
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: cfg.rpId, name: 'bursar' },
      user: { id: fromB64(cfg.userId), name: cfg.name, displayName: cfg.name },
      challenge: fromB64(cfg.challenge),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: cfg.userVerification, residentKey: 'preferred' },
      excludeCredentials: cfg.exclude.map((id) => ({ type: 'public-key', id: fromB64(id) })),
      attestation: 'none',
      timeout: 120000,
    } });
    const r = cred.response;
    const res = await fetch(location.pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credentialId: toB64(cred.rawId), clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.getAuthenticatorData()), publicKey: toB64(r.getPublicKey()), algorithm: r.getPublicKeyAlgorithm() }),
    });
    const out = await res.json();
    if (res.ok) { say('Passkey registered. You can close this page.', 'ok'); return; }
    say('Rejected: ' + out.error, 'bad');
  } catch (err) {
    say('Cancelled: ' + err.message, 'bad');
  }
  lock(false);
});
`;
  return shell('Register bursar passkey', content, cfg, script);
}
