import type { IncomingMessage } from 'node:http';
import type { AuditLog } from '../audit.ts';
import type { Policy } from '../config.ts';
import type { Ledger } from '../ledger/store.ts';
import { approvalPage } from '../approval/pages.ts';
import {
  approvalChallenge,
  b64url,
  parseAssertionBody,
  PasskeyError,
  RP_ID,
  verifyAssertion,
} from '../approval/passkey.ts';
import { currencyOfChain } from '../config.ts';
import { toBudgetUnits } from '../policy/limits.ts';
import { formatUsd, isRecord } from '../util.ts';
import { resolveApproval } from '../approval/resolve.ts';
import type { HttpResult } from './server.ts';

export type ApprovalDeps = {
  policy: Policy;
  ledger: Ledger;
  audit: AuditLog;
  now: () => number;
  origin: string;
};

const MAX_BODY = 16 * 1024;

class Rollback extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function err(status: number, error: string): HttpResult {
  return { status, body: { status: 'error', error } };
}

// What the page shows as the amount, fee included: "$0.10", or "120 sat"
// for Cashu payments in satoshis (never converted).
function displayAmount(intent: Record<string, unknown>): string | null {
  const amount = intent['amount'];
  const decimals = intent['decimals'];
  if (
    typeof amount !== 'string' ||
    !/^\d+$/.test(amount) ||
    typeof decimals !== 'number'
  )
    return null;
  const currency = currencyOfChain(String(intent['chain']));
  let total = toBudgetUnits(currency, BigInt(amount), decimals);
  const fee = intent['fee'];
  if (
    isRecord(fee) &&
    typeof fee['amount'] === 'string' &&
    /^\d+$/.test(fee['amount']) &&
    typeof fee['decimals'] === 'number'
  )
    total += toBudgetUnits(currency, BigInt(fee['amount']), fee['decimals']);
  return currency === 'sat' ? `${total} sat` : `$${formatUsd(total)}`;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new PasskeyError('body_too_large');
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new PasskeyError('body_invalid');
  }
}

export async function handleApprovalRoute(
  req: IncomingMessage,
  url: URL,
  deps: ApprovalDeps,
): Promise<HttpResult> {
  const { ledger, audit, now, origin } = deps;
  const m = /^\/approve\/(apr_[0-9a-f]{24})$/.exec(url.pathname);
  if (!m || m[1] === undefined) return err(404, 'not_found');
  const id = m[1];
  const hostName = (req.headers.host ?? '').replace(/:\d+$/, '');
  if (hostName !== 'localhost') {
    if (req.method === 'GET')
      return {
        status: 302,
        body: '',
        headers: { location: `${origin}${url.pathname}` },
      };
    return err(403, 'use_localhost');
  }
  const approval = ledger.getApproval(id);
  if (approval === null) return err(404, 'not_found');
  const userVerification =
    deps.policy.limits.approval?.userVerification ?? 'required';
  const newRecipient = approval.context.reason === 'new_recipient';

  if (req.method === 'GET') {
    const intent = JSON.parse(approval.intentJson) as Record<string, unknown>;
    const page = approvalPage(
      {
        id,
        agent: approval.agent,
        status: approval.status,
        expiresAt: approval.expiresAt,
        intent,
        amount: displayAmount(intent),
        pending: approval.status === 'pending' && now() < approval.expiresAt,
        newRecipient,
        resourceUrl: approval.context.resourceUrl,
      },
      {
        rpId: RP_ID,
        challenges: {
          approved: b64url(
            approvalChallenge(id, approval.intentJson, 'approved'),
          ),
          denied: b64url(approvalChallenge(id, approval.intentJson, 'denied')),
          ...(newRecipient
            ? {
                remember: b64url(
                  approvalChallenge(id, approval.intentJson, 'remember'),
                ),
              }
            : {}),
        },
        credentials: ledger.listPasskeys().map((p) => p.credentialId),
        userVerification,
      },
    );
    return { status: 200, body: page.body, headers: page.headers };
  }

  if (req.method !== 'POST') return err(405, 'method_not_allowed');
  if (!(req.headers['content-type'] ?? '').startsWith('application/json'))
    return err(415, 'content_type');
  if (req.headers.origin !== undefined && req.headers.origin !== origin)
    return err(403, 'origin_mismatch');
  let parsed: ReturnType<typeof parseAssertionBody>;
  try {
    parsed = parseAssertionBody(await readJson(req));
  } catch (e) {
    return err(400, e instanceof PasskeyError ? e.reason : 'body_invalid');
  }
  if (approval.status !== 'pending' || now() >= approval.expiresAt)
    return err(409, 'approval_not_pending');
  const cred = ledger.getPasskey(parsed.assertion.credentialId);
  if (cred === null) return err(403, 'unknown_credential');
  let signCount: number;
  try {
    signCount = verifyAssertion(cred, parsed.assertion, {
      challenge: approvalChallenge(id, approval.intentJson, parsed.decision),
      origin,
      userVerification,
    });
  } catch (e) {
    return err(403, e instanceof PasskeyError ? e.reason : 'assertion_invalid');
  }
  try {
    ledger.transaction(() => {
      if (!ledger.bumpSignCount(cred.credentialId, cred.signCount, signCount))
        throw new Rollback(409, 'sign_count_race');
      const outcome = resolveApproval(ledger, audit, id, parsed.decision, {
        now,
        via: 'passkey',
        method: 'passkey',
        credential: cred.name || cred.credentialId,
      });
      if (outcome === 'remember_not_allowed') throw new Rollback(400, outcome);
      if (outcome !== 'resolved')
        throw new Rollback(409, 'approval_not_pending');
    });
  } catch (e) {
    if (e instanceof Rollback) return err(e.status, e.message);
    throw e;
  }
  return { status: 200, body: { status: parsed.decision, approvalId: id } };
}
