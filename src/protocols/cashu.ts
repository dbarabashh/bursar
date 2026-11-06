// Cashu NUT-24: a 402 with `X-Cashu: creqA…|creqB…` asks for ecash in the
// retried request's `X-Cashu` header.
//
// Ecash is a bearer instrument and the request names no payee, so bursar
// decides who it is paying from what actually controls the money:
// - locked (nut10 P2PK): the recipient is the public key. Only its holder can
//   redeem the token, so the token may be handed to the agent like an x402
//   authorization.
// - unlocked: the recipient is the https origin of the resource, and bursar
//   delivers the token to that origin itself; the agent never holds it.
import {
  CASHU_DECIMALS,
  normalizeAddress,
  normalizeMintUrl,
  type CashuUnit,
} from '../config.ts';
import type { Lock } from '../cashu/wallet.ts';
import type { PaymentIntent } from '../intent.ts';
import {
  CashuFormatError,
  decodePaymentRequest,
  type PaymentRequest,
} from '../cashu/encoding.ts';
import { isRecord, sha256Hex } from '../util.ts';
import { AdapterError, bindResource, type AdapterContext } from './common.ts';

export type CashuDelivery = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
};

export type CashuPlan = {
  kind: 'cashu';
  unit: CashuUnit;
  amount: number;
  candidates: string[];
  lock: Lock | null;
  delivery: CashuDelivery | null;
};

// Tags that change who can spend a P2PK proof (NUT-11). The payment request
// comes from the agent, so any of these could hand the token back to it:
// `refund` + `locktime` lets a refund key spend after the lock, an expired
// `locktime` alone makes the proof anyone-can-spend, and `pubkeys` adds
// signers next to the allowlisted key.
const SPEND_PATH_TAGS = new Set([
  'pubkeys',
  'n_sigs',
  'locktime',
  'refund',
  'n_sigs_refund',
]);

const DROP_HEADERS = new Set([
  'host',
  'content-length',
  'connection',
  'transfer-encoding',
  'keep-alive',
  'upgrade',
  'te',
  'trailer',
  'proxy-authorization',
  'x-cashu',
]);

function parseLock(req: PaymentRequest): Lock | null {
  const n = req.nut10;
  if (n === undefined) return null;
  if (n.k !== 'P2PK')
    throw new AdapterError('cashu_lock_not_supported', `kind ${n.k}`);
  if (!/^0[23][0-9a-fA-F]{64}$/.test(n.d))
    throw new AdapterError(
      'payload_invalid',
      'nut10.d must be a compressed public key',
    );
  const seen = new Set<string>();
  for (const t of n.t) {
    const key = t[0] as string;
    if (SPEND_PATH_TAGS.has(key))
      throw new AdapterError(
        'cashu_lock_not_supported',
        `tag ${key} changes who can spend the token`,
      );
    if (seen.has(key))
      throw new AdapterError('payload_invalid', `duplicate tag ${key}`);
    seen.add(key);
    if (
      key === 'sigflag' &&
      (t.length !== 2 || (t[1] !== 'SIG_INPUTS' && t[1] !== 'SIG_ALL'))
    )
      throw new AdapterError('payload_invalid', 'bad sigflag');
  }
  return { pubkey: n.d.toLowerCase(), tags: n.t };
}

function parseDelivery(v: unknown, ctx: AdapterContext): CashuDelivery | null {
  if (v === undefined || v === null) return null;
  if (!isRecord(v))
    throw new AdapterError('payload_invalid', 'deliver must be an object');
  if (ctx.resource === null)
    throw new AdapterError(
      'resource_required',
      'deliver needs resource {method, url, bodySha256}',
    );
  const headers: Record<string, string> = {};
  const h = v['headers'];
  if (h !== undefined) {
    if (!isRecord(h))
      throw new AdapterError(
        'payload_invalid',
        'deliver.headers must be an object',
      );
    const entries = Object.entries(h);
    if (entries.length > 50)
      throw new AdapterError('payload_invalid', 'too many headers');
    for (const [k, val] of entries) {
      if (typeof val !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(k))
        throw new AdapterError('payload_invalid', `bad header ${k}`);
      if (/[\r\n]/.test(val))
        throw new AdapterError('payload_invalid', `bad header value for ${k}`);
      if (!DROP_HEADERS.has(k.toLowerCase())) headers[k] = val;
    }
  }
  const body = v['body'];
  if (body !== undefined && body !== null && typeof body !== 'string')
    throw new AdapterError('payload_invalid', 'deliver.body must be a string');
  // The body bursar sends must be the one the resource hash covers.
  const want = ctx.resource.bodySha256?.toLowerCase();
  const got = sha256Hex(typeof body === 'string' ? body : '');
  if (want !== undefined && want !== got)
    throw new AdapterError(
      'resource_hash_mismatch',
      'deliver.body does not match resource.bodySha256',
    );
  let url: URL;
  try {
    url = new URL(ctx.resource.url);
  } catch {
    throw new AdapterError('payload_invalid', 'resource.url is not a URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:')
    throw new AdapterError('payload_invalid', 'resource.url must be http(s)');
  if (url.username !== '' || url.password !== '')
    throw new AdapterError('payload_invalid', 'resource.url has credentials');
  url.hash = '';
  return {
    method: ctx.resource.method.toUpperCase(),
    url: url.href,
    headers,
    body: typeof body === 'string' ? body : null,
  };
}

export function parseCashu(
  payload: unknown,
  ctx: AdapterContext,
): PaymentIntent {
  if (!isRecord(payload))
    throw new AdapterError('payload_invalid', 'payload must be an object');
  for (const k of Object.keys(payload))
    if (k !== 'paymentRequest' && k !== 'deliver')
      throw new AdapterError('payload_invalid', `unknown field ${k}`);
  const raw = payload['paymentRequest'];
  if (typeof raw !== 'string')
    throw new AdapterError(
      'payload_invalid',
      'paymentRequest must be the X-Cashu header value',
    );
  let req: PaymentRequest;
  try {
    req = decodePaymentRequest(raw);
  } catch (e) {
    if (e instanceof CashuFormatError)
      throw new AdapterError('payload_invalid', e.message);
    throw e;
  }
  if (req.a === undefined || req.a <= 0)
    throw new AdapterError('payload_invalid', 'payment request has no amount');
  if (req.u !== 'sat' && req.u !== 'usd')
    throw new AdapterError('unit_not_supported', String(req.u));
  const candidates: string[] = [];
  for (const m of req.m ?? []) {
    try {
      const u = normalizeMintUrl(m);
      if (!candidates.includes(u)) candidates.push(u);
    } catch {
      // not a usable mint URL; skip it
    }
  }
  if (candidates.length === 0)
    throw new AdapterError('payload_invalid', 'payment request names no mint');
  const lock = parseLock(req);
  const delivery = parseDelivery(payload['deliver'], ctx);
  let recipient: string;
  if (lock !== null) recipient = normalizeAddress(lock.pubkey);
  else {
    if (delivery === null)
      throw new AdapterError(
        'cashu_delivery_required',
        'an unlocked Cashu payment is delivered by bursar: send deliver {headers, body} with resource {method, url, bodySha256}',
      );
    recipient = new URL(delivery.url).origin;
  }
  const resourceHash = bindResource(ctx, null);
  const plan: CashuPlan = {
    kind: 'cashu',
    unit: req.u,
    amount: req.a,
    candidates,
    lock,
    delivery,
  };
  const intent: PaymentIntent = {
    protocol: 'cashu',
    chain: `cashu:${req.u}`,
    asset: candidates[0] as string,
    recipient,
    amount: BigInt(req.a),
    decimals: CASHU_DECIMALS[req.u],
    idempotencyKey: ctx.idempotencyKey,
    agentId: ctx.agentId,
    raw: plan,
  };
  if (resourceHash !== undefined) intent.resourceHash = resourceHash;
  if (ctx.resource !== null) intent.resourceUrl = ctx.resource.url;
  return intent;
}
