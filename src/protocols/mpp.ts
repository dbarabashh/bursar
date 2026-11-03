import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import type { MppTempoPlan, PaymentIntent, TempoFeePlan } from '../intent.ts';
import { isRecord } from '../util.ts';
import {
  AdapterError,
  bindResource,
  isEvmAddress,
  requireString,
  requireUintString,
  type AdapterContext,
} from './common.ts';

export const TEMPO_DEFAULT_CHAIN_ID = 42431n;

export const ATTODOLLARS_PER_TOKEN_UNIT = 10n ** 12n;
export const TIP20_DECIMALS = 6;

export function tempoMaxFeeUnits(
  gasLimit: bigint,
  maxFeePerGas: bigint,
): bigint {
  return (
    (gasLimit * maxFeePerGas + ATTODOLLARS_PER_TOKEN_UNIT - 1n) /
    ATTODOLLARS_PER_TOKEN_UNIT
  );
}

export function applyTempoGasPrice(
  intent: PaymentIntent,
  gasPrice: bigint,
  maxFeeUsd: bigint,
): string | null {
  const plan = intent.raw as MppTempoPlan;
  if (plan.kind !== 'mpp-tempo' || plan.fee === null) return null;
  if (gasPrice <= 0n) return 'fee_price_unavailable';
  const capPerGas =
    (maxFeeUsd * ATTODOLLARS_PER_TOKEN_UNIT) / plan.fee.gasLimit;
  const maxFeePerGas = gasPrice * 2n < capPerGas ? gasPrice * 2n : capPerGas;
  if (maxFeePerGas < gasPrice) return 'network_fee_too_high';
  plan.fee.maxFeePerGas = maxFeePerGas;
  intent.fee = {
    asset: plan.fee.token,
    amount: tempoMaxFeeUnits(plan.fee.gasLimit, maxFeePerGas),
    decimals: TIP20_DECIMALS,
  };
  return null;
}

export const TRANSFER_WITH_MEMO_SELECTOR = `0x${bytesToHex(keccak_256(utf8ToBytes('transferWithMemo(address,uint256,bytes32)')).slice(0, 4))}`;

export type MppChallenge = {
  params: Record<string, string>;
  id: string;
  realm: string;
  method: string;
  intent: string;
  request: Record<string, unknown>;
  expires: string | null;
  digest: string | null;
};

const AUTH_PARAM =
  /(?:^|,)\s*(?:([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s+)?([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,"]+)/g;

export function parseChallengeHeaders(value: string): Record<string, string>[] {
  const out: Record<string, string>[] = [];
  let current: Record<string, string> | null = null;
  for (const m of value.matchAll(AUTH_PARAM)) {
    const scheme = m[1];
    if (scheme !== undefined) {
      current = scheme.toLowerCase() === 'payment' ? {} : null;
      if (current !== null) out.push(current);
    }
    const key = m[2];
    const raw = m[3];
    if (current === null || key === undefined || raw === undefined) continue;
    const v = raw.startsWith('"')
      ? raw.slice(1, -1).replace(/\\(.)/g, '$1')
      : raw;
    if (current[key] === undefined) current[key] = v;
  }
  return out;
}

function decodeRequest(v: unknown): Record<string, unknown> {
  if (isRecord(v)) return v;
  if (typeof v !== 'string')
    throw new AdapterError('payload_invalid', 'challenge.request missing');
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(v, 'base64url').toString('utf8'));
  } catch {
    throw new AdapterError(
      'payload_invalid',
      'challenge.request is not base64url JSON',
    );
  }
  if (!isRecord(parsed))
    throw new AdapterError(
      'payload_invalid',
      'challenge.request must be an object',
    );
  return parsed;
}

function toChallenge(o: Record<string, unknown>): MppChallenge {
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(o))
    if (typeof v === 'string') params[k] = v;
  return {
    params,
    id: requireString(o['id'], 'challenge.id'),
    realm: requireString(o['realm'], 'challenge.realm'),
    method: requireString(o['method'], 'challenge.method'),
    intent: requireString(o['intent'], 'challenge.intent'),
    request: decodeRequest(o['request']),
    expires: typeof o['expires'] === 'string' ? o['expires'] : null,
    digest: typeof o['digest'] === 'string' ? o['digest'] : null,
  };
}

function collectChallenges(input: unknown): Record<string, unknown>[] {
  if (typeof input === 'string') return parseChallengeHeaders(input);
  if (Array.isArray(input)) return input.flatMap(collectChallenges);
  if (isRecord(input)) return [input];
  throw new AdapterError(
    'payload_invalid',
    'challenge must be a WWW-Authenticate value, a list of them, or an object',
  );
}

function selectChallenge(input: unknown): MppChallenge {
  const all = collectChallenges(input);
  if (all.length === 0)
    throw new AdapterError('payload_invalid', 'no Payment challenge found');
  const tempo = all.find(
    (c) =>
      String(c['method']).toLowerCase() === 'tempo' &&
      String(c['intent']).toLowerCase() === 'charge',
  );
  if (tempo !== undefined) return toChallenge(tempo);
  const first = all[0] as Record<string, unknown>;
  if (String(first['method']).toLowerCase() !== 'tempo')
    throw new AdapterError('mpp_method_not_supported', String(first['method']));
  throw new AdapterError('mpp_intent_not_supported', String(first['intent']));
}

function checkDigest(digest: string, ctx: AdapterContext): void {
  const body = ctx.resource?.bodySha256;
  if (body === undefined) return;
  const m = /(?:^|,)\s*sha-256=:([A-Za-z0-9+/=]+):/.exec(digest);
  if (!m || m[1] === undefined) return;
  if (Buffer.from(m[1], 'base64').toString('hex') !== body.toLowerCase()) {
    throw new AdapterError(
      'resource_hash_mismatch',
      'challenge digest does not match the request body',
    );
  }
}

function word(hex: string): string {
  return hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
}

export function encodeTransferWithMemo(
  to: string,
  amount: bigint,
  memo: Uint8Array,
): string {
  return `${TRANSFER_WITH_MEMO_SELECTOR}${word(to)}${word(amount.toString(16))}${bytesToHex(memo)}`;
}

export function parseMpp(payload: unknown, ctx: AdapterContext): PaymentIntent {
  if (!isRecord(payload))
    throw new AdapterError('payload_invalid', 'payload must be an object');
  const challenge = selectChallenge(payload['challenge']);

  if (challenge.expires !== null) {
    const exp = Date.parse(challenge.expires);
    if (!Number.isFinite(exp))
      throw new AdapterError(
        'payload_invalid',
        'challenge.expires is not a timestamp',
      );
    if (exp <= ctx.now) throw new AdapterError('mpp_challenge_expired');
  }

  const req = challenge.request;
  const amount = requireUintString(req['amount'], 'request.amount');
  const token = requireString(req['currency'], 'request.currency');
  const recipient = requireString(req['recipient'], 'request.recipient');
  if (!isEvmAddress(token) || !isEvmAddress(recipient))
    throw new AdapterError(
      'payload_invalid',
      'currency and recipient must be addresses',
    );
  const details = isRecord(req['methodDetails']) ? req['methodDetails'] : {};
  const chainId =
    details['chainId'] === undefined
      ? TEMPO_DEFAULT_CHAIN_ID
      : requireUintString(details['chainId'], 'methodDetails.chainId');
  // TODO: not ready yet: MPP splits (one charge paid to several recipients).
  if (details['splits'] !== undefined)
    throw new AdapterError('mpp_splits_not_supported');
  // TODO: not ready yet: push mode (the client broadcasts the transaction itself); only pull is supported.
  const modes = details['supportedModes'];
  if (modes !== undefined && (!Array.isArray(modes) || !modes.includes('pull')))
    throw new AdapterError('mpp_mode_not_supported');
  const feePayer = details['feePayer'] === true;
  let fee: TempoFeePlan | null = null;
  if (!feePayer) {
    if (!ctx.tempo.allowClientPaidFees)
      throw new AdapterError('mpp_client_fees_not_allowed');
    fee = {
      token,
      gasLimit: ctx.tempo.gasLimit,
      maxFeePerGas: null,
      maxPriorityFeePerGas: 0n,
    };
  }

  const resourceHash = bindResource(ctx, null);
  if (challenge.digest !== null) checkDigest(challenge.digest, ctx);

  const serverMemo = details['memo'];
  let memo: Uint8Array;
  let memoSource: MppTempoPlan['memoSource'];
  if (serverMemo !== undefined) {
    if (
      typeof serverMemo !== 'string' ||
      !/^0x[0-9a-fA-F]{64}$/.test(serverMemo)
    ) {
      throw new AdapterError(
        'payload_invalid',
        'methodDetails.memo must be bytes32',
      );
    }
    memo = hexToBytes(serverMemo.slice(2));
    memoSource = 'server';
  } else if (resourceHash !== undefined) {
    memo = hexToBytes(resourceHash);
    memoSource = 'resource';
  } else {
    memo = sha256(utf8ToBytes(`mpp:${challenge.realm}:${challenge.id}`));
    memoSource = 'challenge';
  }

  const raw: MppTempoPlan = {
    kind: 'mpp-tempo',
    challenge: challenge.params,
    expires: challenge.expires,
    feePayer,
    memoSource,
    chainId,
    token,
    recipient,
    amount,
    memo,
    call: { to: token, data: encodeTransferWithMemo(recipient, amount, memo) },
    fee,
  };
  const chain = `eip155:${chainId}`;
  const intent: PaymentIntent = {
    protocol: 'mpp',
    chain,
    asset: token,
    recipient,
    amount,
    decimals: ctx.decimalsFor(chain, token) ?? 0,
    memo,
    idempotencyKey: ctx.idempotencyKey,
    agentId: ctx.agentId,
    raw,
  };
  if (resourceHash !== undefined) intent.resourceHash = resourceHash;
  return intent;
}
