import { bytesToHex } from '@noble/hashes/utils.js';
import type { PaymentIntent, X402EvmPlan, X402SvmPlan } from '../intent.ts';
import { isRecord, parseDecimalAmount } from '../util.ts';
import {
  AdapterError,
  bindResource,
  isEvmAddress,
  requireString,
  requireUintString,
  rpcCall,
  type AdapterContext,
} from './common.ts';

const NETWORK_ALIASES: Record<string, string> = {
  base: 'eip155:8453',
  'base-sepolia': 'eip155:84532',
  avalanche: 'eip155:43114',
  'avalanche-fuji': 'eip155:43113',
  polygon: 'eip155:137',
  'polygon-amoy': 'eip155:80002',
  solana: 'solana:mainnet',
  'solana-devnet': 'solana:devnet',
  'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': 'solana:mainnet',
  'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1': 'solana:devnet',
};

export function canonicalChain(network: string): string | null {
  const alias = NETWORK_ALIASES[network];
  if (alias !== undefined) return alias;
  if (/^eip155:[1-9]\d*$/.test(network)) return network;
  if (network === 'solana:mainnet' || network === 'solana:devnet')
    return network;
  return null;
}

const DISPLAY_FIELDS = [
  'price',
  'displayAmount',
  'display_amount',
  'amountDisplay',
];

function checkDisplayAmounts(
  sources: Record<string, unknown>[],
  amount: bigint,
  decimals: number,
): void {
  for (const src of sources) {
    for (const f of DISPLAY_FIELDS) {
      const v = src[f];
      if (v === undefined || v === null) continue;
      const parsed =
        typeof v === 'string' || typeof v === 'number'
          ? parseDecimalAmount(String(v), decimals)
          : null;
      if (parsed !== amount)
        throw new AdapterError(
          'display_amount_mismatch',
          `${f}=${String(v)} does not match signed amount`,
        );
    }
  }
}

function pickRequirement(
  payload: Record<string, unknown>,
  accepts: Record<string, unknown>[],
  ctx: AdapterContext,
): Record<string, unknown> {
  const idx = payload['accept'];
  if (idx !== undefined) {
    if (typeof idx !== 'number' || !Number.isInteger(idx))
      throw new AdapterError('payload_invalid', 'accept must be an index');
    const req = accepts[idx];
    if (!req)
      throw new AdapterError('payload_invalid', 'accept index out of range');
    return req;
  }
  const usable = accepts.filter(
    (r) =>
      r['scheme'] === 'exact' &&
      typeof r['network'] === 'string' &&
      canonicalChain(r['network']) !== null,
  );
  const preferred = usable.find(
    (r) =>
      typeof r['asset'] === 'string' &&
      ctx.isRouteAllowed(
        canonicalChain(r['network'] as string) as string,
        r['asset'],
      ),
  );
  const req = preferred ?? usable[0];
  if (!req) throw new AdapterError('no_supported_requirement');
  return req;
}

export function parseX402(
  payload: unknown,
  ctx: AdapterContext,
): PaymentIntent {
  if (!isRecord(payload))
    throw new AdapterError('payload_invalid', 'payload must be an object');
  const pr = payload['paymentRequired'];
  if (!isRecord(pr))
    throw new AdapterError(
      'payload_invalid',
      'paymentRequired must be the 402 response object',
    );
  const version = pr['x402Version'];
  if (version !== 1 && version !== 2)
    throw new AdapterError('x402_version_not_supported');
  const acceptsIn = pr['accepts'];
  if (
    !Array.isArray(acceptsIn) ||
    acceptsIn.length === 0 ||
    !acceptsIn.every(isRecord)
  ) {
    throw new AdapterError(
      'payload_invalid',
      'accepts must be a non-empty list',
    );
  }
  const req = pickRequirement(payload, acceptsIn, ctx);
  // TODO: not ready yet: x402 schemes other than "exact" (e.g. "upto").
  if (req['scheme'] !== 'exact') throw new AdapterError('scheme_not_supported');
  const network = requireString(req['network'], 'network');
  const chain = canonicalChain(network);
  if (chain === null) throw new AdapterError('network_not_supported', network);
  const asset = requireString(req['asset'], 'asset');
  const payTo = requireString(req['payTo'], 'payTo');
  const amount = requireUintString(
    version === 2
      ? (req['amount'] ?? req['maxAmountRequired'])
      : req['maxAmountRequired'],
    'amount',
  );
  const resource = version === 2 ? pr['resource'] : req['resource'];
  const resourceUrl =
    typeof resource === 'string'
      ? resource
      : isRecord(resource) && typeof resource['url'] === 'string'
        ? resource['url']
        : null;
  // When the agent says which resource it asked for, a 402 that names none
  // cannot be checked against it, so it is refused rather than signed.
  if (ctx.resource !== null && resourceUrl === null)
    throw new AdapterError(
      'resource_hash_mismatch',
      'payment requirements name no resource',
    );
  const resourceHash = bindResource(ctx, resourceUrl);
  const extra = isRecord(req['extra']) ? req['extra'] : {};

  const knownDecimals = ctx.decimalsFor(chain, asset);
  if (knownDecimals !== undefined)
    checkDisplayAmounts([req, extra], amount, knownDecimals);
  const decimals = knownDecimals ?? 0;

  let raw: X402EvmPlan | X402SvmPlan;

  if (chain.startsWith('eip155:')) {
    if (!isEvmAddress(payTo) || !isEvmAddress(asset))
      throw new AdapterError(
        'payload_invalid',
        'payTo and asset must be EVM addresses',
      );
    const name = requireString(extra['name'], 'extra.name');
    const ver = requireString(extra['version'], 'extra.version');
    const nowSec = BigInt(Math.floor(ctx.now / 1000));
    const timeoutIn = req['maxTimeoutSeconds'];
    const timeout =
      typeof timeoutIn === 'number' && Number.isInteger(timeoutIn)
        ? Math.min(Math.max(timeoutIn, 1), 3600)
        : 60;
    raw = {
      kind: 'x402-evm',
      x402Version: version,
      network,
      accepted: req,
      resource: resource ?? null,
      domain: {
        name,
        version: ver,
        chainId: BigInt(chain.slice('eip155:'.length)),
        verifyingContract: asset,
      },
      message: {
        to: payTo,
        value: amount,
        validAfter: nowSec > 600n ? nowSec - 600n : 0n,
        validBefore: nowSec + BigInt(timeout),
        nonce: `0x${bytesToHex(ctx.random(32))}`,
      },
    };
  } else {
    const feePayer = requireString(extra['feePayer'], 'extra.feePayer');
    const svm = isRecord(payload['solana']) ? payload['solana'] : {};
    const blockhash =
      typeof svm['recentBlockhash'] === 'string'
        ? svm['recentBlockhash']
        : null;
    raw = {
      kind: 'x402-svm',
      x402Version: version,
      network,
      accepted: req,
      resource: resource ?? null,
      mint: asset,
      payTo,
      amount,
      decimals,
      feePayer,
      blockhash,
    };
  }

  const intent: PaymentIntent = {
    protocol: 'x402',
    chain,
    asset,
    recipient: payTo,
    amount,
    decimals,
    idempotencyKey: ctx.idempotencyKey,
    agentId: ctx.agentId,
    raw,
  };
  if (resourceHash !== undefined) intent.resourceHash = resourceHash;
  if (resourceUrl !== null) intent.resourceUrl = resourceUrl;
  return intent;
}

export type X402Signed =
  | {
      kind: 'eip3009';
      signature: string;
      authorization: Record<string, string>;
    }
  | { kind: 'svm'; signature: string; transaction: string };

export function x402Response(
  plan: X402EvmPlan | X402SvmPlan,
  signed: X402Signed,
): Record<string, unknown> {
  const inner =
    signed.kind === 'eip3009'
      ? { signature: signed.signature, authorization: signed.authorization }
      : { transaction: signed.transaction };
  const payment =
    plan.x402Version === 1
      ? {
          x402Version: 1,
          scheme: 'exact',
          network: plan.network,
          payload: inner,
        }
      : {
          x402Version: 2,
          resource: plan.resource,
          accepted: plan.accepted,
          payload: inner,
        };
  const value = Buffer.from(JSON.stringify(payment), 'utf8').toString('base64');
  const out: Record<string, unknown> = {
    signature: signed.signature,
    header: {
      name: plan.x402Version === 1 ? 'X-PAYMENT' : 'PAYMENT-SIGNATURE',
      value,
    },
    payment,
  };
  if (signed.kind === 'svm') out['signedTx'] = signed.transaction;
  return out;
}

export async function fetchSolanaBlockhash(
  rpcUrl: string,
): Promise<string | null> {
  try {
    const json = (await rpcCall(rpcUrl, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
    ])) as { result?: { value?: { blockhash?: string } } };
    return json.result?.value?.blockhash ?? null;
  } catch {
    return null;
  }
}
