import type { Policy } from '../config.ts';
import { computeResourceHash, type ResourceDescriptor } from '../intent.ts';

export class AdapterError extends Error {
  override name = 'AdapterError';
  readonly reason: string;
  constructor(reason: string, detail?: string) {
    super(detail === undefined ? reason : `${reason}: ${detail}`);
    this.reason = reason;
  }
}

export async function rpcCall(
  url: string,
  method: string,
  params: unknown[],
): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(5000),
  });
  return res.json();
}

export type AdapterContext = {
  agentId: string;
  idempotencyKey: string;
  resourceHash: string | null;
  resource: ResourceDescriptor | null;
  now: number;
  random: (n: number) => Uint8Array;
  decimalsFor: (chain: string, asset: string) => number | undefined;
  isRouteAllowed: (chain: string, asset: string) => boolean;
  evm: Policy['evm'];
  tempo: Policy['tempo'];
};

function canonicalUrl(u: string): string | null {
  try {
    const url = new URL(u);
    url.hash = '';
    return url.href;
  } catch {
    return null;
  }
}

export function bindResource(
  ctx: AdapterContext,
  paymentUrl: string | null,
): string | undefined {
  let hash = ctx.resourceHash?.toLowerCase() ?? null;
  if (ctx.resource !== null) {
    const computed = computeResourceHash(ctx.resource);
    if (hash !== null && hash !== computed)
      throw new AdapterError('resource_hash_mismatch');
    hash = computed;
    if (
      paymentUrl !== null &&
      canonicalUrl(paymentUrl) !== canonicalUrl(ctx.resource.url)
    ) {
      throw new AdapterError(
        'resource_hash_mismatch',
        'payment is for a different resource',
      );
    }
  }
  return hash ?? undefined;
}

export function requireString(v: unknown, field: string): string {
  if (typeof v !== 'string' || v.length === 0)
    throw new AdapterError(
      'payload_invalid',
      `${field} must be a non-empty string`,
    );
  return v;
}

export function requireUintString(v: unknown, field: string): bigint {
  if (typeof v === 'string' && /^(0|[1-9]\d{0,77})$/.test(v)) return BigInt(v);
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0)
    return BigInt(v);
  throw new AdapterError(
    'payload_invalid',
    `${field} must be a base-10 integer`,
  );
}

export function isEvmAddress(v: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(v);
}
