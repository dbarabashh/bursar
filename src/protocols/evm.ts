import type { EvmTxPlan, PaymentIntent } from '../intent.ts';
import { isRecord, parseUint } from '../util.ts';
import {
  AdapterError,
  bindResource,
  isEvmAddress,
  requireString,
  rpcCall,
  type AdapterContext,
} from './common.ts';

export const SELECTORS = {
  transfer: '0xa9059cbb',
  transferWithAuthorization: '0xe3ee160e',
} as const;

export type DecodedTransfer = {
  asset: string;
  recipient: string;
  amount: bigint;
};

function words(data: string, count: number): string[] {
  const body = data.slice(10);
  if (body.length !== count * 64)
    throw new AdapterError('calldata_invalid', `expected ${count} ABI words`);
  return Array.from({ length: count }, (_, i) =>
    body.slice(i * 64, (i + 1) * 64),
  );
}

function addressWord(w: string | undefined): string {
  if (w === undefined || !/^0{24}[0-9a-f]{40}$/.test(w))
    throw new AdapterError('calldata_invalid', 'bad address word');
  return `0x${w.slice(24)}`;
}

function uintWord(w: string | undefined): bigint {
  if (w === undefined)
    throw new AdapterError('calldata_invalid', 'missing word');
  return BigInt(`0x${w}`);
}

export function decodeTransferCall(
  to: string,
  value: bigint,
  data: string,
  allowedSelectors?: string[],
): DecodedTransfer {
  const d = data.toLowerCase();
  if (!/^0x([0-9a-f]{2})*$/.test(d))
    throw new AdapterError('calldata_invalid', 'data must be hex');
  if (d === '0x') {
    if (value === 0n)
      throw new AdapterError('calldata_invalid', 'empty transaction');
    return { asset: 'native', recipient: to.toLowerCase(), amount: value };
  }
  const selector = d.slice(0, 10);
  if (allowedSelectors !== undefined && !allowedSelectors.includes(selector))
    throw new AdapterError('selector_not_allowed', selector);
  if (value !== 0n)
    throw new AdapterError(
      'calldata_invalid',
      'token call must not carry native value',
    );
  if (selector === SELECTORS.transfer) {
    const [w0, w1] = words(d, 2);
    return {
      asset: to.toLowerCase(),
      recipient: addressWord(w0),
      amount: uintWord(w1),
    };
  }
  if (selector === SELECTORS.transferWithAuthorization) {
    const w = words(d, 9);
    return {
      asset: to.toLowerCase(),
      recipient: addressWord(w[1]),
      amount: uintWord(w[2]),
    };
  }
  throw new AdapterError('selector_not_allowed', `${selector} has no decoder`);
}

function uint(v: unknown, field: string): bigint {
  try {
    return parseUint(v, field);
  } catch (e) {
    throw new AdapterError('payload_invalid', (e as Error).message);
  }
}

export function parseEvm(payload: unknown, ctx: AdapterContext): PaymentIntent {
  if (!isRecord(payload))
    throw new AdapterError('payload_invalid', 'payload must be an object');
  const to = requireString(payload['to'], 'to');
  if (!isEvmAddress(to))
    throw new AdapterError('payload_invalid', 'to must be an address');
  const dataIn = payload['data'] ?? '0x';
  if (typeof dataIn !== 'string')
    throw new AdapterError('payload_invalid', 'data must be hex');
  const tx: EvmTxPlan['tx'] = {
    chainId: uint(payload['chainId'], 'chainId'),
    to,
    value: uint(payload['value'] ?? 0, 'value'),
    data: dataIn.toLowerCase(),
    nonce: uint(payload['nonce'], 'nonce'),
    gasLimit: uint(payload['gasLimit'], 'gasLimit'),
    maxFeePerGas: uint(payload['maxFeePerGas'], 'maxFeePerGas'),
    maxPriorityFeePerGas: uint(
      payload['maxPriorityFeePerGas'] ?? payload['maxFeePerGas'],
      'maxPriorityFeePerGas',
    ),
  };
  if (tx.chainId === 0n)
    throw new AdapterError('payload_invalid', 'chainId required');
  if (tx.maxPriorityFeePerGas > tx.maxFeePerGas)
    throw new AdapterError('payload_invalid', 'priority fee above max fee');
  if (tx.gasLimit * tx.maxFeePerGas > ctx.evm.maxNetworkFeeWei)
    throw new AdapterError('network_fee_too_high');
  const decoded = decodeTransferCall(
    tx.to,
    tx.value,
    tx.data,
    ctx.evm.allowedSelectors,
  );
  const chain = `eip155:${tx.chainId}`;
  const resourceHash = bindResource(ctx, null);
  const raw: EvmTxPlan = { kind: 'evm-tx', tx };
  const intent: PaymentIntent = {
    protocol: 'evm',
    chain,
    asset: decoded.asset,
    recipient: decoded.recipient,
    amount: decoded.amount,
    decimals: ctx.decimalsFor(chain, decoded.asset) ?? 0,
    idempotencyKey: ctx.idempotencyKey,
    agentId: ctx.agentId,
    raw,
  };
  if (resourceHash !== undefined) intent.resourceHash = resourceHash;
  return intent;
}

export async function fetchGasPrice(rpcUrl: string): Promise<bigint | null> {
  try {
    const json = (await rpcCall(rpcUrl, 'eth_gasPrice', [])) as {
      result?: unknown;
    };
    return typeof json.result === 'string' &&
      /^0x[0-9a-fA-F]{1,64}$/.test(json.result)
      ? BigInt(json.result)
      : null;
  } catch {
    return null;
  }
}

export async function simulateEvmCall(
  rpcUrl: string,
  from: string,
  tx: EvmTxPlan['tx'],
): Promise<string | null> {
  const call = {
    from,
    to: tx.to,
    data: tx.data,
    value: `0x${tx.value.toString(16)}`,
    gas: `0x${tx.gasLimit.toString(16)}`,
  };
  try {
    const json = (await rpcCall(rpcUrl, 'eth_call', [call, 'latest'])) as {
      result?: string;
      error?: { message?: string };
    };
    if (json.error) return json.error.message ?? 'reverted';
    if (
      tx.data !== '0x' &&
      json.result !== undefined &&
      /^0x0*$/.test(json.result) &&
      json.result !== '0x'
    )
      return 'call returned false';
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}
