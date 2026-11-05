import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256Hex } from './util.ts';

export type Protocol = 'x402' | 'mpp' | 'evm';

export const PROTOCOLS: readonly Protocol[] = ['x402', 'mpp', 'evm'];

export type PaymentIntent = {
  protocol: Protocol;
  chain: string;
  asset: string;
  recipient: string;
  amount: bigint;
  decimals: number;
  resourceHash?: string;
  resourceUrl?: string;
  memo?: Uint8Array;
  fee?: NetworkFee;
  idempotencyKey: string;
  agentId: string;
  raw: unknown;
};

export type NetworkFee = {
  asset: string;
  amount: bigint;
  decimals: number;
};

export type ResourceDescriptor = {
  method: string;
  url: string;
  bodySha256?: string;
};

export type X402EvmPlan = {
  kind: 'x402-evm';
  x402Version: 1 | 2;
  network: string;
  accepted: Record<string, unknown>;
  resource: unknown;
  domain: {
    name: string;
    version: string;
    chainId: bigint;
    verifyingContract: string;
  };
  message: {
    to: string;
    value: bigint;
    validAfter: bigint;
    validBefore: bigint;
    nonce: string;
  };
};

export type X402SvmPlan = {
  kind: 'x402-svm';
  x402Version: 1 | 2;
  network: string;
  accepted: Record<string, unknown>;
  resource: unknown;
  mint: string;
  payTo: string;
  amount: bigint;
  decimals: number;
  feePayer: string;
  blockhash: string | null;
};

export type EvmTxPlan = {
  kind: 'evm-tx';
  tx: {
    chainId: bigint;
    to: string;
    value: bigint;
    data: string;
    nonce: bigint;
    gasLimit: bigint;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
  };
};

export type MppTempoPlan = {
  kind: 'mpp-tempo';
  challenge: Record<string, string>;
  expires: string | null;
  feePayer: boolean;
  memoSource: 'server' | 'resource' | 'challenge';
  chainId: bigint;
  token: string;
  recipient: string;
  amount: bigint;
  memo: Uint8Array;
  call: { to: string; data: string };
  fee: TempoFeePlan | null;
};

export type TempoFeePlan = {
  token: string;
  gasLimit: bigint;
  maxFeePerGas: bigint | null;
  maxPriorityFeePerGas: bigint;
};

export type SignPlan = X402EvmPlan | X402SvmPlan | EvmTxPlan | MppTempoPlan;

export const EMPTY_BODY_SHA256 = sha256Hex(new Uint8Array());

export function computeResourceHash(r: ResourceDescriptor): string {
  const body = (r.bodySha256 ?? EMPTY_BODY_SHA256).toLowerCase();
  return sha256Hex(`${r.method.toUpperCase()} ${r.url}\n${body}`);
}

export function intentSummary(intent: PaymentIntent): Record<string, unknown> {
  const out: Record<string, unknown> = {
    protocol: intent.protocol,
    chain: intent.chain,
    asset: intent.asset,
    recipient: intent.recipient,
    amount: intent.amount.toString(),
    decimals: intent.decimals,
    idempotencyKey: intent.idempotencyKey,
    agentId: intent.agentId,
  };
  if (intent.resourceHash !== undefined)
    out['resourceHash'] = intent.resourceHash;
  if (intent.memo !== undefined) out['memo'] = `0x${bytesToHex(intent.memo)}`;
  if (intent.fee !== undefined)
    out['fee'] = {
      asset: intent.fee.asset,
      amount: intent.fee.amount.toString(),
      decimals: intent.fee.decimals,
    };
  return out;
}
