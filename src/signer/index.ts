import type {
  EvmTxPlan,
  MppTempoPlan,
  PaymentIntent,
  SignPlan,
  X402EvmPlan,
  X402SvmPlan,
} from '../intent.ts';
import { normalizeAddress } from '../config.ts';
import { decodeTransferCall } from '../protocols/evm.ts';
import { tempoMaxFeeUnits } from '../protocols/mpp.ts';
import {
  evmAddress,
  signEvmTransaction,
  signTransferAuthorization,
} from './evm.ts';
import { loadKeys, type KeySource } from './keystore.ts';
import { signX402Svm, solanaAddress } from './solana.ts';
import { signTempoTransaction } from './tempo.ts';

export type { KeySource } from './keystore.ts';

export type SignOutput =
  | {
      kind: 'eip3009';
      signature: string;
      authorization: Record<string, string>;
    }
  | { kind: 'svm'; signature: string; transaction: string }
  | { kind: 'evm-tx'; signedTx: string; hash: string };

export type Signer = {
  sign(intent: PaymentIntent): SignOutput;
  addresses(): { evm: string | null; solana: string | null };
  close(): void;
};

export class SignerError extends Error {
  override name = 'SignerError';
}

function same(a: string, b: string): boolean {
  return normalizeAddress(a) === normalizeAddress(b);
}

function assertMatches(
  intent: PaymentIntent,
  recipient: string,
  amount: bigint,
  asset: string,
  chain: string,
): void {
  if (
    !same(intent.recipient, recipient) ||
    intent.amount !== amount ||
    !same(intent.asset, asset) ||
    intent.chain !== chain
  ) {
    throw new SignerError('intent does not match the payload being signed');
  }
}

export function openSigner(source: KeySource): Signer {
  const keys = loadKeys(source);
  let closed = false;
  const evmAddr = keys.evm === null ? null : evmAddress(keys.evm);
  const solAddr = keys.solana === null ? null : solanaAddress(keys.solana);

  function need(k: Uint8Array | null, name: string): Uint8Array {
    if (closed) throw new SignerError('signer is closed');
    if (k === null) throw new SignerError(`no ${name} key loaded`);
    return k;
  }

  function signX402Evm(intent: PaymentIntent, p: X402EvmPlan): SignOutput {
    assertMatches(
      intent,
      p.message.to,
      p.message.value,
      p.domain.verifyingContract,
      `eip155:${p.domain.chainId}`,
    );
    return {
      kind: 'eip3009',
      ...signTransferAuthorization(need(keys.evm, 'evm'), p, evmAddr as string),
    };
  }

  function signSvm(intent: PaymentIntent, p: X402SvmPlan): SignOutput {
    if (!intent.chain.startsWith('solana:'))
      throw new SignerError('chain mismatch');
    assertMatches(intent, p.payTo, p.amount, p.mint, intent.chain);
    if (p.decimals !== intent.decimals)
      throw new SignerError('decimals mismatch');
    return {
      kind: 'svm',
      ...signX402Svm(need(keys.solana, 'solana'), p, solAddr as string),
    };
  }

  function signTx(intent: PaymentIntent, p: EvmTxPlan): SignOutput {
    const d = decodeTransferCall(p.tx.to, p.tx.value, p.tx.data);
    assertMatches(
      intent,
      d.recipient,
      d.amount,
      d.asset,
      `eip155:${p.tx.chainId}`,
    );
    return { kind: 'evm-tx', ...signEvmTransaction(need(keys.evm, 'evm'), p) };
  }

  function signMpp(intent: PaymentIntent, p: MppTempoPlan): SignOutput {
    assertMatches(
      intent,
      p.recipient,
      p.amount,
      p.token,
      `eip155:${p.chainId}`,
    );
    if (p.fee === null) {
      if (intent.fee !== undefined) throw new SignerError('fee mismatch');
    } else if (
      p.fee.maxFeePerGas === null ||
      intent.fee === undefined ||
      !same(intent.fee.asset, p.fee.token) ||
      intent.fee.amount !== tempoMaxFeeUnits(p.fee.gasLimit, p.fee.maxFeePerGas)
    ) {
      throw new SignerError('network fee was not priced and checked by policy');
    }
    return signTempoTransaction(need(keys.evm, 'evm'), p);
  }

  return {
    sign(intent) {
      const p = intent.raw as SignPlan | null;
      switch (p?.kind) {
        case 'x402-evm':
          return signX402Evm(intent, p);
        case 'x402-svm':
          return signSvm(intent, p);
        case 'evm-tx':
          return signTx(intent, p);
        case 'mpp-tempo':
          return signMpp(intent, p);
        default:
          throw new SignerError('unsupported sign plan');
      }
    },
    addresses() {
      return { evm: evmAddr, solana: solAddr };
    },
    close() {
      if (closed) return;
      closed = true;
      keys.evm?.fill(0);
      keys.solana?.fill(0);
    },
  };
}
