import { hexToBytes } from '@noble/hashes/utils.js';
import { addr, signTyped, Transaction } from 'micro-eth-signer';
import type { EvmTxPlan, X402EvmPlan } from '../intent.ts';

const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

export function evmAddress(key: Uint8Array): string {
  return addr.fromPrivateKey(key);
}

export function transferAuthorizationTypedData(
  from: string,
  plan: X402EvmPlan,
) {
  return {
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: 'TransferWithAuthorization' as const,
    domain: plan.domain,
    message: {
      from,
      ...plan.message,
      nonce: hexToBytes(plan.message.nonce.replace(/^0x/, '')),
    },
  };
}

export function signTransferAuthorization(
  key: Uint8Array,
  plan: X402EvmPlan,
  from: string = evmAddress(key),
): { signature: string; authorization: Record<string, string> } {
  const signature = signTyped(transferAuthorizationTypedData(from, plan), key);
  return {
    signature,
    authorization: {
      from,
      to: plan.message.to,
      value: plan.message.value.toString(),
      validAfter: plan.message.validAfter.toString(),
      validBefore: plan.message.validBefore.toString(),
      nonce: plan.message.nonce,
    },
  };
}

export function signEvmTransaction(
  key: Uint8Array,
  plan: EvmTxPlan,
): { signedTx: string; hash: string } {
  const t = plan.tx;
  const tx = Transaction.prepare({
    type: 'eip1559',
    to: t.to,
    value: t.value,
    nonce: t.nonce,
    gasLimit: t.gasLimit,
    maxFeePerGas: t.maxFeePerGas,
    maxPriorityFeePerGas: t.maxPriorityFeePerGas,
    chainId: t.chainId,
    data: t.data.replace(/^0x/, ''),
  });
  const signed = tx.signBy(key);
  return { signedTx: signed.toHex(), hash: signed.hash };
}
