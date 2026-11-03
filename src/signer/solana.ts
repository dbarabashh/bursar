import {
  getAddress,
  PROGRAMS,
  signTx,
  token,
  tokenAddress,
  Transaction,
  TOKEN_PROGRAM,
} from 'micro-sol-signer';
import type { X402SvmPlan } from '../intent.ts';

const computeBudget = PROGRAMS.computeBudget.program.instructions.encoders;

export function solanaAddress(key: Uint8Array): string {
  return getAddress(key);
}

export function buildX402SvmTransaction(
  owner: string,
  plan: X402SvmPlan,
): Uint8Array {
  if (plan.blockhash === null) throw new Error('missing recent blockhash');
  if (plan.feePayer === owner)
    throw new Error('fee payer must be the facilitator, not the bursar wallet');
  const instructions = [
    computeBudget.setComputeUnitLimit({ units: 20_000 }),
    computeBudget.setComputeUnitPrice({ microLamports: 1n }),
    token.transferChecked({
      source: tokenAddress({
        mint: plan.mint,
        owner,
        tokenProgram: TOKEN_PROGRAM,
      }),
      mint: plan.mint,
      destination: tokenAddress({
        mint: plan.mint,
        owner: plan.payTo,
        tokenProgram: TOKEN_PROGRAM,
      }),
      authority: owner,
      amount: plan.amount,
      decimals: plan.decimals,
    }),
  ];
  return Transaction.encode({
    msg: {
      version: 0,
      feePayer: plan.feePayer,
      blockhash: plan.blockhash,
      instructions,
    },
    signatures: {},
  });
}

export function signX402Svm(
  key: Uint8Array,
  plan: X402SvmPlan,
  owner: string = getAddress(key),
): { signature: string; transaction: string } {
  const [signature, transaction] = signTx(
    key,
    buildX402SvmTransaction(owner, plan),
  );
  return { signature, transaction };
}
