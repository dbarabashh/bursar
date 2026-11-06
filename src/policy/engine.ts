import { currencyOfChain, type Policy, type RecipientRule } from '../config.ts';
import type { PaymentIntent } from '../intent.ts';
import { checkAllowlist, findAsset } from './allowlist.ts';
import {
  budgetFor,
  checkLimits,
  toBudgetUnits,
  type LedgerSnapshot,
} from './limits.ts';

// `usd` and `feeUsd` are in the payment's budget units: micro-dollars, or
// satoshis on cashu:sat (see currencyOfChain). Never converted between them.
export type Decision =
  | { kind: 'allow'; usd: bigint; feeUsd: bigint }
  | {
      kind: 'require_approval';
      usd: bigint;
      feeUsd: bigint;
      reason: ApprovalReason;
    }
  | { kind: 'deny'; reason: string; usd: bigint | null };

export type ApprovalReason = 'threshold' | 'new_recipient';

export type EvaluateOptions = {
  approved: boolean;
  learned?: readonly RecipientRule[];
};

const deny = (reason: string, usd: bigint | null = null): Decision => ({
  kind: 'deny',
  reason,
  usd,
});

// The most a payment may add in network or mint fees; null: no fee allowed.
function maxFee(policy: Policy, intent: PaymentIntent): bigint | null {
  switch (intent.protocol) {
    case 'mpp':
      return policy.tempo.maxFeeUsd;
    case 'cashu':
      return policy.cashu?.maxFee[currencyOfChain(intent.chain)] ?? null;
    default:
      return null;
  }
}

export function evaluate(
  policy: Policy,
  intent: PaymentIntent,
  snap: LedgerSnapshot,
  opts: EvaluateOptions,
): Decision {
  const currency = currencyOfChain(intent.chain);
  const allow = checkAllowlist(policy, intent, opts.learned ?? []);
  if (!allow.ok) return deny(allow.reason);
  const budget = budgetFor(policy, currency);
  if (budget === null) return deny('unit_not_allowed');
  if (intent.amount <= 0n) return deny('amount_invalid');
  if (intent.decimals !== allow.asset.decimals)
    return deny('decimals_mismatch');
  if (intent.memo !== undefined && intent.memo.length !== 32)
    return deny('memo_invalid');
  if (policy.requireResourceHash && intent.resourceHash === undefined)
    return deny('resource_hash_required');
  let fee = 0n;
  if (intent.fee !== undefined) {
    const feeAsset = findAsset(policy, intent.chain, intent.fee.asset);
    if (!feeAsset) return deny('fee_asset_not_allowed');
    if (intent.fee.decimals !== feeAsset.decimals)
      return deny('decimals_mismatch');
    fee = toBudgetUnits(currency, intent.fee.amount, feeAsset.decimals);
    const cap = maxFee(policy, intent);
    if (cap === null || fee > cap) return deny('network_fee_too_high');
  }
  const amount = toBudgetUnits(currency, intent.amount, allow.asset.decimals);
  const total = amount + fee;
  const limitReason = checkLimits(
    policy,
    budget,
    total,
    amount,
    allow.recipient,
    snap,
  );
  if (limitReason !== null) return deny(limitReason, total);
  if (allow.unknown && !opts.approved)
    return {
      kind: 'require_approval',
      usd: total,
      feeUsd: fee,
      reason: 'new_recipient',
    };
  if (
    budget.approvalThreshold !== null &&
    total > budget.approvalThreshold &&
    !opts.approved
  )
    return {
      kind: 'require_approval',
      usd: total,
      feeUsd: fee,
      reason: 'threshold',
    };
  return { kind: 'allow', usd: total, feeUsd: fee };
}
