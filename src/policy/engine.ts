import type { Policy } from '../config.ts';
import type { PaymentIntent } from '../intent.ts';
import { stablecoinUnitsToMicroUsd } from '../util.ts';
import { checkAllowlist, findAsset } from './allowlist.ts';
import { checkLimits, type LedgerSnapshot } from './limits.ts';

export type Decision =
  | { kind: 'allow'; usd: bigint; feeUsd: bigint }
  | { kind: 'require_approval'; usd: bigint; feeUsd: bigint }
  | { kind: 'deny'; reason: string; usd: bigint | null };

export type EvaluateOptions = { approved: boolean };

export function evaluate(
  policy: Policy,
  intent: PaymentIntent,
  snap: LedgerSnapshot,
  opts: EvaluateOptions,
): Decision {
  const allow = checkAllowlist(policy, intent);
  if (!allow.ok) return { kind: 'deny', reason: allow.reason, usd: null };
  if (intent.amount <= 0n)
    return { kind: 'deny', reason: 'amount_invalid', usd: null };
  if (intent.decimals !== allow.asset.decimals)
    return { kind: 'deny', reason: 'decimals_mismatch', usd: null };
  if (intent.memo !== undefined && intent.memo.length !== 32)
    return { kind: 'deny', reason: 'memo_invalid', usd: null };
  if (policy.requireResourceHash && intent.resourceHash === undefined) {
    return { kind: 'deny', reason: 'resource_hash_required', usd: null };
  }
  let feeUsd = 0n;
  if (intent.fee !== undefined) {
    const feeAsset = findAsset(policy, intent.chain, intent.fee.asset);
    if (!feeAsset)
      return { kind: 'deny', reason: 'fee_asset_not_allowed', usd: null };
    if (intent.fee.decimals !== feeAsset.decimals)
      return { kind: 'deny', reason: 'decimals_mismatch', usd: null };
    feeUsd = stablecoinUnitsToMicroUsd(intent.fee.amount, feeAsset.decimals);
    if (intent.protocol !== 'mpp' || feeUsd > policy.tempo.maxFeeUsd)
      return { kind: 'deny', reason: 'network_fee_too_high', usd: null };
  }
  const amountUsd = stablecoinUnitsToMicroUsd(
    intent.amount,
    allow.asset.decimals,
  );
  const usd = amountUsd + feeUsd;
  const limitReason = checkLimits(
    policy,
    usd,
    amountUsd,
    allow.recipient,
    snap,
  );
  if (limitReason !== null) return { kind: 'deny', reason: limitReason, usd };
  const approval = policy.limits.approval;
  if (approval !== null && usd > approval.threshold && !opts.approved)
    return { kind: 'require_approval', usd, feeUsd };
  return { kind: 'allow', usd, feeUsd };
}
