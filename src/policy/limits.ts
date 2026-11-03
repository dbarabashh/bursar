import type { Policy, RecipientRule } from '../config.ts';

export type LedgerSnapshot = {
  daySpent: bigint;
  recipientDaySpent: bigint;
  walletDaySpent: bigint;
  monthSpent: bigint;
  recentTxCount: number;
  task: { budget: bigint; spent: bigint } | null;
};

const DAY_MS = 86_400_000;
const MONTH_ROLLING_MS = 30 * DAY_MS;

export function monthStart(policy: Policy, now: number): number {
  if (policy.limits.perMonth?.window === 'rolling_30d')
    return now - MONTH_ROLLING_MS;
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
}

export function monthEnd(policy: Policy, now: number): number | null {
  if (policy.limits.perMonth?.window === 'rolling_30d') return null;
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
}

export function windowStart(policy: Policy, now: number): number {
  if (policy.limits.window === 'rolling_24h') return now - DAY_MS;
  return Math.floor(now / DAY_MS) * DAY_MS;
}

export function windowEnd(policy: Policy, now: number): number | null {
  if (policy.limits.window === 'rolling_24h') return null;
  return windowStart(policy, now) + DAY_MS;
}

export function velocityStart(policy: Policy, now: number): number {
  const v = policy.limits.velocity;
  return v === null ? now : now - v.perSeconds * 1000;
}

export function recipientDayLimit(
  policy: Policy,
  rule: RecipientRule | null,
): bigint | null {
  if (rule !== null && rule.maxUsdDay !== null) return rule.maxUsdDay;
  return policy.limits.perRecipientDay;
}

export function checkLimits(
  policy: Policy,
  usd: bigint,
  recipientUsd: bigint,
  rule: RecipientRule | null,
  snap: LedgerSnapshot,
): string | null {
  if (usd > policy.limits.perTx) return 'per_tx_limit';
  if (snap.task !== null && snap.task.spent + usd > snap.task.budget)
    return 'task_budget_limit';
  const v = policy.limits.velocity;
  if (v !== null && snap.recentTxCount >= v.maxTx) return 'velocity_limit';
  const recipientLimit = recipientDayLimit(policy, rule);
  if (
    recipientLimit !== null &&
    snap.recipientDaySpent + recipientUsd > recipientLimit
  )
    return 'per_recipient_day_limit';
  if (snap.daySpent + usd > policy.limits.perDay) return 'per_day_limit';
  if (
    policy.limits.walletPerDay !== null &&
    snap.walletDaySpent + usd > policy.limits.walletPerDay
  )
    return 'wallet_per_day_limit';
  if (
    policy.limits.perMonth !== null &&
    snap.monthSpent + usd > policy.limits.perMonth.usd
  )
    return 'per_month_limit';
  return null;
}
