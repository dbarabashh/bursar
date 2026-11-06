import type { Currency, Policy, RecipientRule } from '../config.ts';
import { stablecoinUnitsToMicroUsd } from '../util.ts';

export type LedgerSnapshot = {
  daySpent: bigint;
  recipientDaySpent: bigint;
  walletDaySpent: bigint;
  monthSpent: bigint;
  recentTxCount: number;
  task: { budget: bigint | null; spent: bigint } | null;
};

// The limits of one currency. USD amounts are micro-dollars, sat amounts are
// satoshis. A payment is checked against the budget of its own currency only;
// nothing is ever converted between them. Velocity counts every payment.
export type Budget = {
  currency: Currency;
  perTx: bigint;
  perDay: bigint;
  perRecipientDay: bigint | null;
  walletPerDay: bigint | null;
  perMonth: bigint | null;
  perTaskMax: bigint;
  approvalThreshold: bigint | null;
};

export function budgetFor(policy: Policy, currency: Currency): Budget | null {
  const l = policy.limits;
  if (currency === 'usd')
    return {
      currency,
      perTx: l.perTx,
      perDay: l.perDay,
      perRecipientDay: l.perRecipientDay,
      walletPerDay: l.walletPerDay,
      perMonth: l.perMonth?.usd ?? null,
      perTaskMax: l.perTask.maxUsd,
      approvalThreshold: l.approval?.threshold ?? null,
    };
  return l.sat === null ? null : { currency, ...l.sat };
}

// Payment amounts in the units budgets count: micro-dollars for USD, sats.
export function toBudgetUnits(
  currency: Currency,
  amount: bigint,
  decimals: number,
): bigint {
  return currency === 'sat'
    ? amount
    : stablecoinUnitsToMicroUsd(amount, decimals);
}

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
  budget: Budget,
  rule: RecipientRule | null,
): bigint | null {
  const own =
    rule === null
      ? null
      : budget.currency === 'usd'
        ? rule.maxUsdDay
        : rule.maxSatDay;
  if (own !== null) return own;
  return budget.perRecipientDay;
}

export function checkLimits(
  policy: Policy,
  budget: Budget,
  amount: bigint,
  recipientAmount: bigint,
  rule: RecipientRule | null,
  snap: LedgerSnapshot,
): string | null {
  if (amount > budget.perTx) return 'per_tx_limit';
  if (snap.task !== null) {
    if (snap.task.budget === null) return 'task_budget_limit';
    if (snap.task.spent + amount > snap.task.budget) return 'task_budget_limit';
  }
  const v = policy.limits.velocity;
  if (v !== null && snap.recentTxCount >= v.maxTx) return 'velocity_limit';
  const recipientLimit = recipientDayLimit(budget, rule);
  if (
    recipientLimit !== null &&
    snap.recipientDaySpent + recipientAmount > recipientLimit
  )
    return 'per_recipient_day_limit';
  if (snap.daySpent + amount > budget.perDay) return 'per_day_limit';
  if (
    budget.walletPerDay !== null &&
    snap.walletDaySpent + amount > budget.walletPerDay
  )
    return 'wallet_per_day_limit';
  if (budget.perMonth !== null && snap.monthSpent + amount > budget.perMonth)
    return 'per_month_limit';
  return null;
}
