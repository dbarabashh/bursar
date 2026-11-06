import {
  normalizeAddress,
  type AssetRule,
  type Policy,
  type RecipientRule,
} from '../config.ts';
import type { PaymentIntent } from '../intent.ts';
import type { LearnedRecipient } from '../ledger/store.ts';

export type AllowlistResult =
  | {
      ok: true;
      asset: AssetRule;
      recipient: RecipientRule | null;
      unknown: boolean;
    }
  | { ok: false; reason: string };

export function learnedRule(r: LearnedRecipient): RecipientRule {
  return {
    address: r.address,
    label: r.label,
    maxUsdDay: null,
    chains: [r.chain],
  };
}

// Policy recipients plus the ones approved with a passkey, one entry per
// address (policy entries first), for listings such as budget and report.
export function listedRecipients(
  policy: Policy,
  learned: readonly LearnedRecipient[],
): RecipientRule[] | 'any' {
  if (policy.allow.recipients === 'any') return 'any';
  const out = new Map(policy.allow.recipients.map((r) => [r.address, r]));
  for (const l of learned) {
    const known = out.get(l.address);
    if (known === undefined) out.set(l.address, learnedRule(l));
    else if (known.chains !== null && !known.chains.includes(l.chain))
      out.set(l.address, { ...known, chains: [...known.chains, l.chain] });
  }
  return [...out.values()];
}

function onChain(chains: string[] | null, chain: string): boolean {
  return chains === null || chains.includes(chain);
}

export function findAsset(
  policy: Policy,
  chain: string,
  asset: string,
): AssetRule | undefined {
  const a = normalizeAddress(asset);
  return policy.allow.assets.find(
    (r) => r.address === a && onChain(r.chains, chain),
  );
}

export function isRouteAllowed(
  policy: Policy,
  chain: string,
  asset: string,
): boolean {
  return (
    policy.allow.chains.includes(chain) &&
    findAsset(policy, chain, asset) !== undefined
  );
}

export function checkAllowlist(
  policy: Policy,
  intent: PaymentIntent,
  learned: readonly RecipientRule[],
): AllowlistResult {
  if (!policy.allow.chains.includes(intent.chain))
    return { ok: false, reason: 'chain_not_allowed' };
  const asset = findAsset(policy, intent.chain, intent.asset);
  if (!asset) return { ok: false, reason: 'asset_not_allowed' };
  if (policy.allow.recipients === 'any')
    return { ok: true, asset, recipient: null, unknown: false };
  const addr = normalizeAddress(intent.recipient);
  const matches = [...policy.allow.recipients, ...learned].filter(
    (r) => r.address === addr,
  );
  // A max_usd_day set for the address applies on every chain, including
  // chains it was only learned on or is being asked for.
  let cap: bigint | null = null;
  for (const r of matches)
    if (r.maxUsdDay !== null && (cap === null || r.maxUsdDay < cap))
      cap = r.maxUsdDay;
  const capped = (r: RecipientRule): RecipientRule =>
    cap === null ? r : { ...r, maxUsdDay: cap };
  const rule = matches.find((r) => onChain(r.chains, intent.chain));
  if (rule) return { ok: true, asset, recipient: capped(rule), unknown: false };
  if (policy.allow.unknownRecipients === 'ask')
    return {
      ok: true,
      asset,
      recipient: cap === null ? null : capped({ ...matches[0]!, chains: null }),
      unknown: true,
    };
  return {
    ok: false,
    reason:
      matches.length === 0
        ? 'recipient_not_allowed'
        : 'recipient_not_allowed_on_chain',
  };
}
