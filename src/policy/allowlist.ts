import {
  normalizeAddress,
  type AssetRule,
  type Policy,
  type RecipientRule,
} from '../config.ts';
import type { PaymentIntent } from '../intent.ts';

export type AllowlistResult =
  | { ok: true; asset: AssetRule; recipient: RecipientRule | null }
  | { ok: false; reason: string };

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
): AllowlistResult {
  if (!policy.allow.chains.includes(intent.chain))
    return { ok: false, reason: 'chain_not_allowed' };
  const asset = findAsset(policy, intent.chain, intent.asset);
  if (!asset) return { ok: false, reason: 'asset_not_allowed' };
  if (policy.allow.recipients === 'any')
    return { ok: true, asset, recipient: null };
  const addr = normalizeAddress(intent.recipient);
  const matches = policy.allow.recipients.filter((r) => r.address === addr);
  if (matches.length === 0)
    return { ok: false, reason: 'recipient_not_allowed' };
  const rule = matches.find((r) => onChain(r.chains, intent.chain));
  if (!rule) return { ok: false, reason: 'recipient_not_allowed_on_chain' };
  return { ok: true, asset, recipient: rule };
}
