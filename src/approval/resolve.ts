import type { AuditLog } from '../audit.ts';
import { normalizeAddress } from '../config.ts';
import type { Ledger } from '../ledger/store.ts';
import type { ApprovalDecision } from './passkey.ts';

export type ResolveOutcome =
  | 'resolved'
  | 'not_pending'
  | 'passkey_required'
  | 'remember_not_allowed';

// What the approval page calls the service: the host of the paid resource.
export function recipientLabel(resourceUrl: string | null): string {
  if (resourceUrl !== null) {
    try {
      const host = new URL(resourceUrl).host;
      if (host !== '') return host.slice(0, 120);
    } catch {
      // fall through to the generic label
    }
  }
  return 'approved with passkey';
}

// "remember" approves the payment and also adds its recipient, on that chain,
// to the learned allowlist. Only a passkey can do either for a new recipient.
export function resolveApproval(
  ledger: Ledger,
  audit: AuditLog,
  id: string,
  decision: ApprovalDecision,
  opts: {
    now?: () => number;
    via?: 'cli' | 'passkey';
    method?: 'cli' | 'passkey';
    credential?: string;
  } = {},
): ResolveOutcome {
  const now = opts.now ?? Date.now;
  const via = opts.via ?? 'cli';
  if (decision !== 'denied' && opts.method === 'passkey' && via !== 'passkey')
    return 'passkey_required';
  const out = ledger.transaction(() => {
    const a = ledger.getApproval(id);
    if (a === null || a.status !== 'pending' || now() >= a.expiresAt)
      return 'not_pending';
    if (
      decision === 'remember' &&
      (via !== 'passkey' || a.context.reason !== 'new_recipient')
    )
      return 'remember_not_allowed';
    const status = decision === 'denied' ? 'denied' : 'approved';
    if (!ledger.setApprovalStatus(id, 'pending', status, now()))
      return 'not_pending';
    let learned: { recipient: string; chain: string; label: string } | null =
      null;
    if (decision === 'remember') {
      const intent = JSON.parse(a.intentJson) as Record<string, unknown>;
      learned = {
        recipient: normalizeAddress(String(intent['recipient'])),
        chain: String(intent['chain']),
        // The host comes from the agent's 402, not from anything bursar
        // checked, so the stored label says so wherever it is listed.
        label:
          a.context.resourceUrl === null
            ? recipientLabel(null)
            : `${recipientLabel(a.context.resourceUrl)} (unverified)`,
      };
      if (
        !ledger.addLearnedRecipient({
          address: learned.recipient,
          chain: learned.chain,
          label: learned.label,
          created: now(),
          approvalId: id,
          credential: opts.credential ?? via,
        })
      )
        learned = null;
    }
    return { agent: a.agent, status, learned };
  });
  if (typeof out === 'string') return out;
  const base = {
    ts: now(),
    agent: out.agent,
    approvalId: id,
    via,
    ...(opts.credential === undefined ? {} : { credential: opts.credential }),
  };
  audit.append({ ...base, event: 'approval_resolved', reason: out.status });
  if (out.learned !== null)
    audit.append({
      ...base,
      event: 'recipient_added',
      recipient: out.learned.recipient,
      chain: out.learned.chain,
      reason: out.learned.label,
    });
  return 'resolved';
}
