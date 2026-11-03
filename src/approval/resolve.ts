import type { AuditLog } from '../audit.ts';
import type { Ledger } from '../ledger/store.ts';

export type ResolveOutcome = 'resolved' | 'not_pending' | 'passkey_required';

export function resolveApproval(
  ledger: Ledger,
  audit: AuditLog,
  id: string,
  decision: 'approved' | 'denied',
  opts: {
    now?: () => number;
    via?: 'cli' | 'passkey';
    method?: 'cli' | 'passkey';
    credential?: string;
  } = {},
): ResolveOutcome {
  const now = opts.now ?? Date.now;
  const via = opts.via ?? 'cli';
  if (decision === 'approved' && opts.method === 'passkey' && via !== 'passkey')
    return 'passkey_required';
  const ok = ledger.transaction(() => {
    const a = ledger.getApproval(id);
    if (a === null || a.status !== 'pending' || now() >= a.expiresAt)
      return null;
    return ledger.setApprovalStatus(id, 'pending', decision, now()) ? a : null;
  });
  if (ok === null) return 'not_pending';
  audit.append({
    ts: now(),
    agent: ok.agent,
    event: 'approval_resolved',
    approvalId: id,
    reason: decision,
    via,
    ...(opts.credential === undefined ? {} : { credential: opts.credential }),
  });
  return 'resolved';
}
