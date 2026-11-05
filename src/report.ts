import { listedRecipients } from './policy/allowlist.ts';
import type { AuditLog } from './audit.ts';
import type { Policy } from './config.ts';
import type { Ledger, SpendGroup } from './ledger/store.ts';
import { formatUsd } from './util.ts';

export type Period = { from: number; to: number; label: string };

export type ReportRow = {
  key: string;
  label: string | null;
  count: number;
  usd: string;
  feeUsd: string;
};

export type Report = {
  period: { from: string; to: string; label: string };
  totals: {
    payments: number;
    usd: string;
    feeUsd: string;
    denied: number;
    pendingApprovals: number;
  };
  byAgent: (ReportRow & {
    dayLimitUsd: string;
    monthLimitUsd: string | null;
  })[];
  byRecipient: ReportRow[];
  byTask: (ReportRow & {
    agent: string | null;
    budgetUsd: string | null;
    expiresAt: string | null;
  })[];
  denials: { reason: string; count: number; agents: string[] }[];
  approvals: {
    resolved: Record<string, number>;
    pending: { id: string; agent: string; expiresAt: string }[];
  };
  audit: { entries: number; chainValid: boolean };
};

const DAY = 86_400_000;

export function periodFor(
  kind: string,
  now: number,
  since?: string,
  until?: string,
): Period {
  if (since !== undefined || until !== undefined) {
    const from = since === undefined ? 0 : Date.parse(since);
    const to = until === undefined ? now + 1 : Date.parse(until);
    if (!Number.isFinite(from) || !Number.isFinite(to))
      throw new Error('--since/--until must be ISO-8601 dates');
    return { from, to, label: 'custom' };
  }
  const d = new Date(now);
  if (kind === 'day') {
    const from = Math.floor(now / DAY) * DAY;
    return { from, to: from + DAY, label: 'today (UTC)' };
  }
  if (kind === 'month') {
    return {
      from: Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1),
      to: Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1),
      label: 'this month (UTC)',
    };
  }
  if (kind === 'all') return { from: 0, to: now + 1, label: 'all time' };
  throw new Error('--period must be day, month or all');
}

function row(g: SpendGroup, label: string | null): ReportRow {
  return {
    key: g.key,
    label,
    count: g.count,
    usd: formatUsd(g.usd),
    feeUsd: formatUsd(g.feeUsd),
  };
}

export function buildReport(
  deps: { policy: Policy; ledger: Ledger; audit: AuditLog; now: number },
  period: Period,
): Report {
  const { policy, ledger, audit } = deps;
  const agents = ledger.spendBy('agent', period.from, period.to);
  const recipients = ledger.spendBy('recipient', period.from, period.to);
  const tasks = ledger.spendBy('task', period.from, period.to);
  const listed = listedRecipients(policy, ledger.listLearnedRecipients());
  const labels = new Map(
    listed === 'any' ? [] : listed.map((r) => [r.address, r.label]),
  );

  const events = audit
    .readSince(period.from, null)
    .map(
      (l) =>
        JSON.parse(l) as {
          ts: number;
          agent: string;
          event: string;
          reason?: string;
          via?: string;
        },
    )
    .filter((e) => e.ts < period.to);
  const denials = new Map<string, { count: number; agents: Set<string> }>();
  const resolved: Record<string, number> = {};
  for (const e of events) {
    if (e.event === 'denied') {
      const r = e.reason ?? 'unknown';
      const d = denials.get(r) ?? { count: 0, agents: new Set<string>() };
      d.count++;
      d.agents.add(e.agent);
      denials.set(r, d);
    }
    if (e.event === 'approval_resolved') {
      const k = `${e.reason ?? '?'} via ${e.via ?? 'cli'}`;
      resolved[k] = (resolved[k] ?? 0) + 1;
    }
  }
  const pending = ledger
    .listApprovals('pending')
    .filter((a) => a.expiresAt > deps.now)
    .map((a) => ({
      id: a.id,
      agent: a.agent,
      expiresAt: new Date(a.expiresAt).toISOString(),
    }));

  const sum = (gs: SpendGroup[], f: (g: SpendGroup) => bigint) =>
    gs.reduce((acc, g) => acc + f(g), 0n);
  return {
    period: {
      from: new Date(period.from).toISOString(),
      to: new Date(period.to).toISOString(),
      label: period.label,
    },
    totals: {
      payments: agents.reduce((a, g) => a + g.count, 0),
      usd: formatUsd(sum(agents, (g) => g.usd)),
      feeUsd: formatUsd(sum(agents, (g) => g.feeUsd)),
      denied: [...denials.values()].reduce((a, d) => a + d.count, 0),
      pendingApprovals: pending.length,
    },
    byAgent: agents.map((g) => ({
      ...row(g, null),
      dayLimitUsd: formatUsd(policy.limits.perDay),
      monthLimitUsd:
        policy.limits.perMonth === null
          ? null
          : formatUsd(policy.limits.perMonth.usd),
    })),
    byRecipient: recipients.map((g) => row(g, labels.get(g.key) ?? null)),
    byTask: tasks.map((g) => {
      const t = ledger.getTask(g.key);
      return {
        ...row(g, t?.label || null),
        agent: t?.agent ?? null,
        budgetUsd: t === null ? null : formatUsd(t.budgetUsd),
        expiresAt: t === null ? null : new Date(t.expiresAt).toISOString(),
      };
    }),
    denials: [...denials.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .map(([reason, d]) => ({
        reason,
        count: d.count,
        agents: [...d.agents].sort(),
      })),
    approvals: { resolved, pending },
    audit: { entries: events.length, chainValid: audit.verifyChain() },
  };
}

function table(headers: string[], rows: string[][]): string {
  if (rows.length === 0) return '  (none)\n';
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)),
  );
  const line = (cells: string[]) =>
    `  ${cells.map((c, i) => (i === 0 ? c.padEnd(widths[i] ?? 0) : c.padStart(widths[i] ?? 0))).join('   ')}\n`;
  return line(headers) + rows.map(line).join('');
}

export function formatReport(r: Report): string {
  let out = `bursar spend report, ${r.period.label}: ${r.period.from} .. ${r.period.to}\n\n`;
  out += `  payments ${r.totals.payments}   spent $${r.totals.usd} (network fees $${r.totals.feeUsd})   denied ${r.totals.denied}   pending approvals ${r.totals.pendingApprovals}\n`;
  out += `  audit log: ${r.audit.entries} entries in period, hash chain ${r.audit.chainValid ? 'intact' : 'BROKEN - the log was modified'}\n\n`;
  out +=
    'By agent\n' +
    table(
      ['agent', 'payments', 'usd', 'fees', 'day limit', 'month limit'],
      r.byAgent.map((a) => [
        a.key,
        String(a.count),
        a.usd,
        a.feeUsd,
        a.dayLimitUsd,
        a.monthLimitUsd ?? '-',
      ]),
    );
  out +=
    '\nBy recipient\n' +
    table(
      ['recipient', 'label', 'payments', 'usd'],
      r.byRecipient.map((x) => [x.key, x.label ?? '-', String(x.count), x.usd]),
    );
  out +=
    '\nBy task\n' +
    table(
      ['task', 'label', 'agent', 'payments', 'usd', 'budget'],
      r.byTask.map((t) => [
        t.key,
        t.label ?? '-',
        t.agent ?? '-',
        String(t.count),
        t.usd,
        t.budgetUsd ?? '-',
      ]),
    );
  out +=
    '\nDenials\n' +
    table(
      ['reason', 'count', 'agents'],
      r.denials.map((d) => [d.reason, String(d.count), d.agents.join(',')]),
    );
  const resolved = Object.entries(r.approvals.resolved);
  out +=
    '\nApprovals\n' +
    table(
      ['outcome', 'count'],
      resolved.map(([k, v]) => [k, String(v)]),
    );
  if (r.approvals.pending.length > 0)
    out += table(
      ['pending', 'agent', 'expires'],
      r.approvals.pending.map((p) => [p.id, p.agent, p.expiresAt]),
    );
  return out;
}
