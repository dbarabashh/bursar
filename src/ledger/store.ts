import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { PasskeyCredential } from '../approval/passkey.ts';
import type { ApprovalReason } from '../policy/engine.ts';
import type { LedgerSnapshot } from '../policy/limits.ts';

export type StoredResponse = {
  httpStatus: number;
  body: Record<string, unknown>;
};

export type IdempotencyRow = {
  key: string;
  intentHash: string;
  result: StoredResponse;
  ts: number;
};

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'denied'
  | 'expired'
  | 'consumed';

export type ApprovalContext = {
  reason: ApprovalReason;
  resourceUrl: string | null;
};

export type ApprovalRow = {
  id: string;
  agent: string;
  intentJson: string;
  status: ApprovalStatus;
  ts: number;
  expiresAt: number;
  context: ApprovalContext;
};

type ApprovalDbRow = {
  id: string;
  agent: string;
  intent_json: string;
  status: ApprovalStatus;
  ts: number;
  expires_at: number;
  context_json: string | null;
};

function parseContext(raw: string | null): ApprovalContext {
  if (raw === null) return { reason: 'threshold', resourceUrl: null };
  const v = JSON.parse(raw) as Partial<ApprovalContext>;
  return {
    reason: v.reason === 'new_recipient' ? 'new_recipient' : 'threshold',
    resourceUrl: typeof v.resourceUrl === 'string' ? v.resourceUrl : null,
  };
}

function toApprovalRow(r: ApprovalDbRow): ApprovalRow {
  return {
    id: r.id,
    agent: r.agent,
    intentJson: r.intent_json,
    status: r.status,
    ts: Number(r.ts),
    expiresAt: Number(r.expires_at),
    context: parseContext(r.context_json),
  };
}

export type LearnedRecipient = {
  address: string;
  chain: string;
  label: string;
  created: number;
  approvalId: string;
  credential: string;
};

type LearnedDbRow = {
  address: string;
  chain: string;
  label: string;
  created: number;
  approval_id: string;
  credential: string;
};

function toLearned(r: LearnedDbRow): LearnedRecipient {
  return {
    address: r.address,
    chain: r.chain,
    label: r.label,
    created: Number(r.created),
    approvalId: r.approval_id,
    credential: r.credential,
  };
}

type PasskeyDbRow = {
  credential_id: string;
  public_key: Uint8Array;
  sign_count: number;
  name: string;
};

function toPasskey(r: PasskeyDbRow): PasskeyCredential {
  return {
    credentialId: r.credential_id,
    publicKey: new Uint8Array(r.public_key),
    signCount: Number(r.sign_count),
    name: r.name,
  };
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS spend (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  recipient TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  usd INTEGER NOT NULL,
  fee_usd INTEGER NOT NULL DEFAULT 0,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS spend_agent_ts ON spend(agent, ts);
CREATE INDEX IF NOT EXISTS spend_agent_recipient_ts ON spend(agent, recipient, ts);
CREATE INDEX IF NOT EXISTS spend_ts ON spend(ts);
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL,
  name TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY,
  intent_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  status TEXT NOT NULL,
  ts INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS learned_recipients (
  address TEXT NOT NULL,
  chain TEXT NOT NULL,
  label TEXT NOT NULL,
  created INTEGER NOT NULL,
  approval_id TEXT NOT NULL,
  credential TEXT NOT NULL,
  PRIMARY KEY (address, chain)
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  label TEXT NOT NULL,
  budget_usd INTEGER NOT NULL,
  created INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
`;

export type TaskRow = {
  id: string;
  agent: string;
  label: string;
  budgetUsd: bigint;
  created: number;
  expiresAt: number;
};

type TaskDbRow = {
  id: string;
  agent: string;
  label: string;
  budget_usd: bigint;
  created: number;
  expires_at: number;
};

function toTask(r: TaskDbRow): TaskRow {
  return {
    id: r.id,
    agent: r.agent,
    label: r.label,
    budgetUsd: BigInt(r.budget_usd),
    created: Number(r.created),
    expiresAt: Number(r.expires_at),
  };
}

export type SnapshotWindows = {
  dayStart: number;
  monthStart: number;
  velocityStart: number;
  taskId: string | null;
};

export type SpendGroup = {
  key: string;
  count: number;
  usd: bigint;
  feeUsd: bigint;
};

export class Ledger {
  private readonly db: DatabaseSync;
  private readonly stmts;
  private depth = 0;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    const fresh = !existsSync(path);
    this.db = new DatabaseSync(path, { timeout: 10_000 });
    if (fresh) chmodSync(path, 0o600);
    this.retryBusy(() => this.db.exec('PRAGMA journal_mode = WAL'));
    this.db.exec('PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;');
    this.retryBusy(() => {
      this.db.exec('BEGIN IMMEDIATE');
      try {
        this.db.exec(SCHEMA);
        const addColumn = (table: string, column: string, type: string) => {
          const cols = this.db.prepare(`PRAGMA table_info(${table})`).all() as {
            name: string;
          }[];
          if (!cols.some((c) => c.name === column))
            this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
        };
        addColumn('spend', 'fee_usd', 'INTEGER NOT NULL DEFAULT 0');
        addColumn('spend', 'task_id', 'TEXT');
        addColumn('approvals', 'context_json', 'TEXT');
        this.db.exec('CREATE INDEX IF NOT EXISTS spend_task ON spend(task_id)');
        this.db.exec('COMMIT');
      } catch (e) {
        if (this.db.isTransaction) this.db.exec('ROLLBACK');
        throw e;
      }
    });
    this.stmts = {
      daySpent: this.db.prepare(
        'SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE agent = ? AND ts >= ?',
      ),
      walletSpent: this.db.prepare(
        'SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE ts >= ?',
      ),
      taskSpent: this.db.prepare(
        'SELECT COALESCE(SUM(usd), 0) AS s FROM spend WHERE task_id = ?',
      ),
      addTask: this.db.prepare(
        'INSERT INTO tasks (id, agent, label, budget_usd, created, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      ),
      getTask: this.db.prepare(
        'SELECT id, agent, label, budget_usd, created, expires_at FROM tasks WHERE id = ?',
      ),
      listTasks: this.db.prepare(
        'SELECT id, agent, label, budget_usd, created, expires_at FROM tasks WHERE expires_at >= ? ORDER BY created',
      ),
      byAgent: this.db.prepare(
        'SELECT agent AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f FROM spend WHERE ts >= ? AND ts < ? GROUP BY agent ORDER BY s DESC',
      ),
      byRecipient: this.db.prepare(
        'SELECT recipient AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f FROM spend WHERE ts >= ? AND ts < ? GROUP BY recipient ORDER BY s DESC',
      ),
      byTask: this.db.prepare(
        "SELECT COALESCE(task_id, '') AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f FROM spend WHERE ts >= ? AND ts < ? AND task_id IS NOT NULL GROUP BY task_id ORDER BY s DESC",
      ),
      addPasskey: this.db.prepare(
        'INSERT INTO passkeys (credential_id, public_key, sign_count, name, created) VALUES (?, ?, ?, ?, ?)',
      ),
      getPasskey: this.db.prepare(
        'SELECT credential_id, public_key, sign_count, name FROM passkeys WHERE credential_id = ?',
      ),
      listPasskeys: this.db.prepare(
        'SELECT credential_id, public_key, sign_count, name FROM passkeys ORDER BY created',
      ),
      removePasskey: this.db.prepare(
        'DELETE FROM passkeys WHERE credential_id = ?',
      ),
      bumpSignCount: this.db.prepare(
        'UPDATE passkeys SET sign_count = ? WHERE credential_id = ? AND sign_count = ?',
      ),
      recipientSpent: this.db.prepare(
        'SELECT COALESCE(SUM(usd - fee_usd), 0) AS s FROM spend WHERE agent = ? AND recipient = ? AND ts >= ?',
      ),
      recentCount: this.db.prepare(
        'SELECT COUNT(*) AS c FROM spend WHERE agent = ? AND ts >= ?',
      ),
      recipientsSpent: this.db.prepare(
        'SELECT recipient, COALESCE(SUM(usd - fee_usd), 0) AS s FROM spend WHERE agent = ? AND ts >= ? GROUP BY recipient',
      ),
      addSpend: this.db.prepare(
        'INSERT INTO spend (id, agent, recipient, intent_json, usd, fee_usd, task_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ),
      spendCount: this.db.prepare('SELECT COUNT(*) AS c FROM spend'),
      getIdem: this.db.prepare(
        'SELECT key, intent_hash, result_json, ts FROM idempotency WHERE key = ?',
      ),
      putIdem: this.db.prepare(
        'INSERT OR REPLACE INTO idempotency (key, intent_hash, result_json, ts) VALUES (?, ?, ?, ?)',
      ),
      addApproval: this.db.prepare(
        'INSERT INTO approvals (id, agent, intent_json, status, ts, expires_at, context_json) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ),
      getApproval: this.db.prepare(
        'SELECT id, agent, intent_json, status, ts, expires_at, context_json FROM approvals WHERE id = ?',
      ),
      setApproval: this.db.prepare(
        'UPDATE approvals SET status = ?, resolved_at = ? WHERE id = ? AND status = ?',
      ),
      addLearned: this.db.prepare(
        'INSERT OR IGNORE INTO learned_recipients (address, chain, label, created, approval_id, credential) VALUES (?, ?, ?, ?, ?, ?)',
      ),
      listLearned: this.db.prepare(
        'SELECT address, chain, label, created, approval_id, credential FROM learned_recipients ORDER BY created',
      ),
      learnedFor: this.db.prepare(
        'SELECT address, chain, label, created, approval_id, credential FROM learned_recipients WHERE address = ?',
      ),
      removeLearned: this.db.prepare(
        'DELETE FROM learned_recipients WHERE address = ?',
      ),
      listApprovals: this.db.prepare(
        'SELECT id, agent, intent_json, status, ts, expires_at, context_json FROM approvals WHERE status = ? ORDER BY ts',
      ),
    };
    this.stmts.daySpent.setReadBigInts(true);
    this.stmts.walletSpent.setReadBigInts(true);
    for (const st of [
      this.stmts.taskSpent,
      this.stmts.getTask,
      this.stmts.listTasks,
      this.stmts.byAgent,
      this.stmts.byRecipient,
      this.stmts.byTask,
    ]) {
      st.setReadBigInts(true);
    }
    this.stmts.recipientSpent.setReadBigInts(true);
    this.stmts.recipientsSpent.setReadBigInts(true);
  }

  private retryBusy(fn: () => void): void {
    const deadline = Date.now() + 10_000;
    for (;;) {
      try {
        fn();
        return;
      } catch (e) {
        if ((e as { errcode?: number }).errcode !== 5 || Date.now() > deadline)
          throw e;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
  }

  transaction<T>(fn: () => T): T {
    if (this.depth > 0) return fn();
    this.db.exec('BEGIN IMMEDIATE');
    this.depth++;
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    } finally {
      this.depth--;
    }
  }

  snapshot(
    agent: string,
    recipient: string,
    w: SnapshotWindows,
  ): LedgerSnapshot {
    const rec = this.stmts.recipientSpent.get(agent, recipient, w.dayStart) as {
      s: bigint;
    };
    const task = w.taskId === null ? null : this.getTask(w.taskId);
    return {
      daySpent: this.daySpent(agent, w.dayStart),
      recipientDaySpent: BigInt(rec.s),
      walletDaySpent: this.walletDaySpent(w.dayStart),
      monthSpent: this.daySpent(agent, w.monthStart),
      recentTxCount: this.recentTxCount(agent, w.velocityStart),
      task:
        task === null
          ? null
          : { budget: task.budgetUsd, spent: this.taskSpent(task.id) },
    };
  }

  taskSpent(taskId: string): bigint {
    return BigInt((this.stmts.taskSpent.get(taskId) as { s: bigint }).s);
  }

  createTask(t: TaskRow): void {
    this.stmts.addTask.run(
      t.id,
      t.agent,
      t.label,
      t.budgetUsd,
      t.created,
      t.expiresAt,
    );
  }

  getTask(id: string): TaskRow | null {
    const row = this.stmts.getTask.get(id) as TaskDbRow | undefined;
    return row === undefined ? null : toTask(row);
  }

  listTasks(activeAt: number): TaskRow[] {
    return (this.stmts.listTasks.all(activeAt) as TaskDbRow[]).map(toTask);
  }

  spendBy(
    group: 'agent' | 'recipient' | 'task',
    from: number,
    to: number,
  ): SpendGroup[] {
    const st =
      group === 'agent'
        ? this.stmts.byAgent
        : group === 'recipient'
          ? this.stmts.byRecipient
          : this.stmts.byTask;
    return (
      st.all(from, to) as { k: string; c: bigint; s: bigint; f: bigint }[]
    ).map((r) => ({
      key: r.k,
      count: Number(r.c),
      usd: BigInt(r.s),
      feeUsd: BigInt(r.f),
    }));
  }

  walletDaySpent(dayStart: number): bigint {
    return BigInt((this.stmts.walletSpent.get(dayStart) as { s: bigint }).s);
  }

  addPasskey(c: PasskeyCredential, ts: number): void {
    this.stmts.addPasskey.run(
      c.credentialId,
      c.publicKey,
      c.signCount,
      c.name,
      ts,
    );
  }

  getPasskey(credentialId: string): PasskeyCredential | null {
    const row = this.stmts.getPasskey.get(credentialId) as
      | PasskeyDbRow
      | undefined;
    return row === undefined ? null : toPasskey(row);
  }

  listPasskeys(): PasskeyCredential[] {
    return (this.stmts.listPasskeys.all() as PasskeyDbRow[]).map(toPasskey);
  }

  removePasskey(credentialId: string): boolean {
    return Number(this.stmts.removePasskey.run(credentialId).changes) === 1;
  }

  bumpSignCount(credentialId: string, from: number, to: number): boolean {
    return (
      Number(this.stmts.bumpSignCount.run(to, credentialId, from).changes) === 1
    );
  }

  daySpent(agent: string, dayStart: number): bigint {
    return BigInt(
      (this.stmts.daySpent.get(agent, dayStart) as { s: bigint }).s,
    );
  }

  recentTxCount(agent: string, since: number): number {
    return Number(
      (this.stmts.recentCount.get(agent, since) as { c: number }).c,
    );
  }

  spentByRecipient(agent: string, dayStart: number): Map<string, bigint> {
    const rows = this.stmts.recipientsSpent.all(agent, dayStart) as {
      recipient: string;
      s: bigint;
    }[];
    return new Map(rows.map((r) => [r.recipient, BigInt(r.s)]));
  }

  addSpend(row: {
    id: string;
    agent: string;
    recipient: string;
    intentJson: string;
    usd: bigint;
    feeUsd: bigint;
    taskId?: string | null;
    ts: number;
  }): void {
    this.stmts.addSpend.run(
      row.id,
      row.agent,
      row.recipient,
      row.intentJson,
      row.usd,
      row.feeUsd,
      row.taskId ?? null,
      row.ts,
    );
  }

  spendCount(): number {
    return Number((this.stmts.spendCount.get() as { c: number }).c);
  }

  getIdempotency(key: string): IdempotencyRow | null {
    const row = this.stmts.getIdem.get(key) as
      | { key: string; intent_hash: string; result_json: string; ts: number }
      | undefined;
    if (!row) return null;
    return {
      key: row.key,
      intentHash: row.intent_hash,
      result: JSON.parse(row.result_json) as StoredResponse,
      ts: Number(row.ts),
    };
  }

  putIdempotency(
    key: string,
    intentHash: string,
    result: StoredResponse,
    ts: number,
  ): void {
    this.stmts.putIdem.run(key, intentHash, JSON.stringify(result), ts);
  }

  createApproval(row: ApprovalRow): void {
    this.stmts.addApproval.run(
      row.id,
      row.agent,
      row.intentJson,
      row.status,
      row.ts,
      row.expiresAt,
      JSON.stringify(row.context),
    );
  }

  addLearnedRecipient(r: LearnedRecipient): boolean {
    return (
      Number(
        this.stmts.addLearned.run(
          r.address,
          r.chain,
          r.label,
          r.created,
          r.approvalId,
          r.credential,
        ).changes,
      ) === 1
    );
  }

  listLearnedRecipients(): LearnedRecipient[] {
    return (this.stmts.listLearned.all() as LearnedDbRow[]).map(toLearned);
  }

  learnedRecipientsFor(address: string): LearnedRecipient[] {
    return (this.stmts.learnedFor.all(address) as LearnedDbRow[]).map(
      toLearned,
    );
  }

  removeLearnedRecipient(address: string): number {
    return Number(this.stmts.removeLearned.run(address).changes);
  }

  getApproval(id: string): ApprovalRow | null {
    const row = this.stmts.getApproval.get(id) as ApprovalDbRow | undefined;
    return row ? toApprovalRow(row) : null;
  }

  setApprovalStatus(
    id: string,
    from: ApprovalStatus,
    to: ApprovalStatus,
    ts: number,
  ): boolean {
    const r = this.stmts.setApproval.run(to, ts, id, from);
    return Number(r.changes) === 1;
  }

  listApprovals(status: ApprovalStatus): ApprovalRow[] {
    return (this.stmts.listApprovals.all(status) as ApprovalDbRow[]).map(
      toApprovalRow,
    );
  }

  close(): void {
    if (this.db.isOpen) this.db.close();
  }
}
