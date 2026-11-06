import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import type { Currency } from '../config.ts';
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
CREATE TABLE IF NOT EXISTS cashu_keysets (
  id TEXT PRIMARY KEY,
  mint TEXT NOT NULL,
  unit TEXT NOT NULL,
  active INTEGER NOT NULL,
  fee_ppk INTEGER NOT NULL,
  keys_json TEXT NOT NULL,
  updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cashu_proofs (
  y TEXT PRIMARY KEY,
  mint TEXT NOT NULL,
  unit TEXT NOT NULL,
  keyset_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  secret TEXT NOT NULL,
  c TEXT NOT NULL,
  state TEXT NOT NULL,
  op_id TEXT,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cashu_proofs_mint_state ON cashu_proofs(mint, unit, state);
CREATE TABLE IF NOT EXISTS cashu_ops (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  mint TEXT NOT NULL,
  unit TEXT NOT NULL,
  state TEXT NOT NULL,
  data_json TEXT NOT NULL,
  ts INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cashu_ops_state ON cashu_ops(state);
`;

export type TaskRow = {
  id: string;
  agent: string;
  label: string;
  budgetUsd: bigint;
  budgetSat: bigint | null;
  created: number;
  expiresAt: number;
};

type TaskDbRow = {
  id: string;
  agent: string;
  label: string;
  budget_usd: bigint;
  budget_sat: bigint | null;
  created: number;
  expires_at: number;
};

function toTask(r: TaskDbRow): TaskRow {
  return {
    id: r.id,
    agent: r.agent,
    label: r.label,
    budgetUsd: BigInt(r.budget_usd),
    budgetSat: r.budget_sat === null ? null : BigInt(r.budget_sat),
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
  sat: bigint;
  feeSat: bigint;
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
        addColumn('spend', 'sat', 'INTEGER NOT NULL DEFAULT 0');
        addColumn('spend', 'fee_sat', 'INTEGER NOT NULL DEFAULT 0');
        addColumn('tasks', 'budget_sat', 'INTEGER');
        addColumn('approvals', 'context_json', 'TEXT');
        this.db.exec('CREATE INDEX IF NOT EXISTS spend_task ON spend(task_id)');
        this.db.exec('COMMIT');
      } catch (e) {
        if (this.db.isTransaction) this.db.exec('ROLLBACK');
        throw e;
      }
    });
    this.stmts = {
      addTask: this.db.prepare(
        'INSERT INTO tasks (id, agent, label, budget_usd, budget_sat, created, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ),
      getTask: this.db.prepare(
        'SELECT id, agent, label, budget_usd, budget_sat, created, expires_at FROM tasks WHERE id = ?',
      ),
      listTasks: this.db.prepare(
        'SELECT id, agent, label, budget_usd, budget_sat, created, expires_at FROM tasks WHERE expires_at >= ? ORDER BY created',
      ),
      byAgent: this.db.prepare(
        'SELECT agent AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f, COALESCE(SUM(sat), 0) AS t, COALESCE(SUM(fee_sat), 0) AS g FROM spend WHERE ts >= ? AND ts < ? GROUP BY agent ORDER BY s DESC',
      ),
      byRecipient: this.db.prepare(
        'SELECT recipient AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f, COALESCE(SUM(sat), 0) AS t, COALESCE(SUM(fee_sat), 0) AS g FROM spend WHERE ts >= ? AND ts < ? GROUP BY recipient ORDER BY s DESC',
      ),
      byTask: this.db.prepare(
        "SELECT COALESCE(task_id, '') AS k, COUNT(*) AS c, COALESCE(SUM(usd), 0) AS s, COALESCE(SUM(fee_usd), 0) AS f, COALESCE(SUM(sat), 0) AS t, COALESCE(SUM(fee_sat), 0) AS g FROM spend WHERE ts >= ? AND ts < ? AND task_id IS NOT NULL GROUP BY task_id ORDER BY s DESC",
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
      recentCount: this.db.prepare(
        'SELECT COUNT(*) AS c FROM spend WHERE agent = ? AND ts >= ?',
      ),
      addSpend: this.db.prepare(
        'INSERT INTO spend (id, agent, recipient, intent_json, usd, fee_usd, sat, fee_sat, task_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ),
      removeSpend: this.db.prepare('DELETE FROM spend WHERE id = ?'),
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
    for (const st of [
      this.stmts.getTask,
      this.stmts.listTasks,
      this.stmts.byAgent,
      this.stmts.byRecipient,
      this.stmts.byTask,
    ]) {
      st.setReadBigInts(true);
    }
    const sums = (amount: 'usd' | 'sat', fee: 'fee_usd' | 'fee_sat') => {
      const s = {
        day: this.db.prepare(
          `SELECT COALESCE(SUM(${amount}), 0) AS s FROM spend WHERE agent = ? AND ts >= ?`,
        ),
        wallet: this.db.prepare(
          `SELECT COALESCE(SUM(${amount}), 0) AS s FROM spend WHERE ts >= ?`,
        ),
        task: this.db.prepare(
          `SELECT COALESCE(SUM(${amount}), 0) AS s FROM spend WHERE task_id = ?`,
        ),
        recipient: this.db.prepare(
          `SELECT COALESCE(SUM(${amount} - ${fee}), 0) AS s FROM spend WHERE agent = ? AND recipient = ? AND ts >= ?`,
        ),
        recipients: this.db.prepare(
          `SELECT recipient, COALESCE(SUM(${amount} - ${fee}), 0) AS s FROM spend WHERE agent = ? AND ts >= ? AND ${amount} > 0 GROUP BY recipient`,
        ),
      };
      for (const st of Object.values(s)) st.setReadBigInts(true);
      return s;
    };
    this.sums = { usd: sums('usd', 'fee_usd'), sat: sums('sat', 'fee_sat') };
  }

  private readonly sums: Record<
    Currency,
    Record<
      'day' | 'wallet' | 'task' | 'recipient' | 'recipients',
      StatementSync
    >
  >;

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
    currency: Currency = 'usd',
  ): LedgerSnapshot {
    const rec = this.sums[currency].recipient.get(
      agent,
      recipient,
      w.dayStart,
    ) as { s: bigint };
    const task = w.taskId === null ? null : this.getTask(w.taskId);
    return {
      daySpent: this.daySpent(agent, w.dayStart, currency),
      recipientDaySpent: BigInt(rec.s),
      walletDaySpent: this.walletDaySpent(w.dayStart, currency),
      monthSpent: this.daySpent(agent, w.monthStart, currency),
      recentTxCount: this.recentTxCount(agent, w.velocityStart),
      task:
        task === null
          ? null
          : {
              budget: currency === 'usd' ? task.budgetUsd : task.budgetSat,
              spent: this.taskSpent(task.id, currency),
            },
    };
  }

  taskSpent(taskId: string, currency: Currency = 'usd'): bigint {
    return BigInt((this.sums[currency].task.get(taskId) as { s: bigint }).s);
  }

  createTask(t: TaskRow): void {
    this.stmts.addTask.run(
      t.id,
      t.agent,
      t.label,
      t.budgetUsd,
      t.budgetSat,
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
      st.all(from, to) as {
        k: string;
        c: bigint;
        s: bigint;
        f: bigint;
        t: bigint;
        g: bigint;
      }[]
    ).map((r) => ({
      key: r.k,
      count: Number(r.c),
      usd: BigInt(r.s),
      feeUsd: BigInt(r.f),
      sat: BigInt(r.t),
      feeSat: BigInt(r.g),
    }));
  }

  walletDaySpent(dayStart: number, currency: Currency = 'usd'): bigint {
    return BigInt(
      (this.sums[currency].wallet.get(dayStart) as { s: bigint }).s,
    );
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

  daySpent(
    agent: string,
    dayStart: number,
    currency: Currency = 'usd',
  ): bigint {
    return BigInt(
      (this.sums[currency].day.get(agent, dayStart) as { s: bigint }).s,
    );
  }

  recentTxCount(agent: string, since: number): number {
    return Number(
      (this.stmts.recentCount.get(agent, since) as { c: number }).c,
    );
  }

  spentByRecipient(
    agent: string,
    dayStart: number,
    currency: Currency = 'usd',
  ): Map<string, bigint> {
    const rows = this.sums[currency].recipients.all(agent, dayStart) as {
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
    sat?: bigint;
    feeSat?: bigint;
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
      row.sat ?? 0n,
      row.feeSat ?? 0n,
      row.taskId ?? null,
      row.ts,
    );
  }

  // A Cashu payment whose ecash came back unspent (the mint refused the swap,
  // or the merchant never redeemed the token and bursar took it back) is
  // removed again, so it no longer counts against any limit.
  removeSpend(id: string): boolean {
    return Number(this.stmts.removeSpend.run(id).changes) === 1;
  }

  // What is left of a refunded Cashu payment: the mint fees that were really
  // spent getting the ecash out and back. They still count as spending.
  reduceSpendToFee(id: string, currency: Currency, fee: bigint): void {
    const col =
      currency === 'sat' ? 'sat = ?, fee_sat = ?' : 'usd = ?, fee_usd = ?';
    this.q(`UPDATE spend SET ${col} WHERE id = ?`).run(fee, fee, id);
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

  // Statements prepared on first use and kept (node:sqlite has no cache).
  private readonly prepared = new Map<string, StatementSync>();
  private q(sql: string): StatementSync {
    let st = this.prepared.get(sql);
    if (st === undefined) {
      st = this.db.prepare(sql);
      this.prepared.set(sql, st);
    }
    return st;
  }

  // --- Cashu wallet -------------------------------------------------------
  // Proofs are bearer money; this table is the wallet. A proof is `unspent`,
  // `reserved` by an operation in flight (op_id), or `spent`.

  putKeyset(k: CashuKeysetRow): void {
    this.q(
      'INSERT INTO cashu_keysets (id, mint, unit, active, fee_ppk, keys_json, updated) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET active = excluded.active, updated = excluded.updated',
    ).run(
      k.id,
      k.mint,
      k.unit,
      k.active ? 1 : 0,
      k.feePpk,
      JSON.stringify(k.keys),
      k.updated,
    );
  }

  listKeysets(mint: string): CashuKeysetRow[] {
    return (
      this.q(
        'SELECT id, mint, unit, active, fee_ppk, keys_json, updated FROM cashu_keysets WHERE mint = ?',
      ).all(mint) as {
        id: string;
        mint: string;
        unit: string;
        active: number;
        fee_ppk: number;
        keys_json: string;
        updated: number;
      }[]
    ).map((r) => ({
      id: r.id,
      mint: r.mint,
      unit: r.unit,
      active: Number(r.active) === 1,
      feePpk: Number(r.fee_ppk),
      keys: JSON.parse(r.keys_json) as Record<string, string>,
      updated: Number(r.updated),
    }));
  }

  addProofs(
    mint: string,
    unit: string,
    proofs: readonly CashuProofRow[],
    state: CashuProofState,
    opId: string | null,
    ts: number,
  ): void {
    const st = this.q(
      'INSERT INTO cashu_proofs (y, mint, unit, keyset_id, amount, secret, c, state, op_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(y) DO NOTHING',
    );
    for (const p of proofs)
      st.run(p.y, mint, unit, p.id, p.amount, p.secret, p.C, state, opId, ts);
  }

  listProofs(
    mint: string,
    unit: string,
    state: CashuProofState,
  ): CashuProofRow[] {
    return (
      this.q(
        'SELECT y, keyset_id, amount, secret, c FROM cashu_proofs WHERE mint = ? AND unit = ? AND state = ? ORDER BY amount DESC',
      ).all(mint, unit, state) as {
        y: string;
        keyset_id: string;
        amount: number;
        secret: string;
        c: string;
      }[]
    ).map((r) => ({
      y: r.y,
      id: r.keyset_id,
      amount: Number(r.amount),
      secret: r.secret,
      C: r.c,
    }));
  }

  proofBalance(mint: string, unit: string): number {
    return Number(
      (
        this.q(
          "SELECT COALESCE(SUM(amount), 0) AS s FROM cashu_proofs WHERE mint = ? AND unit = ? AND state = 'unspent'",
        ).get(mint, unit) as { s: number }
      ).s,
    );
  }

  // Moves proofs between states; returns how many actually moved, so a
  // caller can tell whether another operation got to them first.
  setProofState(
    ys: readonly string[],
    from: CashuProofState,
    to: CashuProofState,
    opId: string | null,
  ): number {
    const st = this.q(
      'UPDATE cashu_proofs SET state = ?, op_id = ? WHERE y = ? AND state = ?',
    );
    let n = 0;
    for (const y of ys) n += Number(st.run(to, opId, y, from).changes);
    return n;
  }

  cashuBalances(): {
    mint: string;
    unit: string;
    state: string;
    amount: bigint;
    count: number;
  }[] {
    const st = this.q(
      'SELECT mint, unit, state, COALESCE(SUM(amount), 0) AS s, COUNT(*) AS c FROM cashu_proofs GROUP BY mint, unit, state ORDER BY mint, unit, state',
    );
    st.setReadBigInts(true);
    return (
      st.all() as {
        mint: string;
        unit: string;
        state: string;
        s: bigint;
        c: bigint;
      }[]
    ).map((r) => ({
      mint: r.mint,
      unit: r.unit,
      state: r.state,
      amount: BigInt(r.s),
      count: Number(r.c),
    }));
  }

  putOp(op: CashuOpRow): void {
    this.q(
      'INSERT INTO cashu_ops (id, kind, mint, unit, state, data_json, ts, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET state = excluded.state, data_json = excluded.data_json, updated = excluded.updated',
    ).run(
      op.id,
      op.kind,
      op.mint,
      op.unit,
      op.state,
      JSON.stringify(op.data),
      op.ts,
      op.updated,
    );
  }

  getOp(id: string): CashuOpRow | null {
    const r = this.q(`${OP_SELECT} WHERE id = ?`).get(id) as
      | CashuOpDbRow
      | undefined;
    return r === undefined ? null : toOp(r);
  }

  listOps(state: string): CashuOpRow[] {
    return (
      this.q(`${OP_SELECT} WHERE state = ? ORDER BY ts`).all(
        state,
      ) as CashuOpDbRow[]
    ).map(toOp);
  }

  close(): void {
    if (this.db.isOpen) this.db.close();
  }
}

export type CashuKeysetRow = {
  id: string;
  mint: string;
  unit: string;
  active: boolean;
  feePpk: number;
  keys: Record<string, string>;
  updated: number;
};

export type CashuProofState = 'unspent' | 'reserved' | 'spent';

export type CashuProofRow = {
  y: string;
  id: string;
  amount: number;
  secret: string;
  C: string;
};

export type CashuOpRow = {
  id: string;
  kind: string;
  mint: string;
  unit: string;
  state: string;
  data: Record<string, unknown>;
  ts: number;
  updated: number;
};

const OP_SELECT =
  'SELECT id, kind, mint, unit, state, data_json, ts, updated FROM cashu_ops';

type CashuOpDbRow = {
  id: string;
  kind: string;
  mint: string;
  unit: string;
  state: string;
  data_json: string;
  ts: number;
  updated: number;
};

function toOp(r: CashuOpDbRow): CashuOpRow {
  return {
    id: r.id,
    kind: r.kind,
    mint: r.mint,
    unit: r.unit,
    state: r.state,
    data: JSON.parse(r.data_json) as Record<string, unknown>,
    ts: Number(r.ts),
    updated: Number(r.updated),
  };
}
