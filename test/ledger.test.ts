import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { describe, it } from 'node:test';
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';
import { AuditLog } from '../src/audit.ts';
import {
  cleanup,
  makeDir,
  makeEnv,
  MERCHANT_B,
  openEnv,
  sign,
  T0,
  usdc,
  x402Body,
  type PolicyOptions,
} from './helpers.ts';

describe('idempotency', () => {
  it('returns the same result for the same key and charges the budget once', async () => {
    const env = makeEnv();
    try {
      const body = x402Body({ amount: usdc(0.4), key: 'same' });
      const a = await sign(env, body);
      const b = await sign(env, body);
      assert.equal(a.body['status'], 'signed');
      assert.deepEqual(b, a);
      assert.equal(env.ledger.spendCount(), 1);
      const budget = env.app.budget('nanocode').body as {
        perDay: { spentUsd: string };
      };
      assert.equal(budget.perDay.spentUsd, '0.40');
    } finally {
      cleanup(env);
    }
  });

  it('replays denials too', async () => {
    const env = makeEnv();
    try {
      const body = x402Body({ amount: usdc(3), key: 'deny' });
      assert.deepEqual(await sign(env, body), await sign(env, body));
    } finally {
      cleanup(env);
    }
  });

  it('rejects the same key with a different payload as a conflict', async () => {
    const env = makeEnv();
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.4), key: 'k' }))).body[
          'status'
        ],
        'signed',
      );
      const conflict = await sign(
        env,
        x402Body({ amount: usdc(0.5), key: 'k' }),
      );
      assert.equal(conflict.status, 409);
      assert.equal(conflict.body['error'], 'idempotency_conflict');
      const otherRecipient = await sign(
        env,
        x402Body({ amount: usdc(0.4), key: 'k', payTo: MERCHANT_B }),
      );
      assert.equal(otherRecipient.status, 409);
      assert.equal(env.ledger.spendCount(), 1);
    } finally {
      cleanup(env);
    }
  });

  it('scopes keys per agent', async () => {
    const env = makeEnv();
    try {
      assert.equal(
        (await sign(env, x402Body({ key: 'shared' }), 'nanocode')).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (
          await sign(
            env,
            x402Body({ key: 'shared', amount: usdc(0.2) }),
            'other',
          )
        ).body['status'],
        'signed',
      );
      assert.equal(env.ledger.spendCount(), 2);
    } finally {
      cleanup(env);
    }
  });
});

describe('fee accounting', () => {
  it('daily totals include fees, recipient totals exclude them', () => {
    const env = makeEnv();
    try {
      env.ledger.addSpend({
        id: 'f1',
        agent: 'nanocode',
        recipient: '0xabc',
        intentJson: '{}',
        usd: 501_000n,
        feeUsd: 1_000n,
        ts: T0,
      });
      const snap = env.ledger.snapshot('nanocode', '0xabc', {
        dayStart: T0 - 1,
        monthStart: T0 - 1,
        velocityStart: T0 - 1,
        taskId: null,
      });
      assert.equal(snap.daySpent, 501_000n);
      assert.equal(snap.recipientDaySpent, 500_000n);
      assert.equal(
        env.ledger.spentByRecipient('nanocode', T0 - 1).get('0xabc'),
        500_000n,
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('audit log with several writers', () => {
  it('keeps the hash chain intact when the daemon and the CLI both append', () => {
    const dir = makeDir();
    try {
      const log = join(dir, 'audit.jsonl');
      const daemon = new AuditLog(log);
      const cli = new AuditLog(log);
      for (let i = 0; i < 5; i++) {
        daemon.append({ ts: i, agent: 'nanocode', event: 'signed' });
        cli.append({ ts: i, agent: 'nanocode', event: 'approval_resolved' });
      }
      assert.ok(daemon.verifyChain());
      assert.equal(daemon.readSince(0, null).length, 10);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stays intact under concurrent appends from separate threads sharing the ledger lock', async () => {
    const dir = makeDir();
    try {
      const db = join(dir, 'bursar.db');
      const log = join(dir, 'audit.jsonl');
      new AuditLog(log);
      const run = (name: string) =>
        new Promise<void>((resolve, reject) => {
          const w = new Worker(
            new URL('./fixtures/audit-writer.ts', import.meta.url),
            { workerData: { db, log, name, count: 60 } },
          );
          w.once('message', () => resolve());
          w.once('error', reject);
        });
      await Promise.all([run('a'), run('b'), run('c')]);
      const audit = new AuditLog(log);
      assert.equal(audit.readSince(0, null).length, 180);
      assert.ok(audit.verifyChain());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('persistence', () => {
  it('keeps the daily counter across a daemon restart', async () => {
    const dir = makeDir();
    const opts: PolicyOptions = { perDay: '2.00', perRecipient: '10.00' };
    try {
      const first = openEnv(dir, opts);
      assert.equal(
        (await sign(first, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(first, x402Body({ amount: usdc(0.9), key: 'b' }))).body[
          'status'
        ],
        'signed',
      );
      first.close();

      const second = openEnv(dir, opts);
      const budget = second.app.budget('nanocode').body as {
        perDay: { spentUsd: string; remainingUsd: string };
      };
      assert.equal(budget.perDay.spentUsd, '1.80');
      assert.equal(budget.perDay.remainingUsd, '0.20');
      assert.equal(
        (await sign(second, x402Body({ amount: usdc(0.9), key: 'c' }))).body[
          'reason'
        ],
        'per_day_limit',
      );
      assert.equal(
        (await sign(second, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(second.ledger.spendCount(), 2);
      assert.ok(second.audit.verifyChain());
      second.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('concurrency', () => {
  const opts: PolicyOptions = { perDay: '1.50', perRecipient: '10.00' };

  it('two concurrent requests over the daily limit in one daemon: exactly one signs', async () => {
    const env = makeEnv(opts);
    try {
      const { server, port } = await env.app.listen(0, '127.0.0.1');
      const post = (key: string) =>
        fetch(`http://127.0.0.1:${port}/v1/sign`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer test-token-nanocode-0123456789abcdef',
            'content-type': 'application/json',
          },
          body: JSON.stringify(x402Body({ amount: usdc(0.9), key })),
        }).then((r) => r.json() as Promise<Record<string, unknown>>);
      const results = await Promise.all([post('x'), post('y')]);
      server.close();
      assert.deepEqual(results.map((r) => r['status']).sort(), [
        'denied',
        'signed',
      ]);
      assert.equal(env.ledger.spendCount(), 1);
    } finally {
      cleanup(env);
    }
  });

  it('two daemons sharing one ledger file: BEGIN IMMEDIATE lets exactly one sign', async () => {
    const dir = makeDir();
    try {
      openEnv(dir, opts).close();
      const gate = new SharedArrayBuffer(8);
      const flags = new Int32Array(gate);
      const spawn = (key: string) =>
        new Promise<Record<string, unknown>>((resolve, reject) => {
          const w = new Worker(
            new URL('./fixtures/concurrent-worker.ts', import.meta.url),
            {
              workerData: {
                dir,
                opts,
                body: x402Body({ amount: usdc(0.9), key }),
                gate,
                now: T0,
              },
            },
          );
          w.once('message', resolve);
          w.once('error', reject);
        });
      const pending = [spawn('w1'), spawn('w2')];
      while (Atomics.load(flags, 1) < 2)
        await new Promise((r) => setTimeout(r, 5));
      Atomics.store(flags, 0, 1);
      Atomics.notify(flags, 0);
      const results = await Promise.all(pending);
      assert.deepEqual(results.map((r) => r['status']).sort(), [
        'denied',
        'signed',
      ]);
      const check = openEnv(dir, opts);
      assert.equal(check.ledger.spendCount(), 1);
      check.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
