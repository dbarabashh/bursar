import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildReport, formatReport, periodFor } from '../src/report.ts';
import { canonicalJson, sha256Hex } from '../src/util.ts';
import {
  cleanup,
  makeClock,
  makeEnv,
  MERCHANT_B,
  policyYaml,
  sign,
  T0,
  TOKEN,
  usdc,
  x402Body,
  type TestEnv,
} from './helpers.ts';

const DAY = 86_400_000;

function open(
  env: TestEnv,
  budgetUsd: string,
  ttlSeconds = 3600,
  agent = 'nanocode',
  label = 'fix flaky test',
): string {
  const r = env.app.openTask(agent, { budgetUsd, ttlSeconds, label });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return (r.body as { taskId: string }).taskId;
}

describe('task budgets', () => {
  it('caps spend inside a task independently of the daily budget', async () => {
    const env = makeEnv({ perRecipient: '10.00' });
    try {
      const taskId = open(env, '1.00');
      assert.match(taskId, /^task_[0-9a-f]{24}$/);
      const first = await sign(env, {
        ...x402Body({ amount: usdc(0.6), key: 'a' }),
        taskId,
      });
      assert.equal(first.body['status'], 'signed');
      assert.deepEqual(first.body['task'], {
        id: taskId,
        remainingUsd: '0.40',
      });
      const over = await sign(env, {
        ...x402Body({ amount: usdc(0.6), key: 'b' }),
        taskId,
      });
      assert.equal(over.body['reason'], 'task_budget_limit');
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.6), key: 'c' }))).body[
          'status'
        ],
        'signed',
      );
      const b = env.app.budget('nanocode', taskId).body as {
        task: Record<string, unknown>;
        perDay: { spentUsd: string };
      };
      assert.equal(b.task['spentUsd'], '0.60');
      assert.equal(b.task['remainingUsd'], '0.40');
      assert.equal(b.task['label'], 'fix flaky test');
      assert.equal(b.perDay.spentUsd, '1.20');
    } finally {
      cleanup(env);
    }
  });

  it('rejects tasks of other agents, unknown and expired tasks', async () => {
    const env = makeEnv();
    try {
      const theirs = open(env, '1.00', 3600, 'other');
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'x' }), taskId: theirs })).body[
          'reason'
        ],
        'task_not_found',
      );
      assert.equal(
        (
          await sign(env, {
            ...x402Body({ key: 'y' }),
            taskId: 'task_000000000000000000000000',
          })
        ).body['reason'],
        'task_not_found',
      );
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'z' }), taskId: 'not-a-task' }))
          .status,
        400,
      );
      assert.equal(env.app.budget('nanocode', theirs).status, 404);
      const mine = open(env, '1.00', 60);
      env.clock.advance(60_000);
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'w' }), taskId: mine })).body[
          'reason'
        ],
        'task_expired',
      );
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      cleanup(env);
    }
  });

  it('per_task.required forces every payment into a task, and caps task size and lifetime', async () => {
    const env = makeEnv({
      perTask: { required: true, maxUsd: '5.00', maxTtlSeconds: 7200 },
    });
    try {
      assert.equal(
        (await sign(env, x402Body({ key: 'free' }))).body['reason'],
        'task_required',
      );
      assert.equal(
        env.app.openTask('nanocode', { budgetUsd: '5.01' }).status,
        400,
      );
      assert.equal(
        env.app.openTask('nanocode', { budgetUsd: '1.00', ttlSeconds: 7201 })
          .status,
        400,
      );
      assert.equal(
        env.app.openTask('nanocode', { budgetUsd: '0' }).status,
        400,
      );
      assert.equal(
        env.app.openTask('nanocode', { budgetUsd: 1, extra: true }).status,
        400,
      );
      const taskId = open(env, '5.00', 7200);
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'in' }), taskId })).body[
          'status'
        ],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });

  it('the task is part of the idempotency hash, and requests without one hash as before', async () => {
    const env = makeEnv();
    try {
      const a = open(env, '1.00');
      const b = open(env, '1.00');
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'k' }), taskId: a })).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(env, { ...x402Body({ key: 'k' }), taskId: b })).status,
        409,
      );
      const body = x402Body({ key: 'legacy' });
      await sign(env, body);
      const legacy = sha256Hex(
        canonicalJson({
          protocol: body['protocol'],
          payload: body['payload'],
          resourceHash: null,
          resource: null,
        }),
      );
      assert.equal(
        env.ledger.getIdempotency('nanocode:legacy')?.intentHash,
        legacy,
      );
    } finally {
      cleanup(env);
    }
  });

  it('is reachable over HTTP with the agent token only', async () => {
    const env = makeEnv();
    const { server, port } = await env.app.listen(0, '127.0.0.1');
    try {
      const post = (auth: string | null) =>
        fetch(`http://127.0.0.1:${port}/v1/tasks`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(auth === null ? {} : { authorization: `Bearer ${auth}` }),
          },
          body: JSON.stringify({
            budgetUsd: '2.50',
            ttlSeconds: 600,
            label: 'scrape docs',
          }),
        });
      assert.equal((await post(null)).status, 401);
      const r = await post(TOKEN);
      assert.equal(r.status, 201);
      const body = (await r.json()) as Record<string, string>;
      assert.equal(body['budgetUsd'], '2.50');
      const budget = await fetch(
        `http://127.0.0.1:${port}/v1/budget?taskId=${body['taskId']}`,
        { headers: { authorization: `Bearer ${TOKEN}` } },
      );
      assert.equal(
        ((await budget.json()) as { task: { remainingUsd: string } }).task
          .remainingUsd,
        '2.50',
      );
    } finally {
      server.close();
      cleanup(env);
    }
  });
});

describe('monthly limit', () => {
  it('calendar month: accumulates across days and resets on the 1st (UTC)', async () => {
    const clock = makeClock(Date.UTC(2026, 10, 28, 12));
    const env = makeEnv(
      { perRecipient: '10.00', perMonth: { usd: '2.00' } },
      clock,
    );
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      clock.advance(DAY);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'b' }))).body[
          'status'
        ],
        'signed',
      );
      clock.advance(DAY);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'c' }))).body[
          'reason'
        ],
        'per_month_limit',
      );
      const b = env.app.budget('nanocode').body as {
        perMonth: Record<string, unknown>;
      };
      assert.deepEqual(b.perMonth, {
        window: 'calendar_utc',
        limitUsd: '2.00',
        spentUsd: '1.80',
        remainingUsd: '0.20',
        resetsAt: '2026-12-01T00:00:00.000Z',
      });
      clock.set(Date.UTC(2026, 11, 1, 0, 0, 1));
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'd' }))).body[
          'status'
        ],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });

  it('rolling 30 days frees each payment 30 days after it was made', async () => {
    const env = makeEnv({
      perRecipient: '10.00',
      perMonth: { usd: '1.00', window: 'rolling_30d' },
    });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      env.clock.advance(29 * DAY);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'b' }))).body[
          'reason'
        ],
        'per_month_limit',
      );
      env.clock.advance(DAY + 1);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'c' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (env.app.budget('nanocode').body as { perMonth: { resetsAt: null } })
          .perMonth.resetsAt,
        null,
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('spend report', () => {
  async function activity(): Promise<TestEnv> {
    const env = makeEnv({ approval: '0.50', perRecipient: '10.00' });
    const taskId = open(env, '1.00', 3600, 'nanocode', 'refactor');
    await sign(env, { ...x402Body({ amount: usdc(0.3), key: 'a' }), taskId });
    await sign(
      env,
      x402Body({ amount: usdc(0.2), key: 'b', payTo: MERCHANT_B }),
    );
    await sign(env, x402Body({ amount: usdc(0.1), key: 'c' }), 'other');
    await sign(env, x402Body({ amount: usdc(3), key: 'd' }));
    await sign(env, x402Body({ amount: usdc(3), key: 'e' }), 'other');
    await sign(env, x402Body({ amount: usdc(0.7), key: 'f' }));
    return env;
  }

  it('summarises spend by agent, recipient and task, denials and pending approvals', async () => {
    const env = await activity();
    try {
      const r = buildReport(
        {
          policy: env.policy,
          ledger: env.ledger,
          audit: env.audit,
          now: env.clock.now(),
        },
        periodFor('month', env.clock.now()),
      );
      assert.equal(r.period.from, '2026-11-01T00:00:00.000Z');
      assert.deepEqual(r.totals, {
        payments: 3,
        usd: '0.60',
        feeUsd: '0.00',
        denied: 2,
        pendingApprovals: 1,
      });
      assert.deepEqual(
        r.byAgent.map((a) => [a.key, a.count, a.usd]),
        [
          ['nanocode', 2, '0.50'],
          ['other', 1, '0.10'],
        ],
      );
      assert.deepEqual(
        r.byRecipient.map((x) => [x.label, x.usd]),
        [
          ['merchant', '0.40'],
          ['merchant-b', '0.20'],
        ],
      );
      assert.deepEqual(
        r.byTask.map((t) => [t.label, t.agent, t.usd, t.budgetUsd]),
        [['refactor', 'nanocode', '0.30', '1.00']],
      );
      assert.deepEqual(r.denials, [
        { reason: 'per_tx_limit', count: 2, agents: ['nanocode', 'other'] },
      ]);
      assert.equal(r.approvals.pending.length, 1);
      assert.equal(r.audit.chainValid, true);
      const text = formatReport(r);
      assert.match(text, /payments 3 {3}spent \$0\.60/);
      assert.match(text, /hash chain intact/);
      assert.match(text, /refactor/);

      const yesterday = buildReport(
        {
          policy: env.policy,
          ledger: env.ledger,
          audit: env.audit,
          now: env.clock.now(),
        },
        periodFor('custom', 0, '2026-11-02T00:00:00Z', '2026-11-03T00:00:00Z'),
      );
      assert.equal(yesterday.totals.payments, 0);
      assert.throws(() => periodFor('week', T0), /--period/);
    } finally {
      cleanup(env);
    }
  });

  it('flags a tampered audit log', async () => {
    const env = await activity();
    try {
      appendFileSync(
        env.policy.state.auditPath,
        `${JSON.stringify({ ts: T0, agent: 'nanocode', event: 'signed', prev: '0'.repeat(64) })}\n`,
      );
      const r = buildReport(
        {
          policy: env.policy,
          ledger: env.ledger,
          audit: env.audit,
          now: env.clock.now(),
        },
        periodFor('all', env.clock.now()),
      );
      assert.equal(r.audit.chainValid, false);
      assert.match(formatReport(r), /BROKEN/);
    } finally {
      cleanup(env);
    }
  });

  it('bursar report --json works from the CLI', async () => {
    const env = await activity();
    try {
      const policyPath = join(env.dir, 'policy.yaml');
      writeFileSync(policyPath, policyYaml({ approval: '0.50' }));
      const cli = fileURLToPath(new URL('../src/index.ts', import.meta.url));
      const run = spawnSync(
        process.execPath,
        [cli, 'report', '--policy', policyPath, '--period', 'all', '--json'],
        { env: { ...process.env, TEST_TOKEN: TOKEN }, encoding: 'utf8' },
      );
      assert.equal(run.status, 0, run.stderr);
      const r = JSON.parse(run.stdout) as {
        totals: { payments: number; usd: string };
      };
      assert.equal(r.totals.payments, 3);
      assert.equal(r.totals.usd, '0.60');
      const text = spawnSync(
        process.execPath,
        [cli, 'report', '--policy', policyPath, '--period', 'all'],
        { env: { ...process.env, TEST_TOKEN: TOKEN }, encoding: 'utf8' },
      );
      assert.match(text.stdout, /By agent/);
    } finally {
      cleanup(env);
    }
  });
});
