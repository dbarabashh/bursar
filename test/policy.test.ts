import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { addr, verifyTyped } from 'micro-eth-signer';
import { hexToBytes } from '@noble/hashes/utils.js';
import { parsePolicy, PolicyError } from '../src/config.ts';
import { computeResourceHash, type PaymentIntent } from '../src/intent.ts';
import { evaluate } from '../src/policy/engine.ts';
import {
  BASE_ONLY,
  cleanup,
  EVM_KEY,
  makeClock,
  makeEnv,
  MERCHANT,
  MERCHANT_B,
  policyYaml,
  sign,
  STRANGER,
  TOKEN,
  usdc,
  x402Body,
} from './helpers.ts';

const DAY = 86_400_000;

describe('within limits', () => {
  it('signs a valid x402 payment and writes an audit entry', async () => {
    const env = makeEnv();
    try {
      const r = await sign(env, x402Body({ amount: usdc(0.25) }));
      assert.equal(r.status, 200);
      assert.equal(r.body['status'], 'signed');
      assert.equal(r.body['usd'], '0.25');
      const payment = r.body['payment'] as {
        payload: { signature: string; authorization: Record<string, string> };
      };
      const auth = payment.payload.authorization;
      assert.equal(auth['from'], addr.fromPrivateKey(EVM_KEY));
      assert.equal(auth['to'], MERCHANT);
      assert.equal(auth['value'], usdc(0.25));
      const typed = {
        types: {
          TransferWithAuthorization: [
            { name: 'from', type: 'address' },
            { name: 'to', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'validAfter', type: 'uint256' },
            { name: 'validBefore', type: 'uint256' },
            { name: 'nonce', type: 'bytes32' },
          ],
        },
        primaryType: 'TransferWithAuthorization',
        domain: {
          name: 'USD Coin',
          version: '2',
          chainId: 8453n,
          verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        },
        message: {
          from: auth['from'] as string,
          to: auth['to'] as string,
          value: BigInt(auth['value'] as string),
          validAfter: BigInt(auth['validAfter'] as string),
          validBefore: BigInt(auth['validBefore'] as string),
          nonce: hexToBytes((auth['nonce'] as string).slice(2)),
        },
      } as const;
      assert.ok(
        verifyTyped(
          payment.payload.signature,
          typed,
          addr.fromPrivateKey(EVM_KEY),
        ),
      );
      const header = r.body['header'] as { name: string; value: string };
      assert.equal(header.name, 'PAYMENT-SIGNATURE');
      assert.deepEqual(
        JSON.parse(Buffer.from(header.value, 'base64').toString()),
        payment,
      );

      const lines = readFileSync(env.policy.state.auditPath, 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      assert.equal(lines.length, 1);
      assert.equal(lines[0].event, 'signed');
      assert.equal(lines[0].agent, 'nanocode');
      assert.equal(lines[0].usd, '0.25');
      assert.equal(lines[0].intent.recipient, MERCHANT);
      assert.ok(env.audit.verifyChain());
      assert.equal(env.ledger.spendCount(), 1);
    } finally {
      cleanup(env);
    }
  });
});

describe('per-transaction limit', () => {
  it('denies an amount above per_tx and signs nothing', async () => {
    const env = makeEnv();
    try {
      const r = await sign(env, x402Body({ amount: usdc(1.01) }));
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'per_tx_limit');
      assert.equal(r.body['signature'], undefined);
      assert.equal(env.ledger.spendCount(), 0);
      const lines = readFileSync(env.policy.state.auditPath, 'utf8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      assert.equal(lines[0].event, 'denied');
    } finally {
      cleanup(env);
    }
  });
});

describe('daily limit', () => {
  it('denies the payment that would cross per_day and resets at UTC midnight', async () => {
    const clock = makeClock(Date.UTC(2026, 10, 3, 23, 0, 0));
    const env = makeEnv({ perDay: '2.00', perRecipient: '10.00' }, clock);
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'b' }))).body[
          'status'
        ],
        'signed',
      );
      const third = await sign(env, x402Body({ amount: usdc(0.9), key: 'c' }));
      assert.equal(third.body['status'], 'denied');
      assert.equal(third.body['reason'], 'per_day_limit');
      assert.equal(env.ledger.spendCount(), 2);
      clock.advance(60 * 60 * 1000 + 1);
      const nextDay = await sign(
        env,
        x402Body({ amount: usdc(0.9), key: 'd' }),
      );
      assert.equal(nextDay.body['status'], 'signed');
    } finally {
      cleanup(env);
    }
  });

  it('rolling_24h window only frees budget 24h after each spend', async () => {
    const clock = makeClock(Date.UTC(2026, 10, 3, 23, 0, 0));
    const env = makeEnv(
      { perDay: '1.00', perRecipient: '10.00', window: 'rolling_24h' },
      clock,
    );
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      clock.advance(2 * 60 * 60 * 1000);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'b' }))).body[
          'reason'
        ],
        'per_day_limit',
      );
      clock.advance(DAY - 2 * 60 * 60 * 1000 + 1);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'c' }))).body[
          'status'
        ],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('allowlists', () => {
  it('denies unknown recipient, chain and asset, including an allowlisted recipient on the wrong chain', async () => {
    const env = makeEnv();
    try {
      const cases: [Record<string, unknown>, string][] = [
        [x402Body({ payTo: STRANGER, key: 'r' }), 'recipient_not_allowed'],
        [x402Body({ network: 'eip155:1', key: 'c' }), 'chain_not_allowed'],
        [
          x402Body({
            asset: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
            key: 'a',
          }),
          'asset_not_allowed',
        ],
        [x402Body({ network: 'eip155:10', key: 'wc' }), 'asset_not_allowed'],
        [
          x402Body({
            payTo: BASE_ONLY,
            network: 'eip155:4217',
            asset: '0x20c0000000000000000000000000000000000000',
            key: 'bo',
          }),
          'recipient_not_allowed_on_chain',
        ],
      ];
      for (const [body, reason] of cases) {
        const r = await sign(env, body);
        assert.equal(r.body['status'], 'denied', reason);
        assert.equal(r.body['reason'], reason);
      }
      assert.equal(
        (await sign(env, x402Body({ payTo: BASE_ONLY, key: 'ok' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(env.ledger.spendCount(), 1);
    } finally {
      cleanup(env);
    }
  });
});

describe('per-recipient limit', () => {
  it('triggers before the global daily limit', async () => {
    const env = makeEnv({ perDay: '10.00', perRecipient: '1.50' });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      const second = await sign(env, x402Body({ amount: usdc(0.9), key: 'b' }));
      assert.equal(second.body['reason'], 'per_recipient_day_limit');
      const other = await sign(
        env,
        x402Body({ amount: usdc(0.9), key: 'c', payTo: MERCHANT_B }),
      );
      assert.equal(other.body['status'], 'signed');
    } finally {
      cleanup(env);
    }
  });

  it('a recipient-specific max_usd_day overrides the default', async () => {
    const env = makeEnv({
      perDay: '10.00',
      perRecipient: '5.00',
      merchantMaxDay: '1.00',
    });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.6), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.6), key: 'b' }))).body[
          'reason'
        ],
        'per_recipient_day_limit',
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('wallet-wide daily limit', () => {
  it('caps the combined spend of all agents sharing the wallet', async () => {
    const env = makeEnv({
      perDay: '20.00',
      perRecipient: '10.00',
      walletPerDay: '1.50',
    });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'a' }), 'nanocode'))
          .body['status'],
        'signed',
      );
      const other = await sign(
        env,
        x402Body({ amount: usdc(0.9), key: 'b' }),
        'other',
      );
      assert.equal(other.body['reason'], 'wallet_per_day_limit');
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.6), key: 'c' }), 'other'))
          .body['status'],
        'signed',
      );
      const budget = env.app.budget('other').body as {
        perDay: { spentUsd: string };
        walletPerDay: { spentUsd: string; remainingUsd: string };
      };
      assert.equal(budget.perDay.spentUsd, '0.60');
      assert.equal(budget.walletPerDay.spentUsd, '1.50');
      assert.equal(budget.walletPerDay.remainingUsd, '0.00');
      env.clock.advance(DAY);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.9), key: 'd' }), 'other'))
          .body['status'],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });

  it('is absent from the budget when not configured', () => {
    const env = makeEnv();
    try {
      assert.equal(
        (env.app.budget('nanocode').body as Record<string, unknown>)[
          'walletPerDay'
        ],
        null,
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('velocity', () => {
  it('limits the number of payments per time window', async () => {
    const env = makeEnv({ velocity: { maxTx: 2, perSeconds: 60 } });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.01), key: 'a' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.01), key: 'b' }))).body[
          'status'
        ],
        'signed',
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.01), key: 'c' }))).body[
          'reason'
        ],
        'velocity_limit',
      );
      env.clock.advance(61_000);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.01), key: 'd' }))).body[
          'status'
        ],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('resource binding', () => {
  const resource = { method: 'GET', url: 'https://api.example.com/v1/data' };

  it('signs when resourceHash matches the resource the payment is for', async () => {
    const env = makeEnv();
    try {
      const r = await sign(
        env,
        x402Body({ resource, resourceHash: computeResourceHash(resource) }),
      );
      assert.equal(r.body['status'], 'signed');
    } finally {
      cleanup(env);
    }
  });

  it('denies when resourceHash does not match the resource descriptor', async () => {
    const env = makeEnv();
    try {
      const r = await sign(
        env,
        x402Body({
          resource,
          resourceHash: computeResourceHash({
            method: 'POST',
            url: resource.url,
          }),
        }),
      );
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'resource_hash_mismatch');
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      cleanup(env);
    }
  });

  it('denies when the 402 asks payment for a different resource than the one requested', async () => {
    const env = makeEnv();
    try {
      const other = { method: 'GET', url: 'https://api.example.com/v1/other' };
      const r = await sign(
        env,
        x402Body({ resource: other, resourceHash: computeResourceHash(other) }),
      );
      assert.equal(r.body['reason'], 'resource_hash_mismatch');
    } finally {
      cleanup(env);
    }
  });

  it('require_resource_hash denies payments without one', async () => {
    const env = makeEnv({ requireResourceHash: true });
    try {
      assert.equal(
        (await sign(env, x402Body())).body['reason'],
        'resource_hash_required',
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('approval threshold', () => {
  it('returns pending above the threshold and denies after the approval times out', async () => {
    const env = makeEnv({ approval: '0.50', approvalTimeout: 60 });
    try {
      const body = x402Body({ amount: usdc(0.7), key: 'big' });
      const first = await sign(env, body);
      assert.equal(first.status, 202);
      assert.equal(first.body['status'], 'pending');
      const approvalId = first.body['approvalId'] as string;
      assert.match(approvalId, /^apr_[0-9a-f]{24}$/);
      env.clock.advance(30_000);
      const again = await sign(env, body);
      assert.equal(again.body['status'], 'pending');
      assert.equal(again.body['approvalId'], approvalId);
      env.clock.advance(31_000);
      const late = await sign(env, body);
      assert.equal(late.body['status'], 'denied');
      assert.equal(late.body['reason'], 'approval_timeout');
      assert.equal(env.app.resolveApproval(approvalId, 'approved'), false);
      assert.equal((await sign(env, body)).body['reason'], 'approval_timeout');
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      cleanup(env);
    }
  });

  it('signs once a human approves, and denies once a human rejects', async () => {
    const env = makeEnv({ approval: '0.50' });
    try {
      const body = x402Body({ amount: usdc(0.7), key: 'big' });
      const pending = await sign(env, body);
      assert.ok(
        env.app.resolveApproval(
          pending.body['approvalId'] as string,
          'approved',
        ),
      );
      const done = await sign(env, body);
      assert.equal(done.body['status'], 'signed');
      assert.equal(
        (await sign(env, body)).body['signature'],
        done.body['signature'],
      );
      assert.equal(env.ledger.spendCount(), 1);

      const body2 = x402Body({ amount: usdc(0.7), key: 'big2' });
      const p2 = await sign(env, body2);
      assert.ok(
        env.app.resolveApproval(p2.body['approvalId'] as string, 'denied'),
      );
      assert.equal((await sign(env, body2)).body['reason'], 'approval_denied');
    } finally {
      cleanup(env);
    }
  });

  it('amounts at or below the threshold sign immediately', async () => {
    const env = makeEnv({ approval: '0.50' });
    try {
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.5) }))).body['status'],
        'signed',
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('dry run', () => {
  it('evaluates but never signs or charges', async () => {
    const env = makeEnv({ mode: 'dry_run' });
    try {
      const r = await sign(env, x402Body());
      assert.equal(r.body['status'], 'dry_run');
      assert.equal(r.body['decision'], 'allow');
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      cleanup(env);
    }
  });
});

describe('engine', () => {
  const policy = parsePolicy(policyYaml({ perTx: '1.00', perDay: '2.00' }), {
    baseDir: '/tmp',
    env: { TEST_TOKEN: TOKEN },
  });
  const intent: PaymentIntent = {
    protocol: 'x402',
    chain: 'eip155:8453',
    asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    recipient: MERCHANT,
    amount: 500_000n,
    decimals: 6,
    idempotencyKey: 'k',
    agentId: 'nanocode',
    raw: { description: 'pay 0.0001' },
  };
  const empty = {
    daySpent: 0n,
    recipientDaySpent: 0n,
    walletDaySpent: 0n,
    monthSpent: 0n,
    recentTxCount: 0,
    task: null,
  };

  it('is a pure function of policy, intent and snapshot', () => {
    assert.deepEqual(evaluate(policy, intent, empty, { approved: false }), {
      kind: 'allow',
      usd: 500_000n,
      feeUsd: 0n,
    });
    assert.deepEqual(
      evaluate(
        policy,
        intent,
        { ...empty, daySpent: 1_600_000n },
        { approved: false },
      ),
      {
        kind: 'deny',
        reason: 'per_day_limit',
        usd: 500_000n,
      },
    );
    assert.equal(
      evaluate(policy, { ...intent, decimals: 18 }, empty, { approved: false })
        .kind,
      'deny',
    );
    assert.equal(
      evaluate(policy, { ...intent, amount: 0n }, empty, { approved: false })
        .kind,
      'deny',
    );
    const walletPolicy = parsePolicy(
      policyYaml({ perTx: '1.00', perDay: '2.00', walletPerDay: '3.00' }),
      { baseDir: '/tmp', env: { TEST_TOKEN: TOKEN } },
    );
    assert.deepEqual(
      evaluate(
        walletPolicy,
        intent,
        { ...empty, walletDaySpent: 2_600_000n },
        { approved: false },
      ),
      {
        kind: 'deny',
        reason: 'wallet_per_day_limit',
        usd: 500_000n,
      },
    );
    assert.equal(
      evaluate(
        walletPolicy,
        intent,
        { ...empty, walletDaySpent: 2_500_000n },
        { approved: false },
      ).kind,
      'allow',
    );
  });

  it('adds network fees to per_tx, per_day and the approval threshold, but not to the recipient limit', () => {
    const p = parsePolicy(
      policyYaml({
        perTx: '1.00',
        perDay: '2.00',
        perRecipient: '0.50',
        approval: '0.50',
      }),
      { baseDir: '/tmp', env: { TEST_TOKEN: TOKEN } },
    );
    const tempo: PaymentIntent = {
      ...intent,
      protocol: 'mpp',
      chain: 'eip155:4217',
      asset: '0x20c0000000000000000000000000000000000000',
      fee: {
        asset: '0x20c0000000000000000000000000000000000000',
        amount: 1_000n,
        decimals: 6,
      },
    };
    assert.deepEqual(evaluate(p, tempo, empty, { approved: true }), {
      kind: 'allow',
      usd: 501_000n,
      feeUsd: 1_000n,
    });
    assert.equal(
      evaluate(p, tempo, empty, { approved: false }).kind,
      'require_approval',
    );
    assert.equal(
      evaluate(p, { ...tempo, amount: 999_500n }, empty, { approved: true })
        .kind,
      'deny',
    );
    assert.deepEqual(
      evaluate(
        p,
        tempo,
        { ...empty, daySpent: 1_499_500n },
        { approved: true },
      ),
      { kind: 'deny', reason: 'per_day_limit', usd: 501_000n },
    );
    assert.equal(
      evaluate(
        p,
        { ...tempo, fee: { ...tempo.fee!, amount: 20_000n } },
        empty,
        { approved: true },
      ).kind,
      'deny',
    );
    assert.deepEqual(
      evaluate(
        p,
        {
          ...tempo,
          fee: {
            ...tempo.fee!,
            asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
          },
        },
        empty,
        { approved: true },
      ),
      {
        kind: 'deny',
        reason: 'fee_asset_not_allowed',
        usd: null,
      },
    );
    assert.equal(
      evaluate(
        p,
        { ...intent, fee: { asset: intent.asset, amount: 1n, decimals: 6 } },
        empty,
        { approved: true },
      ).kind,
      'deny',
    );
  });

  it('rejects non-decimal and lossy numeric literals instead of silently converting them', () => {
    const env = { TEST_TOKEN: TOKEN };
    const withPerTx = (v: string) =>
      policyYaml().replace('per_tx: { usd: 1.00 }', `per_tx: { usd: ${v} }`);
    for (const bad of [
      '0x10',
      '0o17',
      '1e3',
      '007',
      '.inf',
      '-1',
      '1.0000001',
    ]) {
      assert.throws(
        () => parsePolicy(withPerTx(bad), { baseDir: '/tmp', env }),
        PolicyError,
        bad,
      );
    }
    assert.throws(
      () => parsePolicy(withPerTx('0x10'), { baseDir: '/tmp', env }),
      /line \d+: write numbers as plain decimals/,
    );
    assert.equal(
      parsePolicy(withPerTx('9007199254740993'), { baseDir: '/tmp', env })
        .limits.perTx,
      9007199254740993_000000n,
    );
    assert.equal(
      parsePolicy(withPerTx('"100.50"'), { baseDir: '/tmp', env }).limits.perTx,
      100_500_000n,
    );
    assert.equal(
      parsePolicy(withPerTx('0.000001'), { baseDir: '/tmp', env }).limits.perTx,
      1n,
    );
    assert.throws(
      () =>
        parsePolicy(policyYaml().replace('max_tx: 100', 'max_tx: 0x10'), {
          baseDir: '/tmp',
          env,
        }),
      PolicyError,
    );
    assert.equal(
      parsePolicy(policyYaml().replace('max_tx: 100', 'max_tx: "16"'), {
        baseDir: '/tmp',
        env,
      }).limits.velocity?.maxTx,
      16,
    );
  });

  it('refuses to allowlist native coins, since limits assume 1 token = 1 USD', () => {
    const yaml = policyYaml().replace(
      '  assets:\n',
      '  assets:\n    - { address: native, decimals: 18 }\n',
    );
    assert.throws(
      () => parsePolicy(yaml, { baseDir: '/tmp', env: { TEST_TOKEN: TOKEN } }),
      /native coins are not USD stablecoins/,
    );
    assert.throws(
      () =>
        parsePolicy(
          policyYaml().replace('  assets:\n', '  assets:\n    - NATIVE\n'),
          { baseDir: '/tmp', env: { TEST_TOKEN: TOKEN } },
        ),
      PolicyError,
    );
  });

  it('rejects unknown policy keys and missing env vars', () => {
    assert.throws(
      () =>
        parsePolicy(policyYaml().replace('per_tx:', 'per_txx:'), {
          baseDir: '/tmp',
          env: { TEST_TOKEN: TOKEN },
        }),
      PolicyError,
    );
    assert.throws(
      () => parsePolicy(policyYaml(), { baseDir: '/tmp', env: {} }),
      /TEST_TOKEN/,
    );
  });
});
