import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { randomBytes } from '@noble/hashes/utils.js';
import { createApp, type App } from '../src/api/server.ts';
import { AuditLog } from '../src/audit.ts';
import { newKeyPair } from '../src/cashu/crypto.ts';
import {
  decodeToken,
  encodePaymentRequestA,
  encodeTokenV4,
} from '../src/cashu/encoding.ts';
import { createMintClient } from '../src/cashu/mint.ts';
import { createWallet, type Wallet } from '../src/cashu/wallet.ts';
import { parsePolicy, PolicyError } from '../src/config.ts';
import { Ledger } from '../src/ledger/store.ts';
import { openSigner, type Signer } from '../src/signer/index.ts';
import { sha256Hex } from '../src/util.ts';
import { fakeMint, type FakeMint } from './fixtures/fake-mint.ts';
import { makeClock, makeDir, TOKEN, type Clock } from './helpers.ts';

const MINT = 'http://127.0.0.1:3338';
const SHOP = 'https://shop.example';
const merchant = newKeyPair(randomBytes);

function yaml(o: { satLimits?: boolean } = {}): string {
  const sat = o.satLimits !== false;
  return [
    'version: 1',
    'wallet: { keyfile: ./key, env: BURSAR_TEST_KEY_UNSET }',
    'agents:',
    "  - { id: nanocode, token: '${TEST_TOKEN}' }",
    'limits:',
    `  per_tx: { usd: 1.00${sat ? ', sat: 500' : ''} }`,
    `  per_day: { usd: 20.00${sat ? ', sat: 2000' : ''} }`,
    `  per_recipient_day: { usd: 5.00${sat ? ', sat: 1500' : ''} }`,
    `  approval_threshold: { usd: 5.00${sat ? ', sat: 300' : ''}, timeout_seconds: 60 }`,
    '  velocity: { max_tx: 100, per_seconds: 60 }',
    'allow:',
    `  chains: ['eip155:8453'${sat ? ", 'cashu:sat'" : ''}]`,
    "  assets: [{ address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chains: ['eip155:8453'] }]",
    '  recipients:',
    `    - { address: '${merchant.pub}', label: locked-merchant }`,
    `    - { address: '${SHOP}', label: shop, max_sat_day: 400 }`,
    'cashu:',
    `  mints: [{ url: '${MINT}', units: [sat] }]`,
    '  max_fee: { sat: 5 }',
    'evm: { simulate_before_sign: false }',
  ].join('\n');
}

type Env = {
  dir: string;
  app: App;
  ledger: Ledger;
  signer: Signer;
  wallet: Wallet;
  mint: FakeMint;
  clock: Clock;
  delivered: { url: string; init: RequestInit }[];
  merchantMode: { mode: 'redeem' | 'reject' | 'down' };
};

let env: Env;

function open(
  o: Parameters<typeof yaml>[0] = {},
  mintOpts: Parameters<typeof fakeMint>[0] = {},
): Env {
  const dir = makeDir();
  const policy = parsePolicy(yaml(o), {
    baseDir: dir,
    env: { TEST_TOKEN: TOKEN },
  });
  const signer = openSigner({
    keyfile: policy.wallet.keyfile,
    envVar: policy.wallet.envVar,
    env: {},
  });
  const ledger = new Ledger(policy.state.ledgerPath);
  const audit = new AuditLog(policy.state.auditPath, (fn) =>
    ledger.transaction(fn),
  );
  const clock = makeClock();
  const mint = fakeMint({ url: MINT, ...mintOpts });
  const wallet = createWallet({
    ledger,
    client: (m) => createMintClient(m, { fetch: mint.fetch }),
    random: randomBytes,
    now: clock.now,
  });
  const delivered: Env['delivered'] = [];
  const merchantMode: Env['merchantMode'] = { mode: 'redeem' };
  const app = createApp({
    policy,
    signer,
    ledger,
    audit,
    now: clock.now,
    wallet,
    // The shop: redeems the token at the mint before serving, as NUT-24 asks.
    deliverFetch: async (url, init) => {
      delivered.push({ url, init: init ?? {} });
      if (merchantMode.mode === 'down') throw new Error('connect ECONNREFUSED');
      if (merchantMode.mode === 'reject')
        return new Response('wrong unit', { status: 400 });
      const token = new Headers(init?.headers).get('x-cashu') ?? '';
      const r = await mint.redeem(decodeToken(token).proofs, null);
      return r.ok
        ? new Response('{"data":"paid content"}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        : new Response('bad token', { status: 400 });
    },
  });
  return {
    dir,
    app,
    ledger,
    signer,
    wallet,
    mint,
    clock,
    delivered,
    merchantMode,
  };
}

async function fund(
  amount: number,
  wallet: Wallet = env.wallet,
): Promise<void> {
  const { opId } = await wallet.fundStart(MINT, 'sat', amount, null);
  await wallet.fundFinish(opId, {
    timeoutMs: 1000,
    pollMs: 1,
    sleep: async () => {},
  });
}

const balance = () => env.wallet.balance(MINT, 'sat');

function lockedBody(amount: number, key = 'c-1', extraTags: string[][] = []) {
  return {
    protocol: 'cashu',
    idempotencyKey: key,
    payload: {
      paymentRequest: encodePaymentRequestA({
        a: amount,
        u: 'sat',
        m: [MINT],
        nut10: { k: 'P2PK', d: merchant.pub, t: extraTags },
      }),
    },
  };
}

function unlockedBody(amount: number, key = 'u-1', url = `${SHOP}/v1/data`) {
  return {
    protocol: 'cashu',
    idempotencyKey: key,
    payload: {
      paymentRequest: encodePaymentRequestA({ a: amount, u: 'sat', m: [MINT] }),
      deliver: { headers: { accept: 'application/json' } },
    },
    resource: { method: 'GET', url, bodySha256: sha256Hex('') },
  };
}

async function sign(body: unknown) {
  const r = await env.app.sign('nanocode', body);
  return { status: r.status, body: r.body as Record<string, unknown> };
}

function satSpent(): Record<string, unknown> {
  const b = env.app.budget('nanocode').body as Record<string, unknown>;
  return b['sat'] as Record<string, unknown>;
}

const satDaySpent = () => (satSpent()['perDay'] as { spent: string }).spent;

function closeEnv(e: Env): void {
  e.signer.close();
  e.ledger.close();
  rmSync(e.dir, { recursive: true, force: true });
}

function reopen(...args: Parameters<typeof open>): void {
  closeEnv(env);
  env = open(...args);
}

beforeEach(() => {
  env = open();
});
afterEach(() => closeEnv(env));

describe('cashu policy', () => {
  it('needs sat limits before cashu:sat can be allowed', () => {
    const dir = makeDir();
    assert.throws(
      () =>
        parsePolicy(
          yaml({ satLimits: false }).replace(
            "chains: ['eip155:8453']",
            "chains: ['eip155:8453', 'cashu:sat']",
          ),
          { baseDir: dir, env: { TEST_TOKEN: TOKEN } },
        ),
      (e: Error) => e instanceof PolicyError && /sat limits/.test(e.message),
    );
    assert.throws(
      () =>
        parsePolicy(yaml().replace(', sat: 300', ''), {
          baseDir: dir,
          env: { TEST_TOKEN: TOKEN },
        }),
      /approval_threshold.sat/,
    );
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('cashu funding', () => {
  it('mints ecash from a paid quote (NUT-20 locked) into the wallet', async () => {
    await fund(1000);
    assert.equal(balance(), 1000);
  });
});

describe('cashu locked payments (P2PK)', () => {
  it('returns an X-Cashu token only the merchant key can redeem, and charges sat limits', async () => {
    await fund(1000);
    const r = await sign(lockedBody(100));
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body['status'], 'signed');
    assert.equal(r.body['sat'], '100');
    assert.equal(r.body['recipient'], merchant.pub.slice(2));
    const header = r.body['header'] as { name: string; value: string };
    assert.equal(header.name, 'X-Cashu');
    const token = decodeToken(header.value);
    assert.equal(token.mint, MINT);
    assert.equal(
      token.proofs.reduce((s, p) => s + p.amount, 0),
      100,
    );
    assert.ok(
      token.proofs.every(
        (p) => p.secret.startsWith('["P2PK"') && p.dleq !== undefined,
      ),
    );
    assert.equal(balance(), 900);
    // Without the merchant's key the token is worthless to whoever holds it.
    assert.equal((await env.mint.redeem(token.proofs, null)).status, 400);
    assert.equal(
      (await env.mint.redeem(token.proofs, merchant.priv)).status,
      200,
    );
    const spent = satSpent();
    assert.deepEqual(spent['perDay'], {
      limit: '2000',
      spent: '100',
      remaining: '1900',
    });
    // USD budget untouched: no conversion between the two.
    const usd = env.app.budget('nanocode').body as Record<
      string,
      { spentUsd: string }
    >;
    assert.equal(usd['perDay']?.spentUsd, '0.00');
  });

  it('replays the same token for the same idempotency key', async () => {
    await fund(1000);
    const a = await sign(lockedBody(50, 'same'));
    const b = await sign(lockedBody(50, 'same'));
    assert.deepEqual(a.body, b.body);
    assert.equal(balance(), 950);
  });

  it('refuses locks whose tags open another spending path', async () => {
    await fund(1000);
    for (const tags of [
      [['refund', `02${'11'.repeat(32)}`]],
      [['locktime', '1']],
      [['pubkeys', `02${'22'.repeat(32)}`]],
    ]) {
      const r = await sign(lockedBody(10, `t-${tags[0]![0]}`, tags));
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'cashu_lock_not_supported');
    }
    assert.equal(balance(), 1000);
  });

  it('refuses a key that is not on the list', async () => {
    await fund(1000);
    const other = newKeyPair(randomBytes);
    const body = lockedBody(10);
    body.payload.paymentRequest = encodePaymentRequestA({
      a: 10,
      u: 'sat',
      m: [MINT],
      nut10: { k: 'P2PK', d: other.pub, t: [] },
    });
    const r = await sign(body);
    assert.equal(r.body['reason'], 'recipient_not_allowed');
  });

  it('enforces sat per-tx and approval thresholds', async () => {
    await fund(2000);
    assert.equal(
      (await sign(lockedBody(600, 'big'))).body['reason'],
      'per_tx_limit',
    );
    const p = await sign(lockedBody(350, 'thr'));
    assert.equal(p.status, 202);
    assert.equal(p.body['status'], 'pending');
    assert.equal(p.body['reason'], 'threshold');
    assert.equal(balance(), 2000);
    assert.equal(
      env.app.resolveApproval(String(p.body['approvalId']), 'approved'),
      true,
    );
    const done = await sign(lockedBody(350, 'thr'));
    assert.equal(done.body['status'], 'signed');
    assert.equal(balance(), 1650);
  });

  it('charges a task budget in sat, and refuses tasks without one', async () => {
    await fund(1000);
    const t = env.app.openTask('nanocode', {
      budgetSat: '120',
      label: 'cashu research',
    });
    assert.equal(t.status, 201, JSON.stringify(t.body));
    const taskId = String((t.body as Record<string, unknown>)['taskId']);
    const a = await sign({ ...lockedBody(100, 'task-a'), taskId });
    assert.equal(a.body['status'], 'signed');
    assert.deepEqual(a.body['task'], { id: taskId, remainingSat: '20' });
    assert.equal(
      (await sign({ ...lockedBody(30, 'task-b'), taskId })).body['reason'],
      'task_budget_limit',
    );
    const usdOnly = env.app.openTask('nanocode', { budgetUsd: '0.50' });
    const usdTask = String((usdOnly.body as Record<string, unknown>)['taskId']);
    assert.equal(
      (await sign({ ...lockedBody(10, 'task-c'), taskId: usdTask })).body[
        'reason'
      ],
      'task_budget_limit',
    );
    assert.equal(
      env.app.openTask('nanocode', { budgetSat: '999999' }).status,
      400,
    );
  });

  it('refuses a mint that is not in the policy and an empty wallet', async () => {
    const body = lockedBody(10);
    body.payload.paymentRequest = encodePaymentRequestA({
      a: 10,
      u: 'sat',
      m: ['https://other.mint'],
      nut10: { k: 'P2PK', d: merchant.pub, t: [] },
    });
    assert.equal((await sign(body)).body['reason'], 'mint_not_allowed');
    assert.equal(
      (await sign(lockedBody(10, 'empty'))).body['reason'],
      'insufficient_balance',
    );
  });

  it('refuses to lock at a mint that does not enforce P2PK', async () => {
    reopen({}, { p2pk: false });
    await fund(100);
    assert.equal(
      (await sign(lockedBody(10))).body['reason'],
      'mint_lacks_p2pk',
    );
  });
});

describe('cashu unlocked payments (delivered by bursar)', () => {
  it('delivers the token to the allowlisted origin and returns the response', async () => {
    await fund(1000);
    const r = await sign(unlockedBody(40));
    assert.equal(r.body['status'], 'paid', JSON.stringify(r.body));
    assert.equal(r.body['recipient'], SHOP);
    assert.deepEqual((r.body['response'] as { status: number }).status, 200);
    assert.equal(
      r.body['header'],
      undefined,
      'the agent never sees an unlocked token',
    );
    assert.equal(env.delivered.length, 1);
    assert.equal(env.delivered[0]!.url, `${SHOP}/v1/data`);
    assert.equal(balance(), 960);
    assert.equal(
      (satSpent()['recipients'] as { address: string; spent: string }[]).find(
        (x) => x.address === SHOP,
      )?.spent,
      '40',
    );
  });

  it('takes the ecash back when the merchant refuses it, and refunds the limits', async () => {
    await fund(1000);
    env.merchantMode.mode = 'reject';
    const r = await sign(unlockedBody(40));
    assert.equal(r.body['status'], 'denied');
    assert.equal(r.body['reason'], 'merchant_rejected');
    assert.equal(balance(), 1000);
    assert.equal(satDaySpent(), '0');
  });

  it('with mint fees, the limits count exactly what left the wallet', async () => {
    reopen({}, { feePpk: 100 });
    await fund(1000);
    const paid = await sign(unlockedBody(40, 'fee-paid'));
    assert.equal(paid.body['status'], 'paid');
    env.merchantMode.mode = 'reject';
    const refused = await sign(unlockedBody(40, 'fee-refused'));
    assert.equal(refused.body['reason'], 'merchant_rejected');
    const spent = Number(satDaySpent());
    assert.equal(spent, 1000 - balance());
    assert.ok(spent > 40, 'fees are counted');
  });

  it('takes the ecash back when the merchant is unreachable', async () => {
    await fund(1000);
    env.merchantMode.mode = 'down';
    const r = await sign(unlockedBody(40));
    assert.equal(r.body['reason'], 'merchant_rejected');
    assert.equal(balance(), 1000);
  });

  it('applies the per-recipient sat cap of the origin', async () => {
    await fund(2000);
    assert.equal((await sign(unlockedBody(250, 'a'))).body['status'], 'paid');
    assert.equal(
      (await sign(unlockedBody(200, 'b'))).body['reason'],
      'per_recipient_day_limit',
    );
  });

  it('refuses unknown origins and plain http', async () => {
    await fund(1000);
    assert.equal(
      (await sign(unlockedBody(10, 'x', 'https://evil.example/steal'))).body[
        'reason'
      ],
      'recipient_not_allowed',
    );
    assert.equal(
      (await sign(unlockedBody(10, 'y', 'http://shop.example/v1/data'))).body[
        'reason'
      ],
      'cashu_delivery_needs_https',
    );
    assert.equal(env.delivered.length, 0);
  });

  it('refuses an unlocked request without delivery details', async () => {
    const r = await sign({
      protocol: 'cashu',
      idempotencyKey: 'n',
      payload: {
        paymentRequest: encodePaymentRequestA({ a: 5, u: 'sat', m: [MINT] }),
      },
    });
    assert.equal(r.body['reason'], 'cashu_delivery_required');
  });
});

describe('cashu mint failures', () => {
  it('a refused swap releases the proofs and refunds the limits', async () => {
    await fund(1000);
    env.mint.refuseNextSwap = true;
    const r = await sign(lockedBody(100));
    assert.equal(r.body['reason'], 'mint_refused');
    assert.equal(balance(), 1000);
    assert.equal(satDaySpent(), '0');
    assert.equal(
      (await sign(lockedBody(100, 'again'))).body['status'],
      'signed',
    );
  });

  it('a lost swap answer is recovered with NUT-09 restore, not swapped twice', async () => {
    await fund(1000);
    env.mint.dropNextSwapResponse = true;
    const r = await sign(lockedBody(100, 'lost'));
    assert.equal(r.body['status'], 'signed', JSON.stringify(r.body));
    assert.equal(env.mint.swaps, 1);
    assert.equal(balance(), 900);
  });

  it('when the mint goes away mid-payment, it stays processing and settles on retry', async () => {
    await fund(1000);
    for (const p of ['/v1/swap', '/v1/restore', '/v1/checkstate'])
      env.mint.downPaths.add(p);
    const first = await sign(lockedBody(100, 'later'));
    assert.equal(first.status, 202);
    assert.equal(first.body['status'], 'processing');
    assert.equal(satDaySpent(), '100', 'counted while in flight');
    assert.ok(balance() < 1000, 'inputs stay reserved');
    env.mint.downPaths.clear();
    // The swap never reached the mint: restore finds nothing and the inputs
    // are unspent, so the payment is released and refunded. It is not sent
    // a second time.
    const again = await sign(lockedBody(100, 'later'));
    assert.equal(again.body['reason'], 'mint_refused');
    assert.equal(env.mint.swaps, 0);
    assert.equal(balance(), 1000);
    assert.equal(satDaySpent(), '0');
  });

  it('a swap the mint did process while unreachable is recovered on retry', async () => {
    await fund(1000);
    env.mint.dropNextSwapResponse = true;
    env.mint.downPaths.add('/v1/restore');
    const first = await sign(lockedBody(100, 'later2'));
    assert.equal(first.body['status'], 'processing');
    env.mint.downPaths.clear();
    const again = await sign(lockedBody(100, 'later2'));
    assert.equal(again.body['status'], 'signed');
    assert.equal(env.mint.swaps, 1);
    assert.equal(balance(), 900);
  });
});

describe('cashu operator commands', () => {
  it('receives a token into the wallet and withdraws over lightning', async () => {
    // A token from another wallet: mint it at the fake mint directly.
    const otherLedger = new Ledger(`${env.dir}/other.db`);
    const other = createWallet({
      ledger: otherLedger,
      client: (m) => createMintClient(m, { fetch: env.mint.fetch }),
      random: randomBytes,
      now: env.clock.now,
    });
    await fund(64, other);
    await env.wallet.syncKeysets(MINT);
    const plan = other.planSend(MINT, 'sat', 64);
    assert.ok(!(plan instanceof Error));
    other.reserveSend(plan, 'gift', null, {});
    const out = await other.runSwap('gift');
    assert.equal(out.kind, 'ok');
    const got = await env.wallet.receive(
      (out as { token: string }).token,
      () => ({ maxBalance: null }),
    );
    assert.equal(got.amount, 64);
    assert.equal(balance(), 64);
    const w = await env.wallet.withdraw(MINT, 'sat', 'lntest40');
    assert.equal(w.amount, 40);
    assert.equal(balance(), 64 - 40 - 1);
    otherLedger.close();
  });

  it('a withdrawal stuck in flight is settled once the mint reports it paid', async () => {
    await fund(64);
    env.mint.meltMode = 'pending';
    await assert.rejects(
      env.wallet.withdraw(MINT, 'sat', 'lntest40'),
      /melt_pending/,
    );
    assert.equal(balance(), 0, 'the ecash is reserved while in flight');
    // Still in flight: recovery leaves it alone.
    assert.deepEqual(
      (await env.wallet.sweep(0)).map((r) => r.outcome),
      ['pending'],
    );
    env.mint.finishMelt(env.mint.pendingMelts()[0]!, true);
    assert.deepEqual(
      (await env.wallet.sweep(0)).map((r) => r.outcome),
      ['paid'],
    );
    // 40 paid, 1 sat routing fee; the change came back through NUT-09.
    assert.equal(balance(), 64 - 40 - 1);
    assert.deepEqual(await env.wallet.sweep(0), [], 'settled exactly once');
  });

  it('a withdrawal whose lightning payment fails gives the ecash back', async () => {
    await fund(64);
    env.mint.meltMode = 'pending';
    await assert.rejects(
      env.wallet.withdraw(MINT, 'sat', 'lntest40'),
      /melt_pending/,
    );
    env.mint.finishMelt(env.mint.pendingMelts()[0]!, false);
    assert.deepEqual(
      (await env.wallet.sweep(0)).map((r) => r.outcome),
      ['failed'],
    );
    assert.equal(balance(), 64);
  });

  it('the daemon sweep settles stuck withdrawals too', async () => {
    await fund(64);
    env.mint.meltMode = 'pending';
    await assert.rejects(
      env.wallet.withdraw(MINT, 'sat', 'lntest40'),
      /melt_pending/,
    );
    env.mint.finishMelt(env.mint.pendingMelts()[0]!, true);
    env.clock.advance(10 * 60_000);
    await env.app.sweepCashu();
    assert.equal(balance(), 23);
  });

  it('refuses tokens from mints outside the policy', async () => {
    const token = encodeTokenV4({
      mint: 'https://other.mint.example',
      unit: 'sat',
      proofs: [],
    });
    await assert.rejects(
      env.wallet.receive(token, () => null),
      /mint_not_allowed/,
    );
  });
});
