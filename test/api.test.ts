import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import {
  cleanup,
  erc20TransferData,
  EVM_KEY,
  evmBody,
  makeEnv,
  SOL_KEY,
  TOKEN,
  TOKEN_OTHER,
  usdc,
  x402Body,
  type TestEnv,
} from './helpers.ts';

let env: TestEnv;
let server: Server;
let base: string;
const seen: string[] = [];

async function call(
  path: string,
  init: RequestInit = {},
  token: string | null = TOKEN,
): Promise<{
  status: number;
  text: string;
  json: () => Record<string, unknown>;
}> {
  const headers = new Headers(init.headers);
  if (token !== null) headers.set('authorization', `Bearer ${token}`);
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  const res = await fetch(`${base}${path}`, { ...init, headers });
  const text = await res.text();
  seen.push(text);
  return {
    status: res.status,
    text,
    json: () => JSON.parse(text) as Record<string, unknown>,
  };
}

before(async () => {
  env = makeEnv();
  const l = await env.app.listen(0, '127.0.0.1');
  server = l.server;
  base = `http://127.0.0.1:${l.port}`;
});

after(() => {
  server.close();
  cleanup(env);
});

describe('authentication', () => {
  it('rejects missing or invalid bearer tokens on every route with 401', async () => {
    const routes: [string, RequestInit][] = [
      ['/v1/sign', { method: 'POST', body: JSON.stringify(x402Body()) }],
      ['/v1/budget', {}],
      ['/v1/audit?since=0', {}],
    ];
    for (const [path, init] of routes) {
      for (const token of [
        null,
        '',
        'wrong-token-wrong-token-wrong',
        `${TOKEN}x`,
        TOKEN.slice(0, -1),
      ]) {
        const r = await call(path, init, token);
        assert.equal(r.status, 401, `${path} with ${String(token)}`);
        assert.equal(r.json()['error'], 'unauthorized');
      }
      const basic = await call(
        path,
        {
          ...init,
          headers: {
            authorization: `Basic ${Buffer.from(`nanocode:${TOKEN}`).toString('base64')}`,
          },
        },
        null,
      );
      assert.equal(basic.status, 401);
    }
    assert.equal(env.ledger.spendCount(), 0);
  });

  it('accepts each agent with its own token and attributes spend to it', async () => {
    const r = await call(
      '/v1/sign',
      { method: 'POST', body: JSON.stringify(x402Body({ key: 'other-1' })) },
      TOKEN_OTHER,
    );
    assert.equal(r.json()['status'], 'signed');
    const b = (await call('/v1/budget', {}, TOKEN_OTHER)).json();
    assert.equal(b['agent'], 'other');
    assert.equal((b['perDay'] as Record<string, string>)['spentUsd'], '0.10');
    const mine = (await call('/v1/budget')).json();
    assert.equal(
      (mine['perDay'] as Record<string, string>)['spentUsd'],
      '0.00',
    );
  });
});

describe('no raw signing, no key extraction', () => {
  it('exposes only the three documented routes', async () => {
    for (const path of [
      '/',
      '/v1',
      '/v1/sign/raw',
      '/v1/sign-raw',
      '/v1/sign_message',
      '/v1/key',
      '/v1/keys',
      '/v1/export',
      '/v1/address',
      '/v1/approvals',
      '/debug',
    ]) {
      for (const method of ['GET', 'POST']) {
        const r = await call(
          path,
          method === 'POST' ? { method, body: '{}' } : { method },
        );
        assert.equal(r.status, 404, `${method} ${path}`);
      }
    }
    assert.equal((await call('/v1/sign')).status, 405);
    assert.equal(
      (await call('/v1/budget', { method: 'POST', body: '{}' })).status,
      405,
    );
  });

  it('refuses protocols that would sign arbitrary bytes or messages', async () => {
    for (const protocol of [
      'raw',
      'bytes',
      'eth_sign',
      'personal_sign',
      'eip191',
      'eip712',
      'typed_data',
      'solana_message',
      'X402',
    ]) {
      const r = await call('/v1/sign', {
        method: 'POST',
        body: JSON.stringify({
          protocol,
          payload: { data: '0xdeadbeef' },
          idempotencyKey: `p-${protocol}`,
        }),
      });
      assert.equal(r.status, 400, protocol);
      assert.equal(r.json()['error'], 'protocol_not_supported');
    }
    const extra = await call('/v1/sign', {
      method: 'POST',
      body: JSON.stringify({
        ...x402Body({ key: 'extra' }),
        message: '0xdeadbeef',
      }),
    });
    assert.equal(extra.status, 400);
    const arbitrary = await call('/v1/sign', {
      method: 'POST',
      body: JSON.stringify(
        evmBody(`0x12345678${'00'.repeat(32)}`, { key: 'arb' }),
      ),
    });
    assert.equal(arbitrary.json()['reason'], 'selector_not_allowed');
    const approve = await call('/v1/sign', {
      method: 'POST',
      body: JSON.stringify(
        evmBody(
          erc20TransferData(
            '0x1111111111111111111111111111111111111111',
            2n ** 255n,
            '095ea7b3',
          ),
          { key: 'approve' },
        ),
      ),
    });
    assert.equal(approve.json()['reason'], 'selector_not_allowed');
  });

  it('rejects malformed and oversized bodies', async () => {
    assert.equal(
      (await call('/v1/sign', { method: 'POST', body: '{not json' })).status,
      400,
    );
    assert.equal(
      (
        await call('/v1/sign', {
          method: 'POST',
          body: JSON.stringify({ protocol: 'x402' }),
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await call('/v1/sign', {
          method: 'POST',
          body: JSON.stringify({ pad: 'x'.repeat(70_000) }),
        })
      ).status,
      413,
    );
  });

  it('rejects requests whose Host header is not loopback', async () => {
    const r = await new Promise<number>((resolve) => {
      import('node:http').then(({ request }) => {
        const url = new URL(base);
        const req = request(
          {
            host: url.hostname,
            port: url.port,
            path: '/v1/budget',
            headers: { host: 'evil.example', authorization: `Bearer ${TOKEN}` },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.end();
      });
    });
    assert.equal(r, 403);
  });

  it('never leaks key material in responses, the audit log or the ledger', async () => {
    await call('/v1/sign', {
      method: 'POST',
      body: JSON.stringify(x402Body({ key: 'leak-1', amount: usdc(0.2) })),
    });
    await call('/v1/sign', {
      method: 'POST',
      body: JSON.stringify(
        x402Body({ key: 'leak-2', network: 'solana:mainnet' }),
      ),
    });
    seen.push((await call('/v1/audit?since=0')).text);
    const files = [
      env.policy.state.auditPath,
      env.policy.state.ledgerPath,
      `${env.policy.state.ledgerPath}-wal`,
    ]
      .filter((f) => {
        try {
          return statSync(f).isFile();
        } catch {
          return false;
        }
      })
      .map((f) => readFileSync(f).toString('latin1'));
    const evmHex = EVM_KEY.slice(2);
    for (const text of [...seen, ...files]) {
      assert.ok(!text.toLowerCase().includes(evmHex), 'evm key leaked');
      assert.ok(!text.toLowerCase().includes(SOL_KEY), 'solana key leaked');
    }
  });

  it('the signer exposes no key and only sign/addresses/close', async () => {
    assert.deepEqual(Object.keys(env.signer).sort(), [
      'addresses',
      'close',
      'sign',
    ]);
    assert.ok(!JSON.stringify(env.signer).includes(EVM_KEY.slice(2)));
    const mod = await import('../src/signer/index.ts');
    assert.deepEqual(Object.keys(mod).sort(), ['SignerError', 'openSigner']);
  });

  it('only src/signer imports the keystore, and nothing calls raw-message signing helpers', () => {
    const root = fileURLToPath(new URL('../src/', import.meta.url));
    const walk = (d: string): string[] =>
      readdirSync(d, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)],
      );
    for (const file of walk(root)) {
      const src = readFileSync(file, 'utf8');
      const rel = file.slice(root.length).replaceAll('\\', '/');
      if (!rel.startsWith('signer/') && rel !== 'index.ts')
        assert.ok(!/keystore/.test(src), `${rel} touches the keystore`);
      if (rel === 'index.ts')
        assert.ok(!/loadKeys/.test(src), 'CLI must not load keys directly');
      assert.ok(
        !/\b(signBytes|eip191Signer|signMessage|personal_sign)\b/.test(src),
        `${rel} uses a raw-message signer`,
      );
    }
  });
});

describe('budget and audit routes', () => {
  it('reports remaining budget per day and per recipient', async () => {
    const b = (await call('/v1/budget')).json();
    assert.equal(b['window'], 'calendar_utc');
    assert.equal(b['windowResetsAt'], '2026-11-04T00:00:00.000Z');
    const perDay = b['perDay'] as Record<string, string>;
    assert.equal(perDay['limitUsd'], '20.00');
    assert.equal(perDay['spentUsd'], '0.30');
    assert.equal(perDay['remainingUsd'], '19.70');
    const merchant = (b['recipients'] as Record<string, unknown>[]).find(
      (r) => r['label'] === 'merchant',
    );
    assert.equal(merchant?.['spentUsd'], '0.20');
    assert.equal(merchant?.['remainingUsd'], '4.80');
    const solMerchant = (b['recipients'] as Record<string, unknown>[]).find(
      (r) => r['label'] === 'sol-merchant',
    );
    assert.equal(solMerchant?.['spentUsd'], '0.10');
  });

  it("returns this agent's audit entries as JSONL, filtered by since", async () => {
    const all = await call('/v1/audit?since=0');
    const entries = all.text
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.ok(entries.length > 0);
    assert.ok(entries.every((e) => e['agent'] === 'nanocode'));
    assert.ok(entries.some((e) => e['event'] === 'signed'));
    env.clock.advance(1000);
    const future = await call(
      `/v1/audit?since=${new Date(env.clock.now()).toISOString()}`,
    );
    assert.equal(future.text, '');
    assert.equal((await call('/v1/audit?since=yesterday')).status, 400);
  });
});
