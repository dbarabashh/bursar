import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import { createMcpServer } from '../src/mcp/server.ts';
import {
  cleanup,
  makeEnv,
  MERCHANT,
  STRANGER,
  TOKEN,
  USDC_BASE,
  usdc,
  type TestEnv,
} from './helpers.ts';

type Shop = { url: string; paid: string[]; close: () => void };

function listen(server: Server): Promise<string> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`),
    ),
  );
}

async function shop(
  prices: Record<string, { amount: string; payTo: string }>,
): Promise<Shop> {
  const paid: string[] = [];
  let base = '';
  const server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    if (path === '/free')
      return void res
        .writeHead(200, { 'content-type': 'text/plain' })
        .end('free content');
    const offer = prices[path];
    if (!offer) return void res.writeHead(404).end();
    const header = req.headers['payment-signature'];
    if (typeof header !== 'string') {
      const body = {
        x402Version: 2,
        resource: {
          url: `${base}${path}`,
          description: 'thing',
          mimeType: 'application/json',
        },
        accepts: [
          {
            scheme: 'exact',
            network: 'eip155:8453',
            asset: USDC_BASE,
            payTo: offer.payTo,
            amount: offer.amount,
            maxTimeoutSeconds: 60,
            extra: { name: 'USD Coin', version: '2' },
          },
        ],
      };
      return void res
        .writeHead(402, {
          'payment-required': Buffer.from(JSON.stringify(body)).toString(
            'base64',
          ),
          'content-type': 'application/json',
        })
        .end(JSON.stringify(body));
    }
    const payment = JSON.parse(
      Buffer.from(header, 'base64').toString('utf8'),
    ) as { payload: { authorization: { to: string; value: string } } };
    paid.push(`${path}:${payment.payload.authorization.value}`);
    res
      .writeHead(200, {
        'content-type': 'application/json',
        'payment-response': Buffer.from(
          JSON.stringify({ success: true, transaction: '0xabc' }),
        ).toString('base64'),
      })
      .end(JSON.stringify({ item: path }));
  });
  base = await listen(server);
  return { url: base, paid, close: () => server.close() };
}

async function withDaemon<T>(
  env: TestEnv,
  fn: (bursarUrl: string) => Promise<T>,
): Promise<T> {
  const { server, port } = await env.app.listen(0, '127.0.0.1');
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.close();
  }
}

function parse(result: {
  content: { text: string }[];
  isError?: boolean;
}): Record<string, unknown> {
  return JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
}

const noSleep = () => Promise.resolve();

describe('mcp server', () => {
  it('pays a 402 through bursar and returns the merchant response', async () => {
    const env = makeEnv();
    const s = await shop({ '/data': { amount: usdc(0.1), payTo: MERCHANT } });
    try {
      await withDaemon(env, async (bursarUrl) => {
        const mcp = createMcpServer({
          bursarUrl,
          token: TOKEN,
          sleep: noSleep,
        });
        const r = await mcp.callTool('pay', { url: `${s.url}/data` });
        const out = parse(r);
        assert.equal(r.isError, undefined, JSON.stringify(out));
        assert.equal(out['paid'], true);
        assert.equal(out['usd'], '0.10');
        assert.deepEqual(out['receipt'], {
          success: true,
          transaction: '0xabc',
        });
        assert.deepEqual(s.paid, ['/data:100000']);
        const budget = parse(await mcp.callTool('budget', {}));
        assert.equal(
          (budget['perDay'] as { spentUsd: string }).spentUsd,
          '0.10',
        );
      });
    } finally {
      s.close();
      cleanup(env);
    }
  });

  it('passes through responses that are not 402 without asking bursar', async () => {
    const env = makeEnv();
    const s = await shop({});
    try {
      const mcp = createMcpServer({
        bursarUrl: 'http://127.0.0.1:1',
        token: TOKEN,
        sleep: noSleep,
      });
      const out = parse(await mcp.callTool('pay', { url: `${s.url}/free` }));
      assert.equal(out['paid'], false);
      assert.equal(out['status'], 200);
      assert.equal(out['body'], 'free content');
    } finally {
      s.close();
      cleanup(env);
    }
  });

  it('reports a denial as an error and never pays the merchant', async () => {
    const env = makeEnv();
    const s = await shop({ '/phish': { amount: usdc(0.1), payTo: STRANGER } });
    try {
      await withDaemon(env, async (bursarUrl) => {
        const mcp = createMcpServer({
          bursarUrl,
          token: TOKEN,
          sleep: noSleep,
        });
        const r = await mcp.callTool('pay', { url: `${s.url}/phish` });
        assert.equal(r.isError, true);
        assert.equal(parse(r)['reason'], 'recipient_not_allowed');
        assert.deepEqual(s.paid, []);
      });
    } finally {
      s.close();
      cleanup(env);
    }
  });

  it('returns pending, then completes the same payment once a human approves it', async () => {
    const env = makeEnv({ approval: '0.50' });
    const s = await shop({ '/report': { amount: usdc(0.7), payTo: MERCHANT } });
    try {
      await withDaemon(env, async (bursarUrl) => {
        const mcp = createMcpServer({
          bursarUrl,
          token: TOKEN,
          sleep: noSleep,
          pollMs: 1,
        });
        const first = parse(
          await mcp.callTool('pay', {
            url: `${s.url}/report`,
            wait_seconds: 0,
          }),
        );
        assert.equal(first['status'], 'pending_approval');
        assert.deepEqual(s.paid, []);
        assert.ok(
          env.app.resolveApproval(first['approvalId'] as string, 'approved'),
        );
        const second = parse(
          await mcp.callTool('pay', {
            url: `${s.url}/report`,
            wait_seconds: 0,
          }),
        );
        assert.equal(second['paid'], true, JSON.stringify(second));
        assert.deepEqual(s.paid, ['/report:700000']);
        assert.equal(env.ledger.spendCount(), 1);
      });
    } finally {
      s.close();
      cleanup(env);
    }
  });

  it('rejects a bad url before any network call', async () => {
    const mcp = createMcpServer({
      bursarUrl: 'http://127.0.0.1:1',
      token: TOKEN,
    });
    const r = await mcp.callTool('pay', { url: 'file:///etc/passwd' });
    assert.equal(r.isError, true);
    assert.match(r.content[0]?.text ?? '', /http or https/);
  });

  it('speaks MCP over stdio', async () => {
    const child = spawn(
      process.execPath,
      [new URL('../src/mcp/server.ts', import.meta.url).pathname],
      {
        env: {
          ...process.env,
          BURSAR_TOKEN: TOKEN,
          BURSAR_URL: 'http://127.0.0.1:1',
        },
        stdio: ['pipe', 'pipe', 'inherit'],
      },
    );
    const lines: Record<string, unknown>[] = [];
    let buf = '';
    const got = new Promise<void>((resolve) => {
      child.stdout.on('data', (c: Buffer) => {
        buf += c.toString();
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          lines.push(JSON.parse(buf.slice(0, i)) as Record<string, unknown>);
          buf = buf.slice(i + 1);
          if (lines.length === 2) resolve();
        }
      });
    });
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } })}\n`,
    );
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`,
    );
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`,
    );
    await got;
    child.kill();
    assert.equal(
      (lines[0]?.['result'] as { protocolVersion: string }).protocolVersion,
      '2025-06-18',
    );
    const tools = (
      lines[1]?.['result'] as { tools: { name: string }[] }
    ).tools.map((t) => t.name);
    assert.deepEqual(tools, ['pay', 'budget', 'open_task']);
  });
});
