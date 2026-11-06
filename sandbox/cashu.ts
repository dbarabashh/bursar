// Cashu sandbox: a real mint (Nutshell in Docker, FakeWallet lightning that
// pays its own invoices), a NUT-24 merchant, the real bursar daemon and CLI,
// and an agent paying through the MCP `pay` tool. Nothing leaves the machine.
//
//   npm run sandbox:cashu            # start the mint, run, stop the mint
//   npm run sandbox:cashu -- --keep  # keep the state dir and the mint running
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createMintClient } from '../src/cashu/mint.ts';
import { createMcpServer } from '../src/mcp/server.ts';
import { startCashuMerchant } from './cashu-merchant.ts';

const IMAGE = 'cashubtc/nutshell:0.22.1';
const CONTAINER = 'bursar-sandbox-mint';
const MINT = 'http://127.0.0.1:3338';
const root = new URL('..', import.meta.url).pathname;
const cli = join(root, 'src', 'index.ts');
const keep = process.argv.includes('--keep');

function sh(cmd: string, args: string[]): { ok: boolean; out: string } {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return {
    ok: r.status === 0,
    out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim(),
  };
}

async function mintUp(): Promise<boolean> {
  try {
    return (
      await fetch(`${MINT}/v1/info`, { signal: AbortSignal.timeout(1000) })
    ).ok;
  } catch {
    return false;
  }
}

let startedMint = false;
if (!(await mintUp())) {
  if (!sh('docker', ['version']).ok) {
    console.error(
      'Docker is needed to run the sandbox mint (or run a mint on 127.0.0.1:3338 yourself).',
    );
    process.exit(1);
  }
  sh('docker', ['rm', '-f', CONTAINER]);
  const r = sh('docker', [
    'run',
    '-d',
    '--name',
    CONTAINER,
    '-p',
    '127.0.0.1:3338:3338',
    '-e',
    'MINT_BACKEND_BOLT11_SAT=FakeWallet',
    '-e',
    'MINT_LISTEN_HOST=0.0.0.0',
    '-e',
    'MINT_LISTEN_PORT=3338',
    '-e',
    'MINT_INPUT_FEE_PPK=100',
    '-e',
    'FAKEWALLET_DELAY_INCOMING_PAYMENT=1',
    '-e',
    'FAKEWALLET_DELAY_OUTGOING_PAYMENT=0',
    '-e',
    'MINT_PRIVATE_KEY=bursar-sandbox-not-a-secret',
    IMAGE,
    'poetry',
    'run',
    'mint',
  ]);
  if (!r.ok) {
    console.error(`could not start the mint: ${r.out}`);
    process.exit(1);
  }
  startedMint = true;
  for (let i = 0; i < 60 && !(await mintUp()); i++)
    await new Promise((res) => setTimeout(res, 500));
  if (!(await mintUp())) {
    console.error('the mint did not come up');
    process.exit(1);
  }
}
console.log(
  `mint:     ${MINT} (Nutshell, FakeWallet lightning, 100 ppk input fee)`,
);

const merchant = await startCashuMerchant(MINT);
console.log(
  `merchant: ${merchant.url} (P2PK key ${merchant.pubkey.slice(0, 16)}…)`,
);

const state = mkdtempSync(join(tmpdir(), 'bursar-cashu-sandbox-'));
const policyPath = join(state, 'policy.yaml');
writeFileSync(
  policyPath,
  `version: 1
wallet:
  env: BURSAR_KEY
agents:
  - id: nanocode
    token: \${BURSAR_TOKEN_NANOCODE}
limits:
  per_tx: { usd: 1.00, sat: 500 }
  per_day: { usd: 5.00, sat: 1000 }
  per_recipient_day: { usd: 4.00, sat: 400 }
  approval_threshold: { usd: 0.50, sat: 400, timeout_seconds: 60, method: cli }
  velocity: { max_tx: 60, per_seconds: 60 }
allow:
  chains: ['cashu:sat']
  assets: []
  recipients:
    - { address: '${merchant.pubkey}', label: sandbox merchant key }
    - { address: '${merchant.url}', label: sandbox merchant origin }
cashu:
  mints:
    - { url: '${MINT}', units: [sat], label: sandbox nutshell, max_balance: 5000 }
  max_fee: { sat: 5 }
  # The sandbox merchant listens on plain http on loopback.
  allow_http: true
state:
  dir: ${state}
`,
);

const env: Record<string, string | undefined> = {
  ...process.env,
  BURSAR_KEY: `evm: 0x${bytesToHex(secp256k1.utils.randomSecretKey())}`,
  BURSAR_TOKEN_NANOCODE: bytesToHex(randomBytes(24)),
};

function bursar(args: string[]): string {
  const r = spawnSync(
    process.execPath,
    [cli, ...args, '--policy', policyPath],
    { env, encoding: 'utf8' },
  );
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`.trim();
  if (r.status !== 0)
    throw new Error(`bursar ${args.join(' ')} failed:\n${out}`);
  return out;
}

const step = (s: string) => console.log(`\n== ${s} ==`);

step(
  'operator funds the wallet: bursar cashu fund (FakeWallet pays the invoice)',
);
console.log(
  bursar(['cashu', 'fund', '--mint', MINT, '--amount', '1000']).replace(
    /lnbc\S{40,}/,
    (m) => `${m.slice(0, 40)}…`,
  ),
);

const daemon = spawn(
  process.execPath,
  [cli, 'serve', '--policy', policyPath, '--port', '0'],
  {
    env,
    stdio: ['ignore', 'pipe', 'inherit'],
  },
);
const bursarUrl = await new Promise<string>((resolve, reject) => {
  let out = '';
  daemon.stdout.on('data', (c: Buffer) => {
    out += c.toString();
    const m = /listening on (http:\/\/[\d.]+:\d+)/.exec(out);
    if (m?.[1]) resolve(m[1]);
  });
  daemon.once('exit', (code) =>
    reject(new Error(`bursar exited early (${code})`)),
  );
});
console.log(`\nbursar:   ${bursarUrl}`);

const mcp = createMcpServer({
  bursarUrl,
  token: env['BURSAR_TOKEN_NANOCODE'] as string,
});
async function pay(path: string): Promise<Record<string, unknown>> {
  const r = await mcp.callTool('pay', { url: `${merchant.url}${path}` });
  const text = r.content[0]?.text ?? '';
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { error: text };
  }
}
const show = (label: string, r: Record<string, unknown>) => {
  const { body, ...rest } = r;
  console.log(`agent | ${label}: ${JSON.stringify(rest)}`);
  if (typeof body === 'string' && body !== '')
    console.log(`        body: ${body.slice(0, 120)}`);
};

let failed = false;
const expect = (cond: boolean, what: string) => {
  if (!cond) {
    failed = true;
    console.log(`  ✗ ${what}`);
  } else console.log(`  ✓ ${what}`);
};

step(
  'agent pays a locked (P2PK) request: bursar returns the X-Cashu token, the MCP tool retries',
);
const locked = await pay('/locked');
show('/locked', locked);
expect(
  locked['paid'] === true && locked['sat'] !== undefined,
  'paid 21 sat locked to the merchant key',
);

step('agent pays an unlocked request: bursar delivers the token itself');
const open = await pay('/open');
show('/open', open);
expect(open['paid'] === true, 'paid 34 sat to the allowlisted origin');

step('a payment above per_tx (500 sat)');
const big = await pay('/expensive');
show('/expensive', big);
expect(big['reason'] === 'per_tx_limit', 'denied by per_tx_limit');

step('a merchant that never redeems the token: bursar takes the ecash back');
const broken = await pay('/broken');
show('/broken', broken);
expect(broken['reason'] === 'merchant_rejected', 'refused and reclaimed');

step('budget seen by the agent (sat block)');
const budget = (await mcp.callTool('budget', {})).content[0]?.text ?? '{}';
const sat = (JSON.parse(budget) as { sat?: Record<string, unknown> }).sat;
console.log(JSON.stringify(sat, null, 2));
expect(
  (sat?.['perDay'] as { spent?: string } | undefined)?.spent !== undefined,
  'sat limits reported',
);

step('wallet: bursar cashu balance');
console.log(bursar(['cashu', 'balance']));

step('operator withdraws over lightning: bursar cashu withdraw');
// FakeWallet pays any invoice the mint itself issued; take one from a quote.
const invoice = (await createMintClient(MINT).mintQuote(200, 'sat', null))
  .request;
console.log(bursar(['cashu', 'withdraw', invoice, '--mint', MINT]));
console.log(bursar(['cashu', 'recover']));
console.log(bursar(['cashu', 'balance']));

step('merchant side: payments it actually redeemed at the mint');
for (const r of merchant.receipts)
  console.log(
    `  ${r.path}  ${r.amount} sat  ${r.locked ? 'P2PK' : 'unlocked'}`,
  );
expect(
  merchant.receipts.length === 2,
  'exactly the two allowed payments were redeemed',
);

daemon.kill('SIGTERM');
merchant.close();
if (startedMint && !keep) sh('docker', ['rm', '-f', CONTAINER]);
if (!keep) rmSync(state, { recursive: true, force: true });
else
  console.log(
    `\nstate kept in ${state}${startedMint ? `; mint container ${CONTAINER} still running` : ''}`,
  );
console.log(failed ? '\nsandbox: FAILED' : '\nsandbox: all checks passed');
process.exit(failed ? 1 : 0);
