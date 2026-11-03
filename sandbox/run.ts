import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { resolveApproval } from '../src/approval/resolve.ts';
import { AuditLog } from '../src/audit.ts';
import { Ledger } from '../src/ledger/store.ts';
import { startMerchant } from './merchant.ts';

const root = new URL('..', import.meta.url).pathname;
const cli = join(root, 'src', 'index.ts');
const policyPath = join(root, 'sandbox', 'policy.yaml');
const keep = process.argv.includes('--keep');
const state = mkdtempSync(join(tmpdir(), 'bursar-sandbox-'));

const merchant = await startMerchant();
const env: Record<string, string | undefined> = {
  ...process.env,
  BURSAR_KEY: `evm: 0x${bytesToHex(secp256k1.utils.randomSecretKey())}; solana: ${bytesToHex(randomBytes(32))}`,
  BURSAR_TOKEN_NANOCODE: bytesToHex(randomBytes(24)),
  BURSAR_TOKEN_RESEARCHER: bytesToHex(randomBytes(24)),
  SANDBOX_RPC: `${merchant.url}/rpc`,
  SANDBOX_STATE: state,
  SANDBOX_APPROVAL: 'cli',
};

console.log(`merchant + RPC stub: ${merchant.url}`);
console.log(`state dir:           ${state}`);

const daemon = spawn(
  process.execPath,
  [cli, 'serve', '--policy', policyPath, '--port', '0'],
  { env, stdio: ['ignore', 'pipe', 'inherit'] },
);
const bursarUrl = await new Promise<string>((resolve, reject) => {
  let out = '';
  daemon.stdout.on('data', (c: Buffer) => {
    out += c.toString();
    const m = /listening on (http:\/\/[\d.]+:\d+)/.exec(out);
    if (m?.[1]) {
      process.stdout.write(out.replace(/^/gm, 'bursar | '));
      resolve(m[1]);
    }
  });
  daemon.once('exit', (code) =>
    reject(new Error(`bursar exited early (${code})`)),
  );
});

const ledger = new Ledger(join(state, 'bursar.db'));
const audit = new AuditLog(join(state, 'bursar.audit.jsonl'), (fn) =>
  ledger.transaction(fn),
);
const human = setInterval(() => {
  for (const a of ledger.listApprovals('pending')) {
    const amount = (JSON.parse(a.intentJson) as { amount: string }).amount;
    const decision = amount === '700000' ? 'approved' : 'denied';
    const outcome = resolveApproval(ledger, audit, a.id, decision, {
      via: 'cli',
      method: 'cli',
    });
    console.log(
      `human | ${decision} ${a.id} ($${Number(amount) / 1e6}) -> ${outcome}`,
    );
  }
}, 500);

console.log('');
const agent = spawn('python3', ['-I', join(root, 'sandbox', 'agent.py')], {
  env: {
    ...env,
    MERCHANT_URL: merchant.url,
    BURSAR_URL: bursarUrl,
    TOKEN_NANOCODE: env['BURSAR_TOKEN_NANOCODE'],
    TOKEN_RESEARCHER: env['BURSAR_TOKEN_RESEARCHER'],
  },
  stdio: 'inherit',
});
const code = await new Promise<number>((resolve) =>
  agent.once('exit', (c) => resolve(c ?? 1)),
);
clearInterval(human);

console.log('\n== merchant side: payments that actually verified ==');
const byPath = new Map<string, { n: number; usd: number }>();
for (const r of merchant.receipts) {
  const e = byPath.get(r.path) ?? { n: 0, usd: 0 };
  e.n++;
  e.usd += Number(r.amount) / 1e6;
  byPath.set(r.path, e);
}
for (const [p, e] of byPath)
  console.log(
    `  ${p.padEnd(22)} ${String(e.n).padStart(3)} x  $${e.usd.toFixed(2)}`,
  );
console.log(
  `  total received: $${(merchant.receipts.reduce((s, r) => s + Number(r.amount), 0) / 1e6).toFixed(2)} in ${merchant.receipts.length} payments\n`,
);

const report = spawnSync(
  process.execPath,
  [cli, 'report', '--policy', policyPath, '--period', 'all'],
  { env, encoding: 'utf8' },
);
process.stdout.write(report.stdout);
process.stderr.write(report.stderr);

ledger.close();
daemon.kill('SIGINT');
merchant.close();
if (!keep) rmSync(state, { recursive: true, force: true });
else console.log(`\nstate kept in ${state}`);
process.exit(code);
