import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getAddress } from 'micro-sol-signer';
import { createApp, type App } from '../src/api/server.ts';
import { AuditLog } from '../src/audit.ts';
import { parsePolicy, type Policy } from '../src/config.ts';
import { Ledger } from '../src/ledger/store.ts';
import type { AdapterContext } from '../src/protocols/common.ts';
import { openSigner, type Signer } from '../src/signer/index.ts';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  approvalChallenge,
  parseRegistrationBody,
  verifyRegistration,
  type ApprovalDecision,
} from '../src/approval/passkey.ts';
import { http, softAuthenticator } from './fixtures/authenticator.ts';

export const EVM_KEY = `0x${'11'.repeat(32)}`;
export const SOL_KEY = '22'.repeat(32);
export const TOKEN = 'test-token-nanocode-0123456789abcdef';
export const TOKEN_OTHER = 'test-token-otheragent-0123456789abcd';
export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const USDC_SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const PATHUSD = '0x20c0000000000000000000000000000000000000';
export const MERCHANT = '0x1111111111111111111111111111111111111111';
export const MERCHANT_B = '0x2222222222222222222222222222222222222222';
export const BASE_ONLY = '0x3333333333333333333333333333333333333333';
export const STRANGER = '0x9999999999999999999999999999999999999999';
export const SOL_MERCHANT = getAddress(new Uint8Array(32).fill(5));
export const SOL_FACILITATOR = getAddress(new Uint8Array(32).fill(6));
export const T0 = Date.UTC(2026, 10, 3, 12, 0, 0);

export type PolicyOptions = {
  perTx?: string;
  perDay?: string;
  window?: 'calendar_utc' | 'rolling_24h';
  perRecipient?: string;
  approval?: string | null;
  approvalTimeout?: number;
  velocity?: { maxTx: number; perSeconds: number } | null;
  mode?: 'enforce' | 'dry_run';
  requireResourceHash?: boolean;
  merchantMaxDay?: string | null;
  tempo?: {
    allowClientPaidFees?: boolean;
    maxFeeUsd?: string;
    gasLimit?: number;
  };
  approvalMethod?: 'cli' | 'passkey';
  userVerification?: 'required' | 'preferred';
  walletPerDay?: string;
  perMonth?: { usd: string; window?: 'calendar_utc' | 'rolling_30d' };
  perTask?: { maxUsd?: string; maxTtlSeconds?: number; required?: boolean };
  rpc?: Record<string, string>;
  unknownRecipients?: 'deny' | 'ask';
};

export function policyYaml(o: PolicyOptions = {}): string {
  const lines = [
    'version: 1',
    'wallet:',
    '  keyfile: ./key',
    '  env: BURSAR_TEST_KEY_UNSET',
    'agents:',
    '  - id: nanocode',
    '    token: ${TEST_TOKEN}',
    '  - id: other',
    `    token: ${TOKEN_OTHER}`,
    'limits:',
    `  per_tx: { usd: ${o.perTx ?? '1.00'} }`,
    `  per_day: { usd: ${o.perDay ?? '20.00'}, window: ${o.window ?? 'calendar_utc'} }`,
    `  per_recipient_day: { usd: ${o.perRecipient ?? '5.00'} }`,
  ];
  const vel =
    o.velocity === undefined ? { maxTx: 100, perSeconds: 60 } : o.velocity;
  if (vel !== null)
    lines.push(
      `  velocity: { max_tx: ${vel.maxTx}, per_seconds: ${vel.perSeconds} }`,
    );
  const appr = o.approval === undefined ? '5.00' : o.approval;
  if (appr !== null) {
    const extra = `${o.approvalMethod ? `, method: ${o.approvalMethod}` : ''}${o.userVerification ? `, user_verification: ${o.userVerification}` : ''}`;
    lines.push(
      `  approval_threshold: { usd: ${appr}, timeout_seconds: ${o.approvalTimeout ?? 60}${extra} }`,
    );
  }
  if (o.walletPerDay !== undefined)
    lines.push(`  wallet_per_day: { usd: ${o.walletPerDay} }`);
  if (o.perMonth !== undefined)
    lines.push(
      `  per_month: { usd: ${o.perMonth.usd}${o.perMonth.window ? `, window: ${o.perMonth.window}` : ''} }`,
    );
  if (o.perTask !== undefined) {
    const parts = [
      o.perTask.maxUsd === undefined ? null : `max_usd: ${o.perTask.maxUsd}`,
      o.perTask.maxTtlSeconds === undefined
        ? null
        : `max_ttl_seconds: ${o.perTask.maxTtlSeconds}`,
      o.perTask.required === undefined
        ? null
        : `required: ${o.perTask.required}`,
    ].filter((p) => p !== null);
    lines.push(`  per_task: { ${parts.join(', ')} }`);
  }
  lines.push(
    'allow:',
    "  chains: ['eip155:8453', 'eip155:10', 'solana:mainnet', 'eip155:4217']",
    '  assets:',
    `    - { address: '${USDC_BASE}', chains: ['eip155:8453'] }`,
    `    - { address: '${USDC_SOL}', decimals: 6, chains: ['solana:mainnet'] }`,
    `    - { address: '${PATHUSD}', decimals: 6, chains: ['eip155:4217'] }`,
    '  recipients:',
    `    - { address: '${MERCHANT}', label: merchant${o.merchantMaxDay ? `, max_usd_day: ${o.merchantMaxDay}` : ''} }`,
    `    - { address: '${MERCHANT_B}', label: merchant-b }`,
    `    - { address: '${BASE_ONLY}', label: base-only, chains: ['eip155:8453'] }`,
    `    - { address: '${SOL_MERCHANT}', label: sol-merchant }`,
    ...(o.unknownRecipients === undefined
      ? []
      : [`  unknown_recipients: ${o.unknownRecipients}`]),
    `require_resource_hash: ${o.requireResourceHash ? 'true' : 'false'}`,
    'evm:',
    "  allowed_selectors: ['0xa9059cbb', '0xe3ee160e']",
    '  simulate_before_sign: false',
    `mode: ${o.mode ?? 'enforce'}`,
  );
  if (o.tempo !== undefined) {
    lines.push(
      'tempo:',
      `  allow_client_paid_fees: ${o.tempo.allowClientPaidFees ? 'true' : 'false'}`,
    );
    if (o.tempo.maxFeeUsd !== undefined)
      lines.push(`  max_fee_usd: ${o.tempo.maxFeeUsd}`);
    if (o.tempo.gasLimit !== undefined)
      lines.push(`  gas_limit: ${o.tempo.gasLimit}`);
  }
  if (o.rpc !== undefined) {
    lines.push('rpc:');
    for (const [k, v] of Object.entries(o.rpc)) lines.push(`  '${k}': ${v}`);
  }
  return `${lines.join('\n')}\n`;
}

export type Clock = {
  now: () => number;
  set: (t: number) => void;
  advance: (ms: number) => void;
};

export function makeClock(start = T0): Clock {
  let t = start;
  return {
    now: () => t,
    set: (v) => {
      t = v;
    },
    advance: (ms) => {
      t += ms;
    },
  };
}

export type TestEnv = {
  dir: string;
  policy: Policy;
  app: App;
  signer: Signer;
  ledger: Ledger;
  audit: AuditLog;
  clock: Clock;
  close: () => void;
};

export function makeDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'bursar-test-'));
  writeFileSync(join(dir, 'key'), `evm: ${EVM_KEY}\nsolana: ${SOL_KEY}\n`, {
    mode: 0o600,
  });
  return dir;
}

export function openEnv(
  dir: string,
  opts: PolicyOptions = {},
  clock: Clock = makeClock(),
): TestEnv {
  const policy = parsePolicy(policyYaml(opts), {
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
  const app = createApp({ policy, signer, ledger, audit, now: clock.now });
  return {
    dir,
    policy,
    app,
    signer,
    ledger,
    audit,
    clock,
    close: () => {
      signer.close();
      ledger.close();
    },
  };
}

export function makeEnv(opts: PolicyOptions = {}, clock?: Clock): TestEnv {
  return openEnv(makeDir(), opts, clock);
}

export function cleanup(env: TestEnv): void {
  env.close();
  rmSync(env.dir, { recursive: true, force: true });
}

export const usdc = (usd: number): string =>
  String(Math.round(usd * 1_000_000));

export type X402Options = {
  amount?: string;
  payTo?: string;
  network?: string;
  asset?: string;
  version?: 1 | 2;
  extra?: Record<string, unknown>;
  resourceUrl?: string;
  key?: string;
  agentFields?: Record<string, unknown>;
  resourceHash?: string;
  resource?: { method: string; url: string; bodySha256?: string };
};

export function x402Body(o: X402Options = {}): Record<string, unknown> {
  const version = o.version ?? 2;
  const resourceUrl = o.resourceUrl ?? 'https://api.example.com/v1/data';
  const network = o.network ?? 'eip155:8453';
  const isSol = network.startsWith('solana');
  const extra =
    o.extra ??
    (isSol
      ? { feePayer: SOL_FACILITATOR }
      : { name: 'USD Coin', version: '2' });
  const req: Record<string, unknown> = {
    scheme: 'exact',
    network,
    asset: o.asset ?? (isSol ? USDC_SOL : USDC_BASE),
    payTo: o.payTo ?? (isSol ? SOL_MERCHANT : MERCHANT),
    maxTimeoutSeconds: 60,
    extra,
  };
  if (version === 2) req['amount'] = o.amount ?? usdc(0.1);
  else {
    req['maxAmountRequired'] = o.amount ?? usdc(0.1);
    req['resource'] = resourceUrl;
    req['description'] = 'test resource';
    req['mimeType'] = 'application/json';
  }
  const paymentRequired: Record<string, unknown> = {
    x402Version: version,
    accepts: [req],
  };
  if (version === 2)
    paymentRequired['resource'] = {
      url: resourceUrl,
      description: 'test resource',
      mimeType: 'application/json',
    };
  const payload: Record<string, unknown> = {
    paymentRequired,
    ...(o.agentFields ?? {}),
  };
  if (isSol)
    payload['solana'] = {
      recentBlockhash: getAddress(new Uint8Array(32).fill(9)),
    };
  const body: Record<string, unknown> = {
    protocol: 'x402',
    payload,
    idempotencyKey: o.key ?? 'k-1',
  };
  if (o.resourceHash !== undefined) body['resourceHash'] = o.resourceHash;
  if (o.resource !== undefined) body['resource'] = o.resource;
  return body;
}

export function erc20TransferData(
  to: string,
  amount: bigint,
  selector = 'a9059cbb',
): string {
  return `0x${selector}${to.slice(2).toLowerCase().padStart(64, '0')}${amount.toString(16).padStart(64, '0')}`;
}

export function evmBody(
  data: string,
  o: { to?: string; key?: string; chainId?: number; value?: string } = {},
): Record<string, unknown> {
  return {
    protocol: 'evm',
    idempotencyKey: o.key ?? 'evm-1',
    payload: {
      chainId: o.chainId ?? 8453,
      to: o.to ?? USDC_BASE,
      data,
      value: o.value ?? '0',
      nonce: 0,
      gasLimit: 100000,
      maxFeePerGas: '1000000000',
      maxPriorityFeePerGas: '1000000',
    },
  };
}

export type Res = { status: number; body: Record<string, unknown> };

export async function sign(
  env: TestEnv,
  body: unknown,
  agent = 'nanocode',
): Promise<Res> {
  const r = await env.app.sign(agent, body);
  return { status: r.status, body: r.body as Record<string, unknown> };
}

export function auditEvents(
  env: TestEnv,
  agent: string | null = null,
): Record<string, unknown>[] {
  return env.audit
    .readSince(0, agent)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

export type PasskeyEnv = {
  env: TestEnv;
  port: number;
  origin: string;
  auth: ReturnType<typeof softAuthenticator>;
  close: () => void;
};

// A listening daemon with one registered passkey named "laptop".
export async function startWithPasskey(
  opts: PolicyOptions,
): Promise<PasskeyEnv> {
  const env = makeEnv(opts);
  const { server, port } = await env.app.listen(0, '127.0.0.1');
  const origin = `http://localhost:${port}`;
  const auth = softAuthenticator();
  const challenge = randomBytes(32);
  const cred = verifyRegistration(
    parseRegistrationBody(auth.register({ challenge, origin })),
    { challenge, origin, userVerification: 'required' },
  );
  env.ledger.addPasskey({ ...cred, name: 'laptop' }, env.clock.now());
  return {
    env,
    port,
    origin,
    auth,
    close: () => {
      server.close();
      cleanup(env);
    },
  };
}

// Sign the approval challenge for `decision` with the passkey and POST it.
export function decideWithPasskey(
  s: PasskeyEnv,
  id: string,
  decision: ApprovalDecision,
): ReturnType<typeof http> {
  const row = s.env.ledger.getApproval(id);
  if (row === null) throw new Error(`no approval ${id}`);
  const body = s.auth.assert({
    challenge: approvalChallenge(id, row.intentJson, decision),
    origin: s.origin,
    decision,
  });
  return http(s.port, `/approve/${id}`, { method: 'POST', body });
}

export function adapterCtx(over: Partial<AdapterContext> = {}): AdapterContext {
  return {
    agentId: 'nanocode',
    idempotencyKey: 'k',
    resourceHash: null,
    resource: null,
    now: T0,
    random: (n) => new Uint8Array(n).fill(7),
    decimalsFor: () => 6,
    isRouteAllowed: () => true,
    evm: {
      allowedSelectors: ['0xa9059cbb', '0xe3ee160e'],
      simulateBeforeSign: false,
      maxNetworkFeeWei: 10n ** 15n,
    },
    tempo: {
      allowClientPaidFees: false,
      maxFeeUsd: 10_000n,
      gasLimit: 300_000n,
    },
    ...over,
  };
}
