import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { LineCounter, parseDocument, visit, type Scalar } from 'yaml';
import { SELECTORS } from './protocols/evm.ts';
import { isRecord, parseUint, parseUsd } from './util.ts';

export type AssetRule = {
  address: string;
  decimals: number;
  chains: string[] | null;
  label: string | null;
};

export type RecipientRule = {
  address: string;
  label: string | null;
  maxUsdDay: bigint | null;
  chains: string[] | null;
};

export type AgentRule = { id: string; tokenHash: Uint8Array };

export type Policy = {
  version: 1;
  baseDir: string;
  wallet: { keyfile: string | null; envVar: string };
  agents: AgentRule[];
  limits: {
    perTx: bigint;
    perDay: bigint;
    window: 'calendar_utc' | 'rolling_24h';
    velocity: { maxTx: number; perSeconds: number } | null;
    perRecipientDay: bigint | null;
    walletPerDay: bigint | null;
    perMonth: { usd: bigint; window: 'calendar_utc' | 'rolling_30d' } | null;
    perTask: { maxUsd: bigint; maxTtlSeconds: number; required: boolean };
    approval: {
      threshold: bigint;
      timeoutSeconds: number;
      method: 'cli' | 'passkey';
      userVerification: 'required' | 'preferred';
    } | null;
  };
  allow: {
    chains: string[];
    assets: AssetRule[];
    recipients: RecipientRule[] | 'any';
  };
  requireResourceHash: boolean;
  evm: {
    allowedSelectors: string[];
    simulateBeforeSign: boolean;
    maxNetworkFeeWei: bigint;
  };
  tempo: {
    allowClientPaidFees: boolean;
    maxFeeUsd: bigint;
    gasLimit: bigint;
  };
  rpc: Record<string, string>;
  server: { host: string; port: number; allowRemote: boolean };
  state: { ledgerPath: string; auditPath: string };
  mode: 'enforce' | 'dry_run';
};

export class PolicyError extends Error {
  override name = 'PolicyError';
}

export const DEFAULT_SELECTORS: string[] = [
  SELECTORS.transfer,
  SELECTORS.transferWithAuthorization,
];
export const DEFAULT_PORT = 8402;

type Env = Record<string, string | undefined>;

export function loadPolicy(path: string, env: Env = process.env): Policy {
  const abs = resolve(path);
  let text: string;
  try {
    text = readFileSync(abs, 'utf8');
  } catch (e) {
    throw new PolicyError(`cannot read policy ${abs}: ${(e as Error).message}`);
  }
  return parsePolicy(text, { baseDir: dirname(abs), env });
}

export function parsePolicy(
  text: string,
  opts: { baseDir: string; env: Env },
): Policy {
  const root = substituteEnv(readYaml(text), opts.env, '');
  try {
    return buildPolicy(root, opts.baseDir);
  } catch (e) {
    if (e instanceof PolicyError) throw e;
    throw new PolicyError((e as Error).message);
  }
}

const PLAIN_DECIMAL = /^-?(0|[1-9]\d*)(\.\d+)?$/;

function readYaml(text: string): unknown {
  const lineCounter = new LineCounter();
  const doc = parseDocument(text, {
    keepSourceTokens: true,
    lineCounter,
    uniqueKeys: true,
  });
  const first = doc.errors[0];
  if (first !== undefined)
    throw new PolicyError(`invalid YAML: ${first.message}`);
  visit(doc, {
    Scalar(_key, node: Scalar) {
      if (typeof node.value !== 'number' && typeof node.value !== 'bigint')
        return;
      const token = node.srcToken;
      const source =
        token !== undefined && 'source' in token ? token.source : undefined;
      const line = node.range ? lineCounter.linePos(node.range[0]).line : 0;
      if (source === undefined || !PLAIN_DECIMAL.test(source)) {
        throw new PolicyError(
          `line ${line}: write numbers as plain decimals like 20 or 0.50 (got ${source ?? String(node.value)}); quote the value if it is meant to be text`,
        );
      }
      node.value = source;
    },
  });
  return doc.toJS();
}

function substituteEnv(value: unknown, env: Env, path: string): unknown {
  if (typeof value === 'string') {
    return value.replace(
      /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
      (_m, name: string) => {
        const v = env[name];
        if (v === undefined || v === '')
          throw new PolicyError(
            `${path || 'policy'}: environment variable ${name} is not set`,
          );
        return v;
      },
    );
  }
  if (Array.isArray(value))
    return value.map((v, i) => substituteEnv(v, env, `${path}[${i}]`));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value))
      out[k] = substituteEnv(v, env, path ? `${path}.${k}` : k);
    return out;
  }
  return value;
}

function obj(
  v: unknown,
  path: string,
  allowed: string[],
): Record<string, unknown> {
  if (!isRecord(v)) throw new PolicyError(`${path}: expected a mapping`);
  for (const k of Object.keys(v)) {
    if (!allowed.includes(k))
      throw new PolicyError(`${path}.${k}: unknown key`);
  }
  return v;
}

function optObj(
  v: unknown,
  path: string,
  allowed: string[],
): Record<string, unknown> | null {
  return v === undefined || v === null ? null : obj(v, path, allowed);
}

function str(v: unknown, path: string): string {
  if (typeof v !== 'string' || v.length === 0)
    throw new PolicyError(`${path}: expected a non-empty string`);
  return v;
}

function optStr(v: unknown, path: string): string | null {
  return v === undefined || v === null ? null : str(v, path);
}

function list(v: unknown, path: string): unknown[] {
  if (!Array.isArray(v)) throw new PolicyError(`${path}: expected a list`);
  return v;
}

function posInt(v: unknown, path: string): number {
  if (typeof v === 'string' && /^[1-9]\d*$/.test(v)) v = Number(v);
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v <= 0)
    throw new PolicyError(`${path}: expected a positive integer`);
  return v;
}

function bool(v: unknown, path: string, dflt: boolean): boolean {
  if (v === undefined || v === null) return dflt;
  if (typeof v !== 'boolean')
    throw new PolicyError(`${path}: expected true or false`);
  return v;
}

function chainList(v: unknown, path: string): string[] | null {
  if (v === undefined || v === null) return null;
  return list(v, path).map((c, i) => str(c, `${path}[${i}]`));
}

function expandPath(p: string, baseDir: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return isAbsolute(p) ? p : resolve(baseDir, p);
}

export function normalizeAddress(a: string): string {
  return /^0x[0-9a-fA-F]+$/.test(a) ? a.toLowerCase() : a;
}

function buildPolicy(input: unknown, baseDir: string): Policy {
  const root = obj(input, 'policy', [
    'version',
    'wallet',
    'agents',
    'limits',
    'allow',
    'evm',
    'mode',
    'rpc',
    'server',
    'state',
    'require_resource_hash',
    'tempo',
  ]);
  if (root['version'] !== '1' && root['version'] !== 1)
    throw new PolicyError('version: only version 1 is supported');

  const walletIn = optObj(root['wallet'], 'wallet', ['keyfile', 'env']) ?? {};
  const keyfile = optStr(walletIn['keyfile'], 'wallet.keyfile');
  const wallet = {
    keyfile: keyfile === null ? null : expandPath(keyfile, baseDir),
    envVar: optStr(walletIn['env'], 'wallet.env') ?? 'BURSAR_KEY',
  };

  const agentsIn = list(root['agents'], 'agents');
  if (agentsIn.length === 0)
    throw new PolicyError('agents: at least one agent is required');
  const seenIds = new Set<string>();
  const seenTokens = new Set<string>();
  const agents: AgentRule[] = agentsIn.map((a, i) => {
    const o = obj(a, `agents[${i}]`, ['id', 'token']);
    const id = str(o['id'], `agents[${i}].id`);
    const token = str(o['token'], `agents[${i}].token`);
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(id))
      throw new PolicyError(
        `agents[${i}].id: use 1-64 chars of [A-Za-z0-9_.-]`,
      );
    if (token.length < 24)
      throw new PolicyError(
        `agents[${i}].token: must be at least 24 characters`,
      );
    if (seenIds.has(id))
      throw new PolicyError(`agents[${i}].id: duplicate id ${id}`);
    if (seenTokens.has(token))
      throw new PolicyError(`agents[${i}].token: tokens must be unique`);
    seenIds.add(id);
    seenTokens.add(token);
    return { id, tokenHash: sha256(utf8ToBytes(token)) };
  });

  const lim = obj(root['limits'], 'limits', [
    'per_tx',
    'per_day',
    'velocity',
    'per_recipient_day',
    'wallet_per_day',
    'per_month',
    'per_task',
    'approval_threshold',
  ]);
  const perTx = obj(lim['per_tx'], 'limits.per_tx', ['usd']);
  const perDay = obj(lim['per_day'], 'limits.per_day', ['usd', 'window']);
  const windowIn = perDay['window'] ?? 'calendar_utc';
  if (windowIn !== 'calendar_utc' && windowIn !== 'rolling_24h') {
    throw new PolicyError(
      'limits.per_day.window: expected calendar_utc or rolling_24h',
    );
  }
  const vel = optObj(lim['velocity'], 'limits.velocity', [
    'max_tx',
    'per_seconds',
  ]);
  const prd = optObj(lim['per_recipient_day'], 'limits.per_recipient_day', [
    'usd',
  ]);
  const wpd = optObj(lim['wallet_per_day'], 'limits.wallet_per_day', ['usd']);
  const pm = optObj(lim['per_month'], 'limits.per_month', ['usd', 'window']);
  const pmWindow = pm?.['window'] ?? 'calendar_utc';
  if (pmWindow !== 'calendar_utc' && pmWindow !== 'rolling_30d')
    throw new PolicyError(
      'limits.per_month.window: expected calendar_utc or rolling_30d',
    );
  const pt =
    optObj(lim['per_task'], 'limits.per_task', [
      'max_usd',
      'max_ttl_seconds',
      'required',
    ]) ?? {};
  const appr = optObj(lim['approval_threshold'], 'limits.approval_threshold', [
    'usd',
    'timeout_seconds',
    'method',
    'user_verification',
  ]);
  const method = appr?.['method'] ?? 'cli';
  if (method !== 'cli' && method !== 'passkey')
    throw new PolicyError(
      'limits.approval_threshold.method: expected cli or passkey',
    );
  const userVerification = appr?.['user_verification'] ?? 'required';
  if (userVerification !== 'required' && userVerification !== 'preferred') {
    throw new PolicyError(
      'limits.approval_threshold.user_verification: expected required or preferred',
    );
  }
  const limits: Policy['limits'] = {
    perTx: parseUsd(perTx['usd'], 'limits.per_tx.usd'),
    perDay: parseUsd(perDay['usd'], 'limits.per_day.usd'),
    window: windowIn,
    velocity: vel
      ? {
          maxTx: posInt(vel['max_tx'], 'limits.velocity.max_tx'),
          perSeconds: posInt(vel['per_seconds'], 'limits.velocity.per_seconds'),
        }
      : null,
    perRecipientDay: prd
      ? parseUsd(prd['usd'], 'limits.per_recipient_day.usd')
      : null,
    walletPerDay: wpd
      ? parseUsd(wpd['usd'], 'limits.wallet_per_day.usd')
      : null,
    perMonth: pm
      ? { usd: parseUsd(pm['usd'], 'limits.per_month.usd'), window: pmWindow }
      : null,
    perTask: {
      maxUsd:
        pt['max_usd'] === undefined
          ? parseUsd(perDay['usd'], 'limits.per_day.usd')
          : parseUsd(pt['max_usd'], 'limits.per_task.max_usd'),
      maxTtlSeconds:
        pt['max_ttl_seconds'] === undefined
          ? 86_400
          : posInt(pt['max_ttl_seconds'], 'limits.per_task.max_ttl_seconds'),
      required: bool(pt['required'], 'limits.per_task.required', false),
    },
    approval: appr
      ? {
          threshold: parseUsd(appr['usd'], 'limits.approval_threshold.usd'),
          timeoutSeconds:
            appr['timeout_seconds'] === undefined
              ? 300
              : posInt(
                  appr['timeout_seconds'],
                  'limits.approval_threshold.timeout_seconds',
                ),
          method,
          userVerification,
        }
      : null,
  };

  const allowIn = obj(root['allow'], 'allow', [
    'chains',
    'assets',
    'recipients',
  ]);
  const chains = list(allowIn['chains'], 'allow.chains').map((c, i) =>
    str(c, `allow.chains[${i}]`),
  );
  const assets: AssetRule[] = list(allowIn['assets'], 'allow.assets').map(
    (a, i) => {
      const path = `allow.assets[${i}]`;
      const address =
        typeof a === 'string' ? a : isRecord(a) ? a['address'] : undefined;
      if (typeof address === 'string' && address.toLowerCase() === 'native') {
        throw new PolicyError(
          `${path}: native coins are not USD stablecoins; only USD-pegged tokens can be allowlisted (1 token = 1 USD)`,
        );
      }
      if (typeof a === 'string')
        return {
          address: normalizeAddress(str(a, path)),
          decimals: 6,
          chains: null,
          label: null,
        };
      const o = obj(a, path, ['address', 'decimals', 'chains', 'label']);
      const decIn = o['decimals'] === undefined ? 6 : o['decimals'];
      const decimals =
        typeof decIn === 'string' && /^\d{1,2}$/.test(decIn)
          ? Number(decIn)
          : decIn;
      if (
        typeof decimals !== 'number' ||
        !Number.isInteger(decimals) ||
        decimals < 0 ||
        decimals > 36
      ) {
        throw new PolicyError(`${path}.decimals: expected an integer 0..36`);
      }
      return {
        address: normalizeAddress(str(o['address'], `${path}.address`)),
        decimals,
        chains: chainList(o['chains'], `${path}.chains`),
        label: optStr(o['label'], `${path}.label`),
      };
    },
  );
  let recipients: RecipientRule[] | 'any';
  if (allowIn['recipients'] === 'any') {
    recipients = 'any';
  } else {
    recipients = list(allowIn['recipients'], 'allow.recipients').map((r, i) => {
      const path = `allow.recipients[${i}]`;
      const o = obj(r, path, ['address', 'label', 'max_usd_day', 'chains']);
      return {
        address: normalizeAddress(str(o['address'], `${path}.address`)),
        label: optStr(o['label'], `${path}.label`),
        maxUsdDay:
          o['max_usd_day'] === undefined
            ? null
            : parseUsd(o['max_usd_day'], `${path}.max_usd_day`),
        chains: chainList(o['chains'], `${path}.chains`),
      };
    });
  }

  const evmIn =
    optObj(root['evm'], 'evm', [
      'allowed_selectors',
      'simulate_before_sign',
      'max_network_fee_wei',
    ]) ?? {};
  const selectors =
    evmIn['allowed_selectors'] === undefined
      ? DEFAULT_SELECTORS
      : list(evmIn['allowed_selectors'], 'evm.allowed_selectors').map(
          (s, i) => {
            const v = str(s, `evm.allowed_selectors[${i}]`).toLowerCase();
            if (!/^0x[0-9a-f]{8}$/.test(v))
              throw new PolicyError(
                `evm.allowed_selectors[${i}]: expected 0x + 8 hex chars`,
              );
            return v;
          },
        );
  const maxNetworkFeeWei =
    evmIn['max_network_fee_wei'] === undefined
      ? 10n ** 15n
      : parseUint(evmIn['max_network_fee_wei'], 'evm.max_network_fee_wei');

  const tempoIn =
    optObj(root['tempo'], 'tempo', [
      'allow_client_paid_fees',
      'max_fee_usd',
      'gas_limit',
    ]) ?? {};
  const tempo = {
    allowClientPaidFees: bool(
      tempoIn['allow_client_paid_fees'],
      'tempo.allow_client_paid_fees',
      false,
    ),
    maxFeeUsd:
      tempoIn['max_fee_usd'] === undefined
        ? 10_000n
        : parseUsd(tempoIn['max_fee_usd'], 'tempo.max_fee_usd'),
    gasLimit: BigInt(
      tempoIn['gas_limit'] === undefined
        ? 300_000
        : posInt(tempoIn['gas_limit'], 'tempo.gas_limit'),
    ),
  };

  const rpcIn =
    optObj(
      root['rpc'],
      'rpc',
      Object.keys(isRecord(root['rpc']) ? root['rpc'] : {}),
    ) ?? {};
  const rpc: Record<string, string> = {};
  for (const [k, v] of Object.entries(rpcIn)) rpc[k] = str(v, `rpc.${k}`);

  const serverIn =
    optObj(root['server'], 'server', ['host', 'port', 'allow_remote']) ?? {};
  const server = {
    host: optStr(serverIn['host'], 'server.host') ?? '127.0.0.1',
    port:
      serverIn['port'] === undefined
        ? DEFAULT_PORT
        : posInt(serverIn['port'], 'server.port'),
    allowRemote: bool(serverIn['allow_remote'], 'server.allow_remote', false),
  };

  const stateIn = optObj(root['state'], 'state', ['dir']) ?? {};
  const stateDir = expandPath(
    optStr(stateIn['dir'], 'state.dir') ?? '.',
    baseDir,
  );

  const mode = root['mode'] ?? 'enforce';
  if (mode !== 'enforce' && mode !== 'dry_run')
    throw new PolicyError('mode: expected enforce or dry_run');

  return {
    version: 1,
    baseDir,
    wallet,
    agents,
    limits,
    allow: { chains, assets, recipients },
    requireResourceHash: bool(
      root['require_resource_hash'],
      'require_resource_hash',
      false,
    ),
    evm: {
      allowedSelectors: selectors,
      simulateBeforeSign: bool(
        evmIn['simulate_before_sign'],
        'evm.simulate_before_sign',
        true,
      ),
      maxNetworkFeeWei,
    },
    tempo,
    rpc,
    server,
    state: {
      ledgerPath: join(stateDir, 'bursar.db'),
      auditPath: join(stateDir, 'bursar.audit.jsonl'),
    },
    mode,
  };
}
