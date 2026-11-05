#!/usr/bin/env node
// Interactive installer: asks a few questions, writes the policy, installs the
// daemon under its own macOS user, registers a passkey and connects Claude Code.
// Run it from the repo as your normal user: npm run setup
import { spawn, spawnSync, type SpawnOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { emitKeypressEvents } from 'node:readline';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { DEFAULT_PORT, parsePolicy } from './config.ts';
import { rpcCall } from './protocols/common.ts';
import { formatUsd, parseUsd } from './util.ts';

// Paths the installer (scripts/install-macos.sh) uses.
const PREFIX = '/opt/bursar';
const STATE = '/var/db/bursar';
const PLIST = '/Library/LaunchDaemons/dev.bursar.daemon.plist';
const BURSAR_BIN = '/usr/local/bin/bursar';
const BURSAR_URL = `http://127.0.0.1:${DEFAULT_PORT}`;
// The installer replaces this with a fresh token when it writes a default policy.
const TOKEN_PLACEHOLDER = '__AGENT_TOKEN_SET_BY_INSTALLER__';

export type Network = 'testnet' | 'mainnet';

export const NETWORKS: Record<
  Network,
  {
    chain: string;
    usdc: string;
    label: string;
    rpc: string;
    explorer: string;
  }
> = {
  testnet: {
    chain: 'eip155:84532',
    usdc: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    label: 'USDC on Base Sepolia',
    rpc: 'https://sepolia.base.org',
    explorer: 'https://sepolia.basescan.org',
  },
  mainnet: {
    chain: 'eip155:8453',
    usdc: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    label: 'USDC on Base',
    rpc: 'https://mainnet.base.org',
    explorer: 'https://basescan.org',
  },
};

export type Limits = {
  perTx: string;
  perDay: string;
  perMonth: string;
  threshold: string;
  maxTxPerMinute: number;
};

export const PRESETS: Record<'careful' | 'normal', Limits> = {
  careful: {
    perTx: '0.10',
    perDay: '1.00',
    perMonth: '5.00',
    threshold: '0.05',
    maxTxPerMinute: 10,
  },
  normal: {
    perTx: '1.00',
    perDay: '10.00',
    perMonth: '50.00',
    threshold: '0.50',
    maxTxPerMinute: 30,
  },
};

export type Answers = {
  network: Network;
  limits: Limits;
  connectClaude: boolean;
};

export function checkUsd(v: string, what: string): string {
  try {
    return formatUsd(parseUsd(v.trim().replace(/^\$/, ''), what));
  } catch {
    throw new Error(`${what}: enter an amount like 0.10 or 5`);
  }
}

export function limitWarnings(l: Limits): string[] {
  const tx = parseUsd(l.perTx, 'per payment');
  const day = parseUsd(l.perDay, 'per day');
  const month = parseUsd(l.perMonth, 'per month');
  const out: string[] = [];
  if (tx === 0n || day === 0n || month === 0n)
    out.push('a limit of $0 blocks every payment');
  if (tx > day) out.push('one payment is capped by the daily limit anyway');
  if (day > month) out.push('the daily limit is capped by the monthly one');
  if (parseUsd(l.threshold, 'touch id') >= tx)
    out.push(
      'Touch ID is above the per-payment limit, so it is only asked for new services',
    );
  return out;
}

export function buildPolicyYaml(
  a: Pick<Answers, 'network' | 'limits'>,
  token: string,
  stateDir = STATE,
): string {
  const n = NETWORKS[a.network];
  const l = a.limits;
  return `# Written by bursar setup on ${new Date().toISOString().slice(0, 10)}.
# Change it with: sudo nano ${stateDir}/policy.yaml
# then: sudo launchctl kickstart -k system/dev.bursar.daemon
# Or run npm run setup again.
version: 1

wallet:
  keyfile: ${stateDir}/key

agents:
  - id: claude-code
    token: '${token}'

limits:
  per_tx: { usd: ${l.perTx} }
  per_day: { usd: ${l.perDay}, window: calendar_utc }
  per_recipient_day: { usd: ${l.perDay} }
  velocity: { max_tx: ${l.maxTxPerMinute}, per_seconds: 60 }
  wallet_per_day: { usd: ${l.perDay} }
  per_month: { usd: ${l.perMonth} }
  per_task: { max_usd: ${l.perDay}, max_ttl_seconds: 3600 }
  approval_threshold:
    { usd: ${l.threshold}, timeout_seconds: 600, method: passkey, user_verification: required }

allow:
  chains: ['${n.chain}']
  assets:
    - { address: '${n.usdc}', chains: ['${n.chain}'], label: ${n.label} }
  # Services are added from the passkey page the first time an agent pays them.
  recipients: []
  unknown_recipients: ask

state:
  dir: ${stateDir}

mode: enforce
`;
}

export function parseEvmAddress(out: string): string | null {
  const m = /^evm:\s+(0x[0-9a-fA-F]{40})\s*$/m.exec(out);
  return m?.[1] ?? null;
}

export function balanceOfCall(owner: string): string {
  return `0x70a08231${owner.slice(2).toLowerCase().padStart(64, '0')}`;
}

async function usdcBalance(
  network: Network,
  owner: string,
): Promise<bigint | null> {
  const n = NETWORKS[network];
  try {
    const body = (await rpcCall(n.rpc, 'eth_call', [
      { to: n.usdc, data: balanceOfCall(owner) },
      'latest',
    ])) as { result?: string };
    return typeof body.result === 'string' && /^0x[0-9a-f]*$/i.test(body.result)
      ? BigInt(body.result === '0x' ? 0 : body.result)
      : null;
  } catch {
    return null;
  }
}

// ---------- terminal helpers ----------

const tty = process.stdin.isTTY && process.stdout.isTTY;
const paint = (code: number) => (s: string) =>
  tty ? `\x1b[${code}m${s}\x1b[0m` : s;
const c = {
  bold: paint(1),
  dim: paint(2),
  green: paint(32),
  yellow: paint(33),
  red: paint(31),
};
const say = (s = '') => process.stdout.write(`${s}\n`);
const step = (n: number, total: number, s: string) =>
  say(`\n${c.bold(`[${n}/${total}] ${s}`)}`);

async function ask(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(`  ${prompt} `)).trim();
  } finally {
    rl.close();
  }
}

async function input(question: string, def: string): Promise<string> {
  return (await ask(`${question} ${c.dim(`(${def})`)}`)) || def;
}

async function confirm(question: string, def = true): Promise<boolean> {
  const a = (
    await ask(`${question} ${c.dim(def ? '[Y/n]' : '[y/N]')}`)
  ).toLowerCase();
  return a === '' ? def : a.startsWith('y');
}

type Choice<T> = { value: T; label: string; hint?: string };

async function select<T>(question: string, choices: Choice<T>[]): Promise<T> {
  const first = choices[0];
  if (first === undefined) throw new Error('select needs choices');
  if (!tty) {
    say(`  ${question}`);
    choices.forEach((ch, i) => say(`    ${i + 1}. ${ch.label}`));
    const a = await input('number', '1');
    return (choices[Number(a) - 1] ?? first).value;
  }
  say(`  ${question} ${c.dim('(↑/↓, Enter)')}`);
  let i = 0;
  const draw = (again: boolean) => {
    if (again) process.stdout.write(`\x1b[${choices.length}A`);
    for (const [k, ch] of choices.entries()) {
      const line =
        k === i
          ? `${c.green('●')} ${c.bold(ch.label)}`
          : `${c.dim('○')} ${ch.label}`;
      process.stdout.write(
        `\x1b[2K    ${line}${ch.hint ? `  ${c.dim(ch.hint)}` : ''}\n`,
      );
    }
  };
  draw(false);
  emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolveChoice) => {
    const onKey = (_s: string, key: { name?: string; ctrl?: boolean }) => {
      if (key.ctrl && key.name === 'c') {
        process.stdin.setRawMode(false);
        say();
        process.exit(130);
      }
      if (key.name === 'up' || key.name === 'k')
        i = (i - 1 + choices.length) % choices.length;
      else if (key.name === 'down' || key.name === 'j')
        i = (i + 1) % choices.length;
      else if (key.name === 'return') {
        process.stdin.off('keypress', onKey);
        process.stdin.setRawMode(false);
        process.stdin.pause();
        resolveChoice((choices[i] ?? first).value);
        return;
      } else return;
      draw(true);
    };
    process.stdin.on('keypress', onKey);
  });
}

// ---------- commands ----------

type Runner = {
  dryRun: boolean;
  secrets: string[];
};

// In a dry run, print the command (secrets masked) and report that it was skipped.
function dry(r: Runner, cmd: string, args: string[]): boolean {
  if (!r.dryRun) return false;
  let s = [cmd, ...args].join(' ');
  for (const secret of r.secrets) s = s.replaceAll(secret, '•••');
  say(c.dim(`  $ ${s}`));
  return true;
}

function run(
  r: Runner,
  cmd: string,
  args: string[],
  opts: SpawnOptions = {},
): number {
  if (dry(r, cmd, args)) return 0;
  const res = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  return res.status ?? 1;
}

function capture(r: Runner, cmd: string, args: string[], fake = ''): string {
  if (dry(r, cmd, args)) return fake;
  const res = spawnSync(cmd, args, {
    stdio: ['inherit', 'pipe', 'inherit'],
    encoding: 'utf8',
  });
  return res.status === 0 ? res.stdout : '';
}

function has(cmd: string): boolean {
  return spawnSync('/usr/bin/which', [cmd], { stdio: 'ignore' }).status === 0;
}

function computerName(): string {
  const r = spawnSync('/usr/sbin/scutil', ['--get', 'ComputerName'], {
    encoding: 'utf8',
  });
  const name = r.status === 0 ? r.stdout.trim() : '';
  return name !== '' ? name : hostname().replace(/\.local$/, '') || 'Mac';
}

function openUrl(url: string): void {
  spawnSync('/usr/bin/open', [url], { stdio: 'ignore' });
}

function registerPasskey(r: Runner, name: string): Promise<boolean> {
  const args = ['passkey', 'add', '--name', name];
  if (dry(r, BURSAR_BIN, args)) return Promise.resolve(true);
  return new Promise((done) => {
    const child = spawn(BURSAR_BIN, args, {
      stdio: ['inherit', 'pipe', 'inherit'],
    });
    let opened = false;
    let buf = '';
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      buf += chunk;
      const m = /(http:\/\/localhost:\d+\/[A-Za-z0-9_-]+)/.exec(buf);
      if (m?.[1] !== undefined && !opened) {
        opened = true;
        say(`  Opening ${m[1]}`);
        say('  Press "Create passkey" in the browser and touch Touch ID.');
        openUrl(m[1]);
      }
      if (/registered passkey/.test(buf)) say(c.green('  ✓ passkey saved'));
    });
    child.on('exit', (code) => done(code === 0));
  });
}

async function waitForFunds(network: Network, address: string): Promise<void> {
  const start = await usdcBalance(network, address);
  if (start === null) {
    say(
      c.yellow(
        `  Could not reach ${NETWORKS[network].rpc}; check the balance on the explorer.`,
      ),
    );
    return;
  }
  if (start > 0n) {
    say(c.green(`  ✓ balance: ${formatUsd(start)} USDC`));
    return;
  }
  say(c.dim('  Waiting for USDC to arrive… press Enter to skip.'));
  let skipped = false;
  const rl = createInterface({ input: process.stdin });
  rl.once('line', () => {
    skipped = true;
  });
  const deadline = Date.now() + 20 * 60_000;
  try {
    while (!skipped && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5000));
      const b = await usdcBalance(network, address);
      if (b !== null && b > 0n) {
        say(c.green(`  ✓ received: ${formatUsd(b)} USDC`));
        return;
      }
    }
    if (!skipped)
      say(c.yellow('  Still nothing after 20 minutes; check the explorer.'));
  } finally {
    rl.close();
  }
}

// ---------- the wizard ----------

async function collect(flags: Flags): Promise<Answers> {
  const network =
    flags.network ??
    (await select<Network>('Which network?', [
      {
        value: 'testnet',
        label: 'Testnet (free test money)',
        hint: 'Base Sepolia, recommended first',
      },
      { value: 'mainnet', label: 'Real money', hint: 'USDC on Base' },
    ]));
  const preset =
    flags.limits ??
    (await select<'careful' | 'normal' | 'custom'>('Spending limits?', [
      {
        value: 'careful',
        label: 'Careful',
        hint: '$0.10 per payment · $1/day · $5/month',
      },
      {
        value: 'normal',
        label: 'Normal',
        hint: '$1 per payment · $10/day · $50/month',
      },
      { value: 'custom', label: 'My own' },
    ]));
  const limits: Limits =
    preset === 'custom'
      ? { ...PRESETS.careful, maxTxPerMinute: 20 }
      : { ...PRESETS[preset] };
  const usd = async (question: string, def: string): Promise<string> => {
    for (;;) {
      try {
        return checkUsd(await input(question, def), 'amount');
      } catch (e) {
        say(c.red(`  ${(e as Error).message}`));
      }
    }
  };
  if (preset === 'custom') {
    limits.perTx = await usd('Max per payment, $', limits.perTx);
    limits.perDay = await usd('Max per day, $', limits.perDay);
    limits.perMonth = await usd('Max per month, $', limits.perMonth);
  }
  if (flags.threshold !== undefined)
    limits.threshold = checkUsd(flags.threshold, 'touch id');
  else if (!flags.yes)
    limits.threshold = await usd(
      'Ask Touch ID for payments above, $',
      limits.threshold,
    );
  // stderr, so notes never end up in a policy printed with --print-policy
  for (const w of limitWarnings(limits))
    process.stderr.write(`${c.yellow(`  note: ${w}`)}\n`);
  const claude = has('claude');
  const connectClaude =
    !flags.skipClaude &&
    claude &&
    (flags.yes || (await confirm('Connect Claude Code?', true)));
  if (!claude && !flags.skipClaude)
    say(c.dim('  Claude Code (claude) not found; skipping that step.'));
  return { network, limits, connectClaude };
}

type Flags = {
  network?: Network;
  limits?: 'careful' | 'normal';
  threshold?: string;
  skipClaude: boolean;
  yes: boolean;
  dryRun: boolean;
  printPolicy: boolean;
  keepPolicy: boolean;
};

const USAGE = `npm run setup [-- options]

  --network testnet|mainnet   skip the network question
  --limits careful|normal     skip the limits question
  --threshold <usd>           Touch ID above this amount
  --keep-policy               only update the installed code
  --no-claude                 do not touch Claude Code
  --yes                       take the defaults for the rest
  --print-policy              print the policy that would be written and exit
  --dry-run                   show the commands instead of running them
`;

function parseFlags(argv: string[]): Flags {
  const { values } = parseArgs({
    args: argv,
    options: {
      network: { type: 'string' },
      limits: { type: 'string' },
      threshold: { type: 'string' },
      'no-claude': { type: 'boolean' },
      'keep-policy': { type: 'boolean' },
      yes: { type: 'boolean', short: 'y' },
      'dry-run': { type: 'boolean' },
      'print-policy': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) {
    say(USAGE);
    process.exit(0);
  }
  const net = values.network;
  if (net !== undefined && net !== 'testnet' && net !== 'mainnet')
    throw new Error('--network must be testnet or mainnet');
  const lim = values.limits;
  if (lim !== undefined && lim !== 'careful' && lim !== 'normal')
    throw new Error('--limits must be careful or normal');
  const f: Flags = {
    skipClaude: values['no-claude'] ?? false,
    yes: values.yes ?? false,
    dryRun: values['dry-run'] ?? false,
    printPolicy: values['print-policy'] ?? false,
    keepPolicy: values['keep-policy'] ?? false,
  };
  if (net !== undefined) f.network = net;
  if (lim !== undefined) f.limits = lim;
  if (values.threshold !== undefined) f.threshold = values.threshold;
  if (f.yes) {
    f.network ??= 'testnet';
    f.limits ??= 'careful';
  }
  return f;
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const flags = parseFlags(argv);
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

  if (flags.printPolicy) {
    const a = await collect({ ...flags, skipClaude: true });
    process.stdout.write(buildPolicyYaml(a, TOKEN_PLACEHOLDER));
    return;
  }
  if (process.platform !== 'darwin' && !flags.dryRun)
    throw new Error('setup supports macOS only for now (see SETUP_GUIDE.md)');
  if (process.getuid?.() === 0)
    throw new Error(
      'run setup as your normal user, not with sudo; it asks for sudo itself',
    );
  if (!existsSync(join(repo, 'node_modules', '@noble', 'curves')))
    throw new Error(`run npm ci in ${repo} first`);

  const r: Runner = { dryRun: flags.dryRun, secrets: [] };
  say(c.bold('\nbursar setup'));
  say(
    c.dim(
      'Your agent will be able to ask for payments. The key stays with a hidden system user.',
    ),
  );
  if (flags.dryRun)
    say(c.yellow('dry run: nothing is installed, commands are only shown'));

  const installed = existsSync(PLIST);
  let replacePolicy = !flags.keepPolicy;
  if (installed && !flags.keepPolicy && !flags.yes) {
    replacePolicy = await select<boolean>('bursar is already installed.', [
      { value: false, label: 'Update the code, keep my settings' },
      {
        value: true,
        label: 'Set it up again',
        hint: 'new limits and agent token; key, history and allowed services stay',
      },
    ]);
  }
  if (!installed && flags.keepPolicy)
    throw new Error('--keep-policy needs an existing install');

  const answers = replacePolicy ? await collect(flags) : null;
  const total = answers?.connectClaude ? 5 : 4;
  const token = randomBytes(24).toString('hex');
  r.secrets.push(token);
  const yaml = answers && buildPolicyYaml(answers, token);
  if (answers !== null && yaml !== null) {
    parsePolicy(yaml, { baseDir: STATE, env: {} });
    const l = answers.limits;
    say(`\n  ${c.bold('Summary')}`);
    say(`    network   ${NETWORKS[answers.network].label}`);
    say(
      `    limits    $${l.perTx} per payment · $${l.perDay}/day · $${l.perMonth}/month`,
    );
    say(`    Touch ID  above $${l.threshold}, and for every new service`);
    say(`    Claude    ${answers.connectClaude ? 'connect' : 'skip'}`);
  }
  if (
    !flags.yes &&
    !(await confirm(
      'Install now? You will be asked for your Mac password.',
      true,
    ))
  ) {
    say('Nothing changed.');
    return;
  }

  // 1. install
  step(1, total, 'Installing the daemon');
  const tmp = mkdtempSync(join(tmpdir(), 'bursar-setup-'));
  try {
    const env = [`NODE=${process.execPath}`];
    if (yaml !== null) {
      const file = join(tmp, 'policy.yaml');
      writeFileSync(file, yaml, { mode: 0o600 });
      env.push(`POLICY_FILE=${file}`, 'REPLACE_POLICY=1');
    }
    const code = run(r, '/usr/bin/sudo', [
      '/usr/bin/env',
      ...env,
      join(repo, 'scripts', 'install-macos.sh'),
    ]);
    if (code !== 0)
      throw new Error('the installer failed; nothing was connected');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // 2. passkey
  step(2, total, 'Touch ID');
  const passkeys = capture(r, BURSAR_BIN, ['passkey', 'list']);
  if (passkeys.trim() !== '') {
    say(c.green('  ✓ a passkey is already registered'));
  } else {
    const name = `${computerName()} Touch ID`;
    if (!(await registerPasskey(r, name)))
      say(c.yellow('  Passkey not saved. Run later: bursar passkey add'));
  }

  // 3. Claude Code
  let n = 3;
  if (answers?.connectClaude) {
    step(n++, total, 'Connecting Claude Code');
    run(r, 'claude', ['mcp', 'remove', 'bursar', '--scope', 'user'], {
      stdio: 'ignore',
    });
    const code = run(r, 'claude', [
      'mcp',
      'add',
      'bursar',
      '--scope',
      'user',
      '-e',
      `BURSAR_URL=${BURSAR_URL}`,
      '-e',
      `BURSAR_TOKEN=${token}`,
      '--',
      `${PREFIX}/bin/node`,
      `${PREFIX}/app/src/mcp/server.ts`,
    ]);
    say(
      code === 0
        ? c.green(
            '  ✓ Claude Code has the pay, budget and open_task tools (restart it)',
          )
        : c.yellow('  claude mcp add failed; see SETUP_GUIDE.md step 5'),
    );
  } else if (answers !== null && installed) {
    say(
      c.yellow(
        '\n  The agent token changed. An agent connected earlier gets 401 until you reconnect it (run setup again and choose Claude Code).',
      ),
    );
  } else if (answers === null) {
    say(
      c.dim(
        '\n  Claude Code: kept as it was (the agent token did not change).',
      ),
    );
  }

  // 4. fund
  const network = answers?.network ?? null;
  step(n++, total, 'Fund the wallet');
  const address = parseEvmAddress(
    capture(r, BURSAR_BIN, ['address'], `evm:    0x${'0'.repeat(40)}\n`),
  );
  if (address === null)
    throw new Error('could not read the wallet address (bursar address)');
  say(`  Wallet address: ${c.bold(address)}`);
  if (network === 'testnet') {
    say(
      '  Free test USDC: https://faucet.circle.com → Base Sepolia → paste the address.',
    );
  } else if (network === 'mainnet') {
    say(
      `  Send USDC on the ${c.bold('Base')} network (not Ethereum). Start with $5–10.`,
    );
    say(
      '  Compare the first and last 6 characters of the address before you send.',
    );
  }
  if (network !== null) {
    say(`  Explorer: ${NETWORKS[network].explorer}/address/${address}`);
    if (
      !r.dryRun &&
      tty &&
      (await confirm('Wait here until the money arrives?', true))
    )
      await waitForFunds(network, address);
  }

  // 5. done
  step(n, total, 'Ready');
  say('  Restart Claude Code, then try:');
  say(c.bold('    "Show my bursar budget"'));
  if (network === 'mainnet')
    say(
      c.bold(
        '    "Use bursar pay on https://crypto.apitoll.cloud/v1/crypto/global and summarize it"',
      ),
    );
  else
    say(
      c.dim(
        '    For a first purchase on the testnet, start the test merchant: SETUP_GUIDE.md step 7.',
      ),
    );
  say(
    '\n  The first payment to each service opens a page: press "Always allow" and touch Touch ID.',
  );
  say(
    c.dim('  Everyday: bursar report · bursar recipients · bursar approvals'),
  );
}

if (import.meta.main) {
  main().catch((e: unknown) => {
    process.stderr.write(`\nsetup: ${(e as Error).message}\n`);
    process.exit(1);
  });
}
