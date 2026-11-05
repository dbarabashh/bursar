#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { createApp } from './api/server.ts';
import { resolveApproval } from './approval/resolve.ts';
import { AuditLog } from './audit.ts';
import { loadPolicy, normalizeAddress, type Policy } from './config.ts';
import { Ledger } from './ledger/store.ts';
import { openSigner } from './signer/index.ts';
import { generateKeyFile } from './signer/keystore.ts';
import { startRegistration } from './approval/register.ts';
import { buildReport, formatReport, periodFor } from './report.ts';

const USAGE = `bursar - policy-enforcing signing daemon for AI agents

Usage:
  bursar serve     --policy <file> [--port <n>]
  bursar address   --policy <file>
  bursar approvals --policy <file>
  bursar approve   <approvalId> --policy <file>
  bursar deny      <approvalId> --policy <file>
  bursar recipients        --policy <file>
  bursar recipients remove <address> --policy <file>
  bursar passkey add    --policy <file> [--name <label>]
  bursar passkey list   --policy <file>
  bursar passkey remove <credentialId> --policy <file>
  bursar report    --policy <file> [--period day|month|all] [--since <iso>] [--until <iso>] [--json]
  bursar keygen    --out <file>
`;

function fail(msg: string): never {
  process.stderr.write(`bursar: ${msg}\n`);
  process.exit(1);
}

function policyFrom(path: string | undefined): Policy {
  if (path === undefined) fail('--policy is required');
  return loadPolicy(path);
}

async function serve(policy: Policy, port: number | undefined): Promise<void> {
  const signer = openSigner({ ...policy.wallet, env: process.env });
  const ledger = new Ledger(policy.state.ledgerPath);
  const audit = new AuditLog(policy.state.auditPath, (fn) =>
    ledger.transaction(fn),
  );
  const app = createApp({ policy, signer, ledger, audit });
  const { server, port: bound } = await app.listen(port ?? policy.server.port);
  const addrs = signer.addresses();
  if (
    policy.limits.approval?.method === 'passkey' &&
    ledger.listPasskeys().length === 0
  ) {
    process.stderr.write(
      'warning: approval method is passkey but no passkey is registered; run `bursar passkey add`. Payments above the threshold will time out.\n',
    );
  }
  process.stdout.write(
    `bursar listening on http://${policy.server.host}:${bound} (mode=${policy.mode})\n` +
      `  evm wallet:    ${addrs.evm ?? '-'}\n  solana wallet: ${addrs.solana ?? '-'}\n` +
      `  ledger: ${policy.state.ledgerPath}\n  audit:  ${policy.state.auditPath}\n`,
  );
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    server.close(() => {
      signer.close();
      ledger.close();
      process.exit(0);
    });
    server.closeAllConnections();
    setTimeout(() => {
      signer.close();
      process.exit(0);
    }, 3000).unref();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      policy: { type: 'string', short: 'p' },
      port: { type: 'string' },
      out: { type: 'string' },
      name: { type: 'string' },
      period: { type: 'string' },
      since: { type: 'string' },
      until: { type: 'string' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [cmd, arg, arg2] = positionals;
  if (values.help || cmd === undefined) {
    process.stdout.write(USAGE);
    return;
  }
  switch (cmd) {
    case 'serve': {
      const port = values.port === undefined ? undefined : Number(values.port);
      if (
        port !== undefined &&
        (!Number.isInteger(port) || port < 0 || port > 65535)
      )
        fail('--port must be 0..65535');
      await serve(policyFrom(values.policy), port);
      return;
    }
    case 'address': {
      const policy = policyFrom(values.policy);
      const signer = openSigner({ ...policy.wallet, env: process.env });
      const a = signer.addresses();
      signer.close();
      process.stdout.write(
        `evm:    ${a.evm ?? '-'}\nsolana: ${a.solana ?? '-'}\n`,
      );
      return;
    }
    case 'approvals': {
      const policy = policyFrom(values.policy);
      const ledger = new Ledger(policy.state.ledgerPath);
      const passkey = policy.limits.approval?.method === 'passkey';
      for (const a of ledger.listApprovals('pending')) {
        const where = passkey
          ? `  approve at http://localhost:${policy.server.port}/approve/${a.id}`
          : '';
        const why =
          a.context.reason === 'new_recipient'
            ? `  new recipient${a.context.resourceUrl ? ` (${a.context.resourceUrl})` : ''}`
            : '';
        process.stdout.write(
          `${a.id}  agent=${a.agent}  expires=${new Date(a.expiresAt).toISOString()}${why}  ${a.intentJson}${where}\n`,
        );
      }
      ledger.close();
      return;
    }
    case 'approve':
    case 'deny': {
      if (arg === undefined) fail(`${cmd} needs an approval id`);
      const policy = policyFrom(values.policy);
      const ledger = new Ledger(policy.state.ledgerPath);
      const audit = new AuditLog(policy.state.auditPath, (fn) =>
        ledger.transaction(fn),
      );
      const decision = cmd === 'approve' ? 'approved' : 'denied';
      const outcome = resolveApproval(ledger, audit, arg, decision, {
        via: 'cli',
        method: policy.limits.approval?.method ?? 'cli',
      });
      ledger.close();
      if (outcome === 'passkey_required') {
        fail(
          `this policy requires passkey approval; open http://localhost:${policy.server.port}/approve/${arg} (deny still works from the CLI)`,
        );
      }
      if (outcome === 'not_pending')
        fail(
          `approval ${arg} is not pending (unknown, already resolved, or expired)`,
        );
      process.stdout.write(
        `${arg} ${decision}; the agent's next /v1/sign retry with the same idempotencyKey completes it\n`,
      );
      return;
    }
    case 'recipients': {
      const policy = policyFrom(values.policy);
      const ledger = new Ledger(policy.state.ledgerPath);
      try {
        if (arg === undefined || arg === 'list') {
          if (policy.allow.recipients === 'any')
            process.stdout.write('policy: any recipient (recipients: any)\n');
          else
            for (const r of policy.allow.recipients)
              process.stdout.write(
                `${r.address}  ${r.label ?? '-'}  chains=${r.chains?.join(',') ?? 'any'}  source=policy\n`,
              );
          for (const r of ledger.listLearnedRecipients())
            process.stdout.write(
              `${r.address}  ${r.label}  chains=${r.chain}  source=passkey  added=${new Date(r.created).toISOString()}\n`,
            );
          if (policy.allow.unknownRecipients === 'ask')
            process.stdout.write(
              'new recipients: ask (approve them with your passkey when an agent first pays them)\n',
            );
          return;
        }
        if (arg !== 'remove')
          fail(
            'usage: bursar recipients [list] | bursar recipients remove <address>',
          );
        if (arg2 === undefined) fail('recipients remove needs an address');
        const address = normalizeAddress(arg2);
        const removed = ledger.removeLearnedRecipient(address);
        if (removed === 0) {
          const inPolicy =
            policy.allow.recipients !== 'any' &&
            policy.allow.recipients.some((r) => r.address === address);
          fail(
            inPolicy
              ? `${arg2} is in the policy file; remove it there (sudo nano ${values.policy ?? 'policy.yaml'})`
              : `${arg2} is not on the list`,
          );
        }
        const audit = new AuditLog(policy.state.auditPath, (fn) =>
          ledger.transaction(fn),
        );
        audit.append({
          ts: Date.now(),
          agent: '-',
          event: 'recipient_removed',
          recipient: address,
          via: 'cli',
        });
        process.stdout.write(`removed ${address}\n`);
        return;
      } finally {
        ledger.close();
      }
    }
    case 'passkey': {
      const policy = policyFrom(values.policy);
      const ledger = new Ledger(policy.state.ledgerPath);
      try {
        if (arg === 'list') {
          for (const p of ledger.listPasskeys())
            process.stdout.write(
              `${p.credentialId}  name=${p.name}  signCount=${p.signCount}\n`,
            );
          return;
        }
        if (arg === 'remove') {
          if (arg2 === undefined) fail('passkey remove needs a credential id');
          if (!ledger.removePasskey(arg2)) fail(`no passkey ${arg2}`);
          process.stdout.write(`removed ${arg2}\n`);
          return;
        }
        if (arg !== 'add') fail('usage: bursar passkey add|list|remove');
        const session = await startRegistration({
          ledger,
          name: values.name ?? 'bursar operator',
          userVerification:
            policy.limits.approval?.userVerification ?? 'required',
        });
        process.stdout.write(
          `Open this one-time link in a browser on this machine to register a passkey:\n  ${session.url}\n`,
        );
        const cred = await session.done;
        process.stdout.write(
          `registered passkey ${cred.credentialId} (${cred.name})\n`,
        );
        return;
      } finally {
        ledger.close();
      }
    }
    case 'report': {
      const policy = policyFrom(values.policy);
      const ledger = new Ledger(policy.state.ledgerPath);
      const audit = new AuditLog(policy.state.auditPath, (fn) =>
        ledger.transaction(fn),
      );
      try {
        const now = Date.now();
        const report = buildReport(
          { policy, ledger, audit, now },
          periodFor(values.period ?? 'month', now, values.since, values.until),
        );
        process.stdout.write(
          values.json
            ? `${JSON.stringify(report, null, 2)}\n`
            : formatReport(report),
        );
      } finally {
        ledger.close();
      }
      return;
    }
    case 'setup':
      fail('run setup from the bursar repo as your own user: npm run setup');
    case 'keygen': {
      if (values.out === undefined) fail('--out is required');
      generateKeyFile(values.out);
      process.stdout.write(`wrote ${values.out} (mode 600)\n`);
      return;
    }
    default:
      fail(`unknown command ${cmd}\n\n${USAGE}`);
  }
}

main().catch((e: unknown) => fail((e as Error).message));
