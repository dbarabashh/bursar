import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parsePolicy } from '../src/config.ts';
import type { PaymentIntent } from '../src/intent.ts';
import { learnedRule } from '../src/policy/allowlist.ts';
import { evaluate } from '../src/policy/engine.ts';
import type { LedgerSnapshot } from '../src/policy/limits.ts';
import { MERCHANT, USDC_BASE } from './helpers.ts';

// Recipient X is capped at $1/day and listed for Base only. With
// unknown_recipients: ask, paying X on Optimism must still honour that cap,
// both before and after X is learned on Optimism.
const X = MERCHANT;
const USDC = USDC_BASE;

const policy = parsePolicy(
  [
    'version: 1',
    'wallet:',
    '  keyfile: ./key',
    'agents:',
    '  - id: a',
    '    token: test-token-0123456789abcdef0123456789',
    'limits:',
    '  per_tx: { usd: 100.00 }',
    '  per_day: { usd: 500.00 }',
    '  approval_threshold: { usd: 50.00, timeout_seconds: 60, method: passkey }',
    'allow:',
    "  chains: ['eip155:8453', 'eip155:10']",
    `  assets: ['${USDC}']`,
    '  recipients:',
    `    - { address: '${X}', label: capped, max_usd_day: 1.00, chains: ['eip155:8453'] }`,
    '  unknown_recipients: ask',
    '',
  ].join('\n'),
  { baseDir: '/nonexistent', env: {} },
);

function intent(chain: string): PaymentIntent {
  return {
    protocol: 'x402',
    chain,
    asset: USDC,
    recipient: X,
    amount: 40_000_000n,
    decimals: 6,
    idempotencyKey: 'k',
    agentId: 'a',
    raw: null,
  };
}

const snap: LedgerSnapshot = {
  daySpent: 1_000_000n,
  recipientDaySpent: 1_000_000n, // X already received $1 today
  walletDaySpent: 1_000_000n,
  monthSpent: 1_000_000n,
  recentTxCount: 1,
  task: null,
};

describe('audit: per-recipient max_usd_day across chains', () => {
  it('denies on the listed chain (baseline)', () => {
    const d = evaluate(policy, intent('eip155:8453'), snap, {
      approved: false,
    });
    assert.equal(d.kind, 'deny');
    assert.equal(d.kind === 'deny' && d.reason, 'per_recipient_day_limit');
  });

  it('still denies on another chain via the unknown_recipients: ask path', () => {
    const d = evaluate(policy, intent('eip155:10'), snap, { approved: false });
    assert.deepEqual(
      d.kind === 'deny' ? d.reason : d.kind,
      'per_recipient_day_limit',
    );
  });

  it('still denies after X is learned on the other chain', () => {
    const learned = [
      learnedRule({
        address: X,
        chain: 'eip155:10',
        label: 'capped',
        created: 0,
        approvalId: 'x',
        credential: 'c',
      } as never),
    ];
    const d = evaluate(policy, intent('eip155:10'), snap, {
      approved: false,
      learned,
    });
    assert.deepEqual(
      d.kind === 'deny' ? d.reason : d.kind,
      'per_recipient_day_limit',
    );
  });
});
