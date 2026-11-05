import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';
import { parsePolicy } from '../src/config.ts';
import { parseUsd } from '../src/util.ts';
import {
  balanceOfCall,
  buildPolicyYaml,
  checkUsd,
  limitWarnings,
  NETWORKS,
  parseEvmAddress,
  PRESETS,
  type Network,
} from '../src/setup.ts';

const TOKEN = 'a'.repeat(48);

describe('setup: policy', () => {
  for (const network of ['testnet', 'mainnet'] as Network[]) {
    for (const preset of ['careful', 'normal'] as const) {
      it(`${network} / ${preset} parses and matches the answers`, () => {
        const yaml = buildPolicyYaml(
          { network, limits: PRESETS[preset] },
          TOKEN,
          '/var/db/bursar',
        );
        const p = parsePolicy(yaml, { baseDir: '/var/db/bursar', env: {} });
        const n = NETWORKS[network];
        assert.deepEqual(p.allow.chains, [n.chain]);
        assert.equal(p.allow.assets[0]?.address, n.usdc.toLowerCase());
        assert.deepEqual(p.allow.recipients, []);
        assert.equal(p.allow.unknownRecipients, 'ask');
        assert.equal(p.limits.approval?.method, 'passkey');
        assert.equal(p.mode, 'enforce');
        assert.equal(p.agents[0]?.id, 'claude-code');
        assert.equal(p.wallet.keyfile, '/var/db/bursar/key');
        assert.equal(p.state.ledgerPath, '/var/db/bursar/bursar.db');
        const micro = (usd: string) => parseUsd(usd, 'test');
        assert.equal(p.limits.perTx, micro(PRESETS[preset].perTx));
        assert.equal(p.limits.perDay, micro(PRESETS[preset].perDay));
        assert.equal(p.limits.perMonth?.usd, micro(PRESETS[preset].perMonth));
        assert.equal(
          p.limits.approval?.threshold,
          micro(PRESETS[preset].threshold),
        );
      });
    }
  }

  it('custom limits go through as typed', () => {
    const limits = {
      perTx: checkUsd('$2', 'x'),
      perDay: checkUsd('20', 'x'),
      perMonth: checkUsd('100.5', 'x'),
      threshold: checkUsd('0', 'x'),
      maxTxPerMinute: 20,
    };
    assert.equal(limits.perTx, '2.00');
    assert.equal(limits.perMonth, '100.50');
    const p = parsePolicy(
      buildPolicyYaml({ network: 'testnet', limits }, TOKEN),
      {
        baseDir: '/var/db/bursar',
        env: {},
      },
    );
    assert.equal(p.limits.perTx, 2_000_000n);
    assert.equal(p.limits.approval?.threshold, 0n);
  });
});

describe('setup: input checks', () => {
  it('accepts plain dollar amounts only', () => {
    assert.equal(checkUsd(' 0.1 ', 'x'), '0.10');
    for (const bad of ['', 'abc', '-1', '1e3', '0.1234567', '1,5'])
      assert.throws(() => checkUsd(bad, 'per day'), /per day/);
  });

  it('warns about limits that do not do what they look like', () => {
    assert.deepEqual(limitWarnings(PRESETS.careful), []);
    const w = limitWarnings({
      perTx: '5.00',
      perDay: '1.00',
      perMonth: '0.50',
      threshold: '10.00',
      maxTxPerMinute: 10,
    });
    assert.equal(w.length, 3);
    assert.match(w.join('\n'), /only asked for new services/);
  });

  it('reads the wallet address and builds a balanceOf call', () => {
    const a = '0x8f3a00000000000000000000000000000000c2aB';
    assert.equal(parseEvmAddress(`evm:    ${a}\nsolana: -\n`), a);
    assert.equal(parseEvmAddress('evm:    -\n'), null);
    assert.equal(
      balanceOfCall(a),
      `0x70a08231${'0'.repeat(24)}${a.slice(2).toLowerCase()}`,
    );
  });
});

describe('setup: command line', () => {
  it('--print-policy --yes prints a valid testnet policy without installing anything', () => {
    const r = spawnSync(
      process.execPath,
      [
        new URL('../src/setup.ts', import.meta.url).pathname,
        '--print-policy',
        '--yes',
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    assert.equal(r.status, 0, r.stderr);
    const p = parsePolicy(r.stdout, { baseDir: '/', env: {} });
    assert.deepEqual(p.allow.chains, ['eip155:84532']);
    assert.equal(p.limits.perTx, 100_000n);
  });

  it('rejects unknown option values', () => {
    const r = spawnSync(
      process.execPath,
      [
        new URL('../src/setup.ts', import.meta.url).pathname,
        '--network',
        'eth',
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    assert.equal(r.status, 1);
    assert.match(r.stderr, /--network must be testnet or mainnet/);
  });
});
