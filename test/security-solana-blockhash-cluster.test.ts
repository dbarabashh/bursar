import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import * as sol from 'micro-sol-signer';
import { createApp } from '../src/api/server.ts';
import { AuditLog } from '../src/audit.ts';
import { parsePolicy } from '../src/config.ts';
import { Ledger } from '../src/ledger/store.ts';
import { openSigner } from '../src/signer/index.ts';
import {
  cleanup,
  makeClock,
  makeDir,
  policyYaml,
  SOL_MERCHANT,
  TOKEN,
  USDC_SOL,
  x402Body,
  type TestEnv,
} from './helpers.ts';

const DEVNET_BH = sol.getAddress(new Uint8Array(32).fill(7));
const MAINNET_BH = sol.getAddress(new Uint8Array(32).fill(9));

// Policy: two Solana clusters, USDC mint allowed as a plain string (any
// allowed chain), merchant pinned to devnet only, devnet RPC configured.
function env(rpcUrl: string): TestEnv {
  const yaml = policyYaml({ rpc: { 'solana:devnet': rpcUrl } })
    .replace(
      "'solana:mainnet', 'eip155:4217']",
      "'solana:mainnet', 'solana:devnet', 'eip155:4217']",
    )
    .replace(
      `{ address: '${USDC_SOL}', decimals: 6, chains: ['solana:mainnet'] }`,
      `'${USDC_SOL}'`,
    )
    .replace(
      `{ address: '${SOL_MERCHANT}', label: sol-merchant }`,
      `{ address: '${SOL_MERCHANT}', label: sol-merchant, chains: ['solana:devnet'] }`,
    );
  assert.match(yaml, /solana:devnet', 'eip155/);
  const dir = makeDir();
  const clock = makeClock();
  const policy = parsePolicy(yaml, {
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

describe('audit: Solana blockhash cluster binding', () => {
  it('does not sign with an agent-supplied blockhash from another cluster', async () => {
    const rpc = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', () => {
        const { id } = JSON.parse(body) as { id: number };
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              value: { blockhash: DEVNET_BH, lastValidBlockHeight: 1 },
            },
          }),
        );
      });
    });
    await new Promise<void>((r) => rpc.listen(0, '127.0.0.1', r));
    const e = env(`http://127.0.0.1:${(rpc.address() as AddressInfo).port}`);
    try {
      const body = x402Body({ network: 'solana-devnet' });
      // The agent supplies a mainnet blockhash while claiming devnet.
      (body['payload'] as Record<string, unknown>)['solana'] = {
        recentBlockhash: MAINNET_BH,
      };
      const r = await e.app.sign('nanocode', body);
      const res = r.body as Record<string, unknown>;
      if (res['status'] !== 'signed') return; // refusing is also secure
      const tx = sol.Transaction.decode(
        Buffer.from(res['signedTx'] as string, 'base64'),
      );
      assert.notEqual(
        tx.msg.blockhash,
        MAINNET_BH,
        'signed a solana:devnet payment with the agent-supplied (mainnet) blockhash',
      );
      assert.equal(tx.msg.blockhash, DEVNET_BH);
    } finally {
      rpc.close();
      cleanup(e);
    }
  });
});
