import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { addr, Transaction } from 'micro-eth-signer';
import * as sol from 'micro-sol-signer';
import { computeResourceHash, type MppTempoPlan } from '../src/intent.ts';
import { AdapterError } from '../src/protocols/common.ts';
import {
  applyTempoGasPrice,
  parseMpp,
  TRANSFER_WITH_MEMO_SELECTOR,
} from '../src/protocols/mpp.ts';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { parseX402 } from '../src/protocols/x402.ts';
import {
  adapterCtx,
  cleanup,
  erc20TransferData,
  EVM_KEY,
  evmBody,
  makeEnv,
  MERCHANT,
  PATHUSD,
  sign,
  SOL_FACILITATOR,
  SOL_KEY,
  SOL_MERCHANT,
  STRANGER,
  usdc,
  USDC_BASE,
  USDC_SOL,
  x402Body,
} from './helpers.ts';

const ctx = adapterCtx;

describe('x402 adapter', () => {
  it('derives recipient and amount from the signed requirement, ignoring agent-supplied fields', async () => {
    const env = makeEnv();
    try {
      const sneaky = x402Body({
        payTo: STRANGER,
        amount: usdc(0.1),
        agentFields: { recipient: MERCHANT, payTo: MERCHANT, amount: '1' },
        key: 'sneaky',
      });
      const denied = await sign(env, sneaky);
      assert.equal(denied.body['status'], 'denied');
      assert.equal(denied.body['reason'], 'recipient_not_allowed');

      const big = x402Body({
        amount: usdc(5),
        agentFields: { amount: usdc(0.01), maxAmountRequired: usdc(0.01) },
        key: 'big',
      });
      assert.equal((await sign(env, big)).body['reason'], 'per_tx_limit');

      const intent = parseX402(
        x402Body({ amount: usdc(0.3) })['payload'],
        ctx(),
      );
      assert.equal(intent.recipient, MERCHANT);
      assert.equal(intent.amount, 300_000n);
      const raw = intent.raw as { message: { to: string; value: bigint } };
      assert.equal(raw.message.to, intent.recipient);
      assert.equal(raw.message.value, intent.amount);

      const ok = await sign(env, x402Body({ amount: usdc(0.3), key: 'ok' }));
      const auth = (
        ok.body['payment'] as {
          payload: { authorization: Record<string, string> };
        }
      ).payload.authorization;
      assert.equal(auth['to'], MERCHANT);
      assert.equal(auth['value'], usdc(0.3));
      assert.equal(env.ledger.spendCount(), 1);
    } finally {
      cleanup(env);
    }
  });

  it('rejects a payload whose display amount differs from the signed amount', async () => {
    const env = makeEnv();
    try {
      const body = x402Body({
        amount: usdc(0.9),
        extra: { name: 'USD Coin', version: '2', displayAmount: '0.01' },
      });
      const r = await sign(env, body);
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'display_amount_mismatch');
      assert.equal(env.ledger.spendCount(), 0);

      const price = x402Body({
        amount: usdc(0.9),
        extra: { name: 'USD Coin', version: '2', price: '$0.90' },
        key: 'p',
      });
      assert.equal((await sign(env, price)).body['status'], 'signed');
      assert.throws(
        () =>
          parseX402(
            x402Body({
              amount: usdc(0.9),
              extra: { name: 'USD Coin', version: '2', price: '$0.01' },
            })['payload'],
            ctx(),
          ),
        AdapterError,
      );
    } finally {
      cleanup(env);
    }
  });

  it('supports x402 v1 with network aliases and the X-PAYMENT header', async () => {
    const env = makeEnv();
    try {
      const r = await sign(env, x402Body({ version: 1, network: 'base' }));
      assert.equal(r.body['status'], 'signed');
      const header = r.body['header'] as { name: string; value: string };
      assert.equal(header.name, 'X-PAYMENT');
      const decoded = JSON.parse(
        Buffer.from(header.value, 'base64').toString(),
      ) as Record<string, unknown>;
      assert.equal(decoded['x402Version'], 1);
      assert.equal(decoded['network'], 'base');
      assert.equal(decoded['scheme'], 'exact');
    } finally {
      cleanup(env);
    }
  });

  it('signs a Solana exact payment as a partially signed transferChecked transaction', async () => {
    const env = makeEnv();
    try {
      const r = await sign(
        env,
        x402Body({
          network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
          amount: usdc(0.2),
        }),
      );
      assert.equal(r.body['status'], 'signed');
      const txB64 = r.body['signedTx'] as string;
      const decoded = sol.Transaction.decode(Buffer.from(txB64, 'base64'));
      assert.equal(decoded.msg.feePayer, SOL_FACILITATOR);
      const owner = sol.getAddress(Buffer.from(SOL_KEY, 'hex'));
      const parsed = decoded.msg.instructions.map((i) =>
        sol.parseInstruction(i),
      ) as { TAG: string; data: Record<string, unknown> }[];
      assert.deepEqual(
        parsed.map((p) => p.TAG),
        ['setComputeUnitLimit', 'setComputeUnitPrice', 'transferChecked'],
      );
      const transfer = parsed[2];
      assert.ok(transfer);
      assert.equal(transfer.data['amount'], 200_000n);
      assert.equal(transfer.data['mint'], USDC_SOL);
      assert.equal(transfer.data['authority'], owner);
      assert.equal(
        transfer.data['destination'],
        sol.tokenAddress({
          mint: USDC_SOL,
          owner: SOL_MERCHANT,
          tokenProgram: sol.TOKEN_PROGRAM,
        }),
      );
      assert.ok(decoded.signatures[SOL_FACILITATOR]?.every((b) => b === 0));
      const sig = decoded.signatures[owner];
      assert.ok(sig);
      const msg = Buffer.from(sol.getMessageFromTransaction(txB64), 'base64');
      assert.ok(ed25519.verify(sig, msg, sol.parseAddress(owner)));
    } finally {
      cleanup(env);
    }
  });
});

describe('mpp adapter', () => {
  const resource = { method: 'GET', url: 'https://mpp.example.com/v1/chat' };
  const request = {
    amount: usdc(0.2),
    currency: PATHUSD,
    recipient: MERCHANT,
    methodDetails: { chainId: 4217, feePayer: true },
  };
  const enc = (r: unknown) =>
    Buffer.from(JSON.stringify(r)).toString('base64url');
  const challengeFor = (r: unknown, extra = '') =>
    `Payment id="ch_123", realm="mpp.example.com", method="tempo", intent="charge", request="${enc(r)}"${extra}`;
  const header = challengeFor(request, ', expires="2026-11-03T12:05:00Z"');

  it('builds a Tempo intent whose memo is the resource hash when the server sets none', () => {
    const resourceHash = computeResourceHash(resource);
    const intent = parseMpp(
      { challenge: header },
      ctx({ resource, resourceHash }),
    );
    assert.equal(intent.protocol, 'mpp');
    assert.equal(intent.chain, 'eip155:4217');
    assert.equal(intent.asset, PATHUSD);
    assert.equal(intent.recipient, MERCHANT);
    assert.equal(intent.amount, 200_000n);
    assert.equal(intent.decimals, 6);
    assert.equal(intent.resourceHash, resourceHash);
    assert.ok(intent.memo);
    assert.equal(bytesToHex(intent.memo), resourceHash);
    const plan = intent.raw as MppTempoPlan;
    assert.equal(plan.memoSource, 'resource');
    assert.equal(plan.feePayer, true);
    assert.equal(plan.expires, '2026-11-03T12:05:00Z');
    assert.equal(plan.challenge['id'], 'ch_123');
    assert.equal(plan.call.to, PATHUSD);
    assert.equal(TRANSFER_WITH_MEMO_SELECTOR, '0x95777d59');
    assert.ok(plan.call.data.startsWith(TRANSFER_WITH_MEMO_SELECTOR));
    assert.ok(plan.call.data.endsWith(resourceHash));
    assert.equal(plan.call.data.length, 2 + 8 + 64 * 3);
  });

  it('uses a server-provided memo verbatim, as the spec requires', () => {
    const serverMemo = `0x${'ab'.repeat(32)}`;
    const h = challengeFor({
      ...request,
      methodDetails: { chainId: 4217, feePayer: true, memo: serverMemo },
    });
    const intent = parseMpp(
      { challenge: h },
      ctx({ resource, resourceHash: computeResourceHash(resource) }),
    );
    assert.equal(`0x${bytesToHex(intent.memo as Uint8Array)}`, serverMemo);
    assert.equal((intent.raw as MppTempoPlan).memoSource, 'server');
    assert.equal(intent.resourceHash, computeResourceHash(resource));
  });

  it('defaults to the Tempo testnet chain id when methodDetails.chainId is absent', async () => {
    const intent = parseMpp(
      {
        challenge: challengeFor({
          amount: '1',
          currency: PATHUSD,
          recipient: MERCHANT,
          methodDetails: { feePayer: true },
        }),
      },
      ctx(),
    );
    assert.equal(intent.chain, 'eip155:42431');
    const env = makeEnv();
    try {
      const r = await sign(env, {
        protocol: 'mpp',
        idempotencyKey: 'mpp-testnet',
        payload: {
          challenge: challengeFor({
            amount: '1',
            currency: PATHUSD,
            recipient: MERCHANT,
            methodDetails: { feePayer: true },
          }),
        },
      });
      assert.equal(r.body['reason'], 'chain_not_allowed');
    } finally {
      cleanup(env);
    }
  });

  it('picks the tempo charge challenge among several and accepts token-form params', () => {
    const multi = `Bearer realm="x", Payment id=stripe1, realm=api.example.com, method=stripe, intent=charge, request="${enc({ amount: '5' })}", Payment id=t1, realm=api.example.com, method=tempo, intent=charge, request=${enc(request)}`;
    const intent = parseMpp({ challenge: multi }, ctx());
    assert.equal(intent.recipient, MERCHANT);
    assert.equal((intent.raw as MppTempoPlan).challenge['id'], 't1');
    const asList = parseMpp(
      {
        challenge: [
          challengeFor({
            amount: '5',
            currency: PATHUSD,
            recipient: MERCHANT,
          }).replace('tempo', 'stripe'),
          header,
        ],
      },
      ctx(),
    );
    assert.equal(asList.amount, 200_000n);
    assert.throws(
      () =>
        parseMpp({ challenge: header.replace('"tempo"', '"stripe"') }, ctx()),
      /mpp_method_not_supported/,
    );
    assert.throws(
      () =>
        parseMpp({ challenge: header.replace('"charge"', '"session"') }, ctx()),
      /mpp_intent_not_supported/,
    );
  });

  it('rejects expired challenges, splits, push-only mode and a mismatched body digest', () => {
    assert.throws(
      () =>
        parseMpp(
          {
            challenge: challengeFor(
              request,
              ', expires="2026-11-03T11:59:59Z"',
            ),
          },
          ctx(),
        ),
      /mpp_challenge_expired/,
    );
    const splits = {
      ...request,
      methodDetails: {
        chainId: 4217,
        feePayer: true,
        splits: [{ amount: '1', recipient: STRANGER }],
      },
    };
    assert.throws(
      () => parseMpp({ challenge: challengeFor(splits) }, ctx()),
      /mpp_splits_not_supported/,
    );
    const push = {
      ...request,
      methodDetails: {
        chainId: 4217,
        feePayer: true,
        supportedModes: ['push'],
      },
    };
    assert.throws(
      () => parseMpp({ challenge: challengeFor(push) }, ctx()),
      /mpp_mode_not_supported/,
    );
    const pull = {
      ...request,
      methodDetails: {
        chainId: 4217,
        feePayer: true,
        supportedModes: ['push', 'pull'],
      },
    };
    assert.equal(
      parseMpp({ challenge: challengeFor(pull) }, ctx()).amount,
      200_000n,
    );
    const body = '{"q":1}';
    const bodySha = createHash('sha256').update(body).digest();
    const digest = `, digest="sha-256=:${bodySha.toString('base64')}:"`;
    const withBody = {
      method: 'POST',
      url: resource.url,
      bodySha256: bodySha.toString('hex'),
    };
    assert.equal(
      parseMpp(
        { challenge: challengeFor(request, digest) },
        ctx({ resource: withBody }),
      ).amount,
      200_000n,
    );
    const otherBody = {
      ...withBody,
      bodySha256: createHash('sha256').update('{"q":2}').digest('hex'),
    };
    assert.throws(
      () =>
        parseMpp(
          { challenge: challengeFor(request, digest) },
          ctx({ resource: otherBody }),
        ),
      /resource_hash_mismatch/,
    );
  });

  it('runs through policy and stops at the unimplemented Tempo signer without charging', async () => {
    const env = makeEnv();
    try {
      const r = await sign(env, {
        protocol: 'mpp',
        idempotencyKey: 'mpp-1',
        payload: { challenge: header },
        resource,
        resourceHash: computeResourceHash(resource),
      });
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'signer_not_implemented');
      assert.equal(env.ledger.spendCount(), 0);
      const budget = env.app.budget('nanocode').body as {
        perDay: { spentUsd: string };
      };
      assert.equal(budget.perDay.spentUsd, '0.00');
      const over = await sign(env, {
        protocol: 'mpp',
        idempotencyKey: 'mpp-2',
        payload: { challenge: challengeFor({ ...request, amount: usdc(2) }) },
      });
      assert.equal(over.body['reason'], 'per_tx_limit');
    } finally {
      cleanup(env);
    }
  });
});

describe('mpp network fees (feePayer: false)', () => {
  const clientPaid = {
    amount: usdc(0.2),
    currency: PATHUSD,
    recipient: MERCHANT,
    methodDetails: { chainId: 4217 },
  };
  const enc = (r: unknown) =>
    Buffer.from(JSON.stringify(r)).toString('base64url');
  const challengeFor = (r: unknown) =>
    `Payment id="ch_fee", realm="mpp.example.com", method="tempo", intent="charge", request="${enc(r)}"`;

  async function withRpc<T>(
    gasPrice: bigint | null,
    fn: (url: string) => Promise<T>,
  ): Promise<T> {
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => {
        body += c;
      });
      req.on('end', () => {
        const id = (JSON.parse(body) as { id: number }).id;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify(
            gasPrice === null
              ? { jsonrpc: '2.0', id, error: { code: -32000, message: 'down' } }
              : { jsonrpc: '2.0', id, result: `0x${gasPrice.toString(16)}` },
          ),
        );
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      return await fn(
        `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
      );
    } finally {
      server.close();
    }
  }

  it('denies client-paid fees by default', async () => {
    assert.throws(
      () => parseMpp({ challenge: challengeFor(clientPaid) }, ctx()),
      /mpp_client_fees_not_allowed/,
    );
    const env = makeEnv();
    try {
      const r = await sign(env, {
        protocol: 'mpp',
        idempotencyKey: 'fee-default',
        payload: { challenge: challengeFor(clientPaid) },
      });
      assert.equal(r.body['reason'], 'mpp_client_fees_not_allowed');
    } finally {
      cleanup(env);
    }
  });

  it('prices the worst-case fee in USD from the RPC gas price (attodollars per gas)', () => {
    const intent = parseMpp(
      { challenge: challengeFor(clientPaid) },
      ctx({
        tempo: {
          allowClientPaidFees: true,
          maxFeeUsd: 10_000n,
          gasLimit: 300_000n,
        },
      }),
    );
    assert.equal(intent.fee, undefined);
    assert.equal(applyTempoGasPrice(intent, 600_000_000n, 10_000n), null);
    assert.deepEqual(intent.fee, { asset: PATHUSD, amount: 360n, decimals: 6 });
    const plan = intent.raw as MppTempoPlan;
    assert.equal(plan.fee?.maxFeePerGas, 1_200_000_000n);
    assert.equal(plan.fee?.token, PATHUSD);

    const clamped = parseMpp(
      { challenge: challengeFor(clientPaid) },
      ctx({
        tempo: {
          allowClientPaidFees: true,
          maxFeeUsd: 10_000n,
          gasLimit: 300_000n,
        },
      }),
    );
    assert.equal(applyTempoGasPrice(clamped, 20_000_000_000n, 10_000n), null);
    assert.ok((clamped.fee?.amount ?? 0n) <= 10_000n);
    const tooHigh = parseMpp(
      { challenge: challengeFor(clientPaid) },
      ctx({
        tempo: {
          allowClientPaidFees: true,
          maxFeeUsd: 10_000n,
          gasLimit: 300_000n,
        },
      }),
    );
    assert.equal(
      applyTempoGasPrice(tooHigh, 10n ** 12n, 10_000n),
      'network_fee_too_high',
    );
  });

  it('counts the fee against per_tx but not against the recipient limit', async () => {
    await withRpc(600_000_000n, async (url) => {
      const env = makeEnv({
        tempo: { allowClientPaidFees: true },
        rpc: { 'eip155:4217': url },
      });
      try {
        const exact = { ...clientPaid, amount: usdc(1) };
        const over = await sign(env, {
          protocol: 'mpp',
          idempotencyKey: 'fee-over',
          payload: { challenge: challengeFor(exact) },
        });
        assert.equal(over.body['reason'], 'per_tx_limit');
        const sponsored = {
          ...exact,
          methodDetails: { chainId: 4217, feePayer: true },
        };
        const ok = await sign(env, {
          protocol: 'mpp',
          idempotencyKey: 'fee-sponsored',
          payload: { challenge: challengeFor(sponsored) },
        });
        assert.equal(ok.body['reason'], 'signer_not_implemented');
        const priced = await sign(env, {
          protocol: 'mpp',
          idempotencyKey: 'fee-priced',
          payload: { challenge: challengeFor(clientPaid) },
        });
        assert.equal(priced.body['reason'], 'signer_not_implemented');
        const audit = env.audit
          .readSince(0, 'nanocode')
          .map((l) => JSON.parse(l) as Record<string, unknown>);
        const last = audit[audit.length - 1] as {
          usd: string;
          intent: { fee: { amount: string } };
        };
        assert.equal(last.usd, '0.20036');
        assert.equal(last.intent.fee.amount, '360');
        assert.equal(env.ledger.spendCount(), 0);
      } finally {
        cleanup(env);
      }
    });
  });

  it('denies when the gas price is unavailable or above the fee cap', async () => {
    const noRpc = makeEnv({ tempo: { allowClientPaidFees: true } });
    try {
      const r = await sign(noRpc, {
        protocol: 'mpp',
        idempotencyKey: 'fee-norpc',
        payload: { challenge: challengeFor(clientPaid) },
      });
      assert.equal(r.body['reason'], 'fee_price_unavailable');
    } finally {
      cleanup(noRpc);
    }
    await withRpc(null, async (url) => {
      const env = makeEnv({
        tempo: { allowClientPaidFees: true },
        rpc: { 'eip155:4217': url },
      });
      try {
        assert.equal(
          (
            await sign(env, {
              protocol: 'mpp',
              idempotencyKey: 'fee-down',
              payload: { challenge: challengeFor(clientPaid) },
            })
          ).body['reason'],
          'fee_price_unavailable',
        );
      } finally {
        cleanup(env);
      }
    });
    await withRpc(10n ** 12n, async (url) => {
      const env = makeEnv({
        tempo: { allowClientPaidFees: true, maxFeeUsd: '0.01' },
        rpc: { 'eip155:4217': url },
      });
      try {
        assert.equal(
          (
            await sign(env, {
              protocol: 'mpp',
              idempotencyKey: 'fee-spike',
              payload: { challenge: challengeFor(clientPaid) },
            })
          ).body['reason'],
          'network_fee_too_high',
        );
      } finally {
        cleanup(env);
      }
    });
  });

  it('the signer refuses a plan whose fee was not priced and checked', () => {
    const env = makeEnv();
    try {
      const intent = parseMpp(
        { challenge: challengeFor(clientPaid) },
        ctx({
          tempo: {
            allowClientPaidFees: true,
            maxFeeUsd: 10_000n,
            gasLimit: 300_000n,
          },
        }),
      );
      assert.throws(() => env.signer.sign(intent), /not priced/);
      applyTempoGasPrice(intent, 600_000_000n, 10_000n);
      assert.throws(
        () =>
          env.signer.sign({
            ...intent,
            fee: { asset: PATHUSD, amount: 1n, decimals: 6 },
          }),
        /not priced/,
      );
      assert.throws(
        () => env.signer.sign(intent),
        /tempo_0x76_not_implemented/,
      );
    } finally {
      cleanup(env);
    }
  });
});

describe('evm adapter', () => {
  it('signs an ERC-20 transfer to an allowlisted recipient', async () => {
    const env = makeEnv();
    try {
      const r = await sign(env, evmBody(erc20TransferData(MERCHANT, 250_000n)));
      assert.equal(r.body['status'], 'signed');
      const tx = Transaction.fromHex(r.body['signedTx'] as string);
      assert.equal(tx.sender, addr.fromPrivateKey(EVM_KEY));
      assert.equal(tx.raw.to.toLowerCase(), USDC_BASE.toLowerCase());
      assert.equal(r.body['usd'], '0.25');
    } finally {
      cleanup(env);
    }
  });

  it('denies approve, unknown selectors, and transfers to strangers', async () => {
    const env = makeEnv();
    try {
      const approve = await sign(
        env,
        evmBody(erc20TransferData(MERCHANT, 1n, '095ea7b3'), {
          key: 'approve',
        }),
      );
      assert.equal(approve.body['reason'], 'selector_not_allowed');
      const unknown = await sign(
        env,
        evmBody(`0xdeadbeef${'00'.repeat(64)}`, { key: 'unknown' }),
      );
      assert.equal(unknown.body['reason'], 'selector_not_allowed');
      const stranger = await sign(
        env,
        evmBody(erc20TransferData(STRANGER, 1n), { key: 'stranger' }),
      );
      assert.equal(stranger.body['reason'], 'recipient_not_allowed');
      const padded = await sign(
        env,
        evmBody(`${erc20TransferData(MERCHANT, 1n)}00`, { key: 'padded' }),
      );
      assert.equal(padded.body['reason'], 'calldata_invalid');
      const withValue = await sign(
        env,
        evmBody(erc20TransferData(MERCHANT, 1n), { key: 'value', value: '1' }),
      );
      assert.equal(withValue.body['reason'], 'calldata_invalid');
      const native = await sign(
        env,
        evmBody('0x', { key: 'native', to: MERCHANT, value: '1000' }),
      );
      assert.equal(native.body['reason'], 'asset_not_allowed');
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      cleanup(env);
    }
  });

  it('caps the network fee the agent can make the wallet pay', async () => {
    const env = makeEnv();
    try {
      const body = evmBody(erc20TransferData(MERCHANT, 1n));
      (body['payload'] as Record<string, unknown>)['maxFeePerGas'] =
        '100000000000000';
      assert.equal(
        (await sign(env, body)).body['reason'],
        'network_fee_too_high',
      );
    } finally {
      cleanup(env);
    }
  });
});
