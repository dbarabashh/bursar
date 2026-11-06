import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { approvalChallenge } from '../src/approval/passkey.ts';
import { resolveApproval } from '../src/approval/resolve.ts';
import { parsePolicy } from '../src/config.ts';
import { http } from './fixtures/authenticator.ts';
import {
  auditEvents,
  decideWithPasskey,
  makeDir,
  makeEnv,
  cleanup,
  MERCHANT,
  PATHUSD,
  policyYaml,
  sign,
  startWithPasskey,
  STRANGER,
  TOKEN,
  usdc,
  x402Body,
  type PolicyOptions,
} from './helpers.ts';

const ASK: PolicyOptions = {
  approval: '0.50',
  approvalMethod: 'passkey',
  unknownRecipients: 'ask',
};

const start = (opts: PolicyOptions = ASK) => startWithPasskey(opts);

const stranger = (key: string, amount = usdc(0.01)) =>
  x402Body({
    payTo: STRANGER,
    amount,
    key,
    resourceUrl: 'https://crypto.apitoll.cloud/v1/crypto/global',
  });

describe('policy: unknown_recipients', () => {
  const parse = (o: PolicyOptions) =>
    parsePolicy(policyYaml(o), {
      baseDir: makeDir(),
      env: { TEST_TOKEN: TOKEN },
    });

  it('defaults to deny and accepts ask with passkey approvals', () => {
    assert.equal(parse({}).allow.unknownRecipients, 'deny');
    assert.equal(parse(ASK).allow.unknownRecipients, 'ask');
  });

  it('refuses ask without passkey approvals, because the CLI can be driven by an agent', () => {
    assert.throws(
      () => parse({ unknownRecipients: 'ask' }),
      /needs limits.approval_threshold.method: passkey/,
    );
    assert.throws(
      () => parse({ unknownRecipients: 'ask', approval: null }),
      /needs limits.approval_threshold.method: passkey/,
    );
  });
});

describe('new recipients', () => {
  it('are still denied when the policy does not ask', async () => {
    const env = makeEnv({ approval: '0.50', approvalMethod: 'passkey' });
    try {
      const r = await sign(env, stranger('s1'));
      assert.equal(r.body['status'], 'denied');
      assert.equal(r.body['reason'], 'recipient_not_allowed');
    } finally {
      cleanup(env);
    }
  });

  it('need a passkey even below the threshold, and the page names the service', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      assert.equal(r.status, 202);
      assert.equal(r.body['status'], 'pending');
      assert.equal(r.body['reason'], 'new_recipient');
      const id = r.body['approvalId'] as string;
      assert.equal(s.env.app.resolveApproval(id, 'approved'), false);
      assert.equal(
        resolveApproval(s.env.ledger, s.env.audit, id, 'approved', {
          method: 'passkey',
          now: s.env.clock.now,
        }),
        'passkey_required',
      );
      const page = await http(s.port, `/approve/${id}`);
      assert.equal(page.status, 200);
      assert.match(page.text, /New service wants to be paid/);
      assert.match(page.text, /crypto\.apitoll\.cloud/);
      assert.match(page.text, /Always allow this service/);
      assert.match(page.text, /"remember":/);
    } finally {
      s.close();
    }
  });

  it('allow once pays this request only', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      const ok = await decideWithPasskey(
        s,
        r.body['approvalId'] as string,
        'approved',
      );
      assert.equal(ok.status, 200, ok.text);
      assert.equal(
        (await sign(s.env, stranger('s1'))).body['status'],
        'signed',
      );
      const next = await sign(s.env, stranger('s2'));
      assert.equal(next.body['status'], 'pending');
      assert.equal(next.body['reason'], 'new_recipient');
      assert.equal(s.env.ledger.listLearnedRecipients().length, 0);
    } finally {
      s.close();
    }
  });

  it('always allow adds the recipient, and later payments follow the normal rules', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      const id = r.body['approvalId'] as string;
      const ok = await decideWithPasskey(s, id, 'remember');
      assert.equal(ok.status, 200, ok.text);
      assert.equal(
        (await sign(s.env, stranger('s1'))).body['status'],
        'signed',
      );

      const learned = s.env.ledger.listLearnedRecipients();
      assert.equal(learned.length, 1);
      assert.equal(learned[0]?.address, STRANGER);
      assert.equal(learned[0]?.chain, 'eip155:8453');
      assert.equal(learned[0]?.label, 'crypto.apitoll.cloud (unverified)');
      assert.equal(learned[0]?.credential, 'laptop');

      assert.equal(
        (await sign(s.env, stranger('s2'))).body['status'],
        'signed',
      );
      const big = await sign(s.env, stranger('s3', usdc(0.7)));
      assert.equal(big.body['status'], 'pending');
      assert.equal(big.body['reason'], 'threshold');
      const over = await sign(s.env, stranger('s4', usdc(1.5)));
      assert.equal(over.body['reason'], 'per_tx_limit');

      const budget = s.env.app.budget('nanocode').body as {
        recipients: { address: string; label: string | null }[];
      };
      assert.ok(
        budget.recipients.some(
          (x) =>
            x.address === STRANGER &&
            x.label === 'crypto.apitoll.cloud (unverified)',
        ),
      );
      const added = auditEvents(s.env).find(
        (e) => e['event'] === 'recipient_added',
      );
      assert.equal(added?.['recipient'], STRANGER);
      assert.equal(added?.['via'], 'passkey');
    } finally {
      s.close();
    }
  });

  it('a learned recipient is only allowed on the chain it was approved for', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      await decideWithPasskey(s, r.body['approvalId'] as string, 'remember');
      const other = await sign(
        s.env,
        x402Body({
          payTo: STRANGER,
          amount: usdc(0.01),
          network: 'eip155:4217',
          asset: PATHUSD,
          key: 'tempo',
        }),
      );
      assert.equal(other.body['status'], 'pending', JSON.stringify(other.body));
      assert.equal(other.body['reason'], 'new_recipient');
    } finally {
      s.close();
    }
  });

  it('remember cannot be used on an ordinary threshold approval', async () => {
    const s = await start();
    try {
      const r = await sign(
        s.env,
        x402Body({ payTo: MERCHANT, amount: usdc(0.7), key: 'm' }),
      );
      assert.equal(r.body['reason'], 'threshold');
      const id = r.body['approvalId'] as string;
      const page = await http(s.port, `/approve/${id}`);
      assert.doesNotMatch(page.text, /Always allow/);
      const res = await decideWithPasskey(s, id, 'remember');
      assert.equal(res.status, 400);
      assert.match(res.text, /remember_not_allowed/);
      assert.equal(s.env.ledger.getApproval(id)?.status, 'pending');
    } finally {
      s.close();
    }
  });

  it('a signature for allow once cannot be replayed as always allow', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      const id = r.body['approvalId'] as string;
      const row = s.env.ledger.getApproval(id);
      assert.ok(row);
      const body = s.auth.assert({
        challenge: approvalChallenge(id, row.intentJson, 'approved'),
        origin: s.origin,
        decision: 'remember',
      });
      const res = await http(s.port, `/approve/${id}`, {
        method: 'POST',
        body,
      });
      assert.equal(res.status, 403);
      assert.equal(s.env.ledger.listLearnedRecipients().length, 0);
    } finally {
      s.close();
    }
  });

  it('chain and asset rules still apply to new recipients', async () => {
    const s = await start();
    try {
      const chain = await sign(
        s.env,
        x402Body({ payTo: STRANGER, network: 'eip155:1', key: 'c' }),
      );
      assert.equal(chain.body['reason'], 'chain_not_allowed');
      const asset = await sign(
        s.env,
        x402Body({
          payTo: STRANGER,
          asset: '0x4444444444444444444444444444444444444444',
          key: 'a',
        }),
      );
      assert.equal(asset.body['reason'], 'asset_not_allowed');
    } finally {
      s.close();
    }
  });

  it('removing a learned recipient makes the next payment ask again', async () => {
    const s = await start();
    try {
      const r = await sign(s.env, stranger('s1'));
      await decideWithPasskey(s, r.body['approvalId'] as string, 'remember');
      assert.equal(s.env.ledger.removeLearnedRecipient(STRANGER), 1);
      const again = await sign(s.env, stranger('s2'));
      assert.equal(again.body['reason'], 'new_recipient');
    } finally {
      s.close();
    }
  });
});
