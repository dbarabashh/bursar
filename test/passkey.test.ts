import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { randomBytes } from '@noble/hashes/utils.js';
import { startRegistration } from '../src/approval/register.ts';
import {
  approvalChallenge,
  parseAssertionBody,
  parseRegistrationBody,
  PasskeyError,
  verifyAssertion,
  verifyRegistration,
  type Expectation,
  type PasskeyCredential,
} from '../src/approval/passkey.ts';
import { resolveApproval } from '../src/approval/resolve.ts';
import { http, softAuthenticator } from './fixtures/authenticator.ts';
import {
  auditEvents,
  cleanup,
  makeEnv,
  sign,
  startWithPasskey,
  usdc,
  x402Body,
  type TestEnv,
} from './helpers.ts';

const ORIGIN = 'http://localhost:8402';

function reason(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof PasskeyError) return e.reason;
    throw e;
  }
  return 'ok';
}

function registered(auth = softAuthenticator()): {
  auth: ReturnType<typeof softAuthenticator>;
  cred: PasskeyCredential;
} {
  const challenge = randomBytes(32);
  const cred = verifyRegistration(
    parseRegistrationBody(auth.register({ challenge, origin: ORIGIN })),
    { challenge, origin: ORIGIN, userVerification: 'required' },
  );
  return { auth, cred: { ...cred, name: 'test' } };
}

describe('passkey registration', () => {
  it('accepts a valid ES256 registration and extracts the public key', () => {
    const auth = softAuthenticator();
    const challenge = randomBytes(32);
    const cred = verifyRegistration(
      parseRegistrationBody(auth.register({ challenge, origin: ORIGIN })),
      { challenge, origin: ORIGIN, userVerification: 'required' },
    );
    assert.equal(cred.credentialId, auth.credentialId);
    assert.deepEqual(cred.publicKey, auth.spki.slice(26));
  });

  it('rejects registrations that do not match what the operator started', () => {
    const auth = softAuthenticator();
    const challenge = randomBytes(32);
    const exp: Expectation = {
      challenge,
      origin: ORIGIN,
      userVerification: 'required',
    };
    const check = (o: Partial<Parameters<typeof auth.register>[0]>) =>
      reason(() =>
        verifyRegistration(
          parseRegistrationBody(
            auth.register({ challenge, origin: ORIGIN, ...o }),
          ),
          exp,
        ),
      );
    assert.equal(check({ challenge: randomBytes(32) }), 'challenge_mismatch');
    assert.equal(check({ origin: 'http://localhost:9999' }), 'origin_mismatch');
    assert.equal(check({ origin: 'https://evil.example' }), 'origin_mismatch');
    assert.equal(check({ rpId: 'evil.example' }), 'rp_id_mismatch');
    assert.equal(check({ type: 'webauthn.get' }), 'client_data_type_mismatch');
    assert.equal(check({ flags: 0x44 }), 'user_not_present');
    assert.equal(check({ flags: 0x41 }), 'user_not_verified');
    assert.equal(check({ flags: 0x05 }), 'attested_credential_missing');
    assert.equal(check({ algorithm: -8 }), 'algorithm_not_supported');
    assert.equal(
      check({ publicKey: softAuthenticator().spki }),
      'public_key_mismatch',
    );
    assert.equal(check({ corruptCose: 'x' }), 'public_key_mismatch');
    assert.equal(check({ corruptCose: 'y' }), 'public_key_mismatch');
    assert.equal(
      check({ publicKey: new Uint8Array(91) }),
      'public_key_not_p256',
    );
    assert.equal(
      check({ credentialId: softAuthenticator().credentialId }),
      'credential_id_mismatch',
    );
  });
});

describe('passkey assertion', () => {
  const intentJson =
    '{"amount":"700000","recipient":"0x1111111111111111111111111111111111111111"}';
  const exp = (
    decision: 'approved' | 'denied' = 'approved',
    id = 'apr_000000000000000000000001',
  ): Expectation => ({
    challenge: approvalChallenge(id, intentJson, decision),
    origin: ORIGIN,
    userVerification: 'required',
  });

  it('verifies a valid assertion, including high-S signatures that real authenticators produce', () => {
    const { auth, cred } = registered();
    const a1 = parseAssertionBody(
      auth.assert({ challenge: exp().challenge, origin: ORIGIN }),
    ).assertion;
    assert.equal(verifyAssertion(cred, a1, exp()), 1);
    const a2 = parseAssertionBody(
      auth.assert({ challenge: exp().challenge, origin: ORIGIN, highS: true }),
    ).assertion;
    assert.equal(verifyAssertion({ ...cred, signCount: 1 }, a2, exp()), 2);
  });

  it('binds the signature to the approval id, decision and intent', () => {
    const { auth, cred } = registered();
    const approveSig = parseAssertionBody(
      auth.assert({ challenge: exp('approved').challenge, origin: ORIGIN }),
    ).assertion;
    assert.equal(
      reason(() => verifyAssertion(cred, approveSig, exp('denied'))),
      'challenge_mismatch',
    );
    assert.equal(
      reason(() =>
        verifyAssertion(
          cred,
          approveSig,
          exp('approved', 'apr_000000000000000000000002'),
        ),
      ),
      'challenge_mismatch',
    );
    const otherIntent = {
      ...exp(),
      challenge: approvalChallenge(
        'apr_000000000000000000000001',
        intentJson.replace('700000', '9000000'),
        'approved',
      ),
    };
    assert.equal(
      reason(() => verifyAssertion(cred, approveSig, otherIntent)),
      'challenge_mismatch',
    );
  });

  it('rejects wrong origin, rp id, flags, tampering, foreign keys and counter rollback', () => {
    const { auth, cred } = registered();
    const c = exp().challenge;
    const check = (
      o: Partial<Parameters<typeof auth.assert>[0]>,
      e: Expectation = exp(),
      k: PasskeyCredential = cred,
    ) =>
      reason(() =>
        verifyAssertion(
          k,
          parseAssertionBody(
            auth.assert({ challenge: c, origin: ORIGIN, ...o }),
          ).assertion,
          e,
        ),
      );
    assert.equal(check({ origin: 'http://127.0.0.1:8402' }), 'origin_mismatch');
    assert.equal(check({ crossOrigin: true }), 'cross_origin_not_allowed');
    assert.equal(check({ rpId: 'example.com' }), 'rp_id_mismatch');
    assert.equal(
      check({ type: 'webauthn.create' }),
      'client_data_type_mismatch',
    );
    assert.equal(check({ flags: 0x04 }), 'user_not_present');
    assert.equal(check({ flags: 0x01 }), 'user_not_verified');
    assert.equal(
      check({ flags: 0x01 }, { ...exp(), userVerification: 'preferred' }),
      'ok',
    );
    assert.equal(check({ tamper: true }), 'signature_invalid');
    const other = registered().cred;
    assert.equal(
      check({}, exp(), { ...other, credentialId: cred.credentialId }),
      'signature_invalid',
    );
    assert.equal(
      check({}, exp(), { ...cred, signCount: 100 }),
      'sign_count_regressed',
    );
    assert.equal(
      check({ keepCount: true }, exp(), { ...cred, signCount: 1000 }),
      'sign_count_regressed',
    );
  });

  it('allows authenticators that always report a zero counter', () => {
    const { auth, cred } = registered(softAuthenticator(0));
    const a = parseAssertionBody(
      auth.assert({
        challenge: exp().challenge,
        origin: ORIGIN,
        keepCount: true,
      }),
    ).assertion;
    assert.equal(verifyAssertion(cred, a, exp()), 0);
  });
});

describe('passkey approval flow over HTTP', () => {
  const start = () =>
    startWithPasskey({ approval: '0.50', approvalMethod: 'passkey' });

  async function pending(
    env: TestEnv,
    key: string,
  ): Promise<{ id: string; url: string }> {
    const r = await sign(env, x402Body({ amount: usdc(0.7), key }));
    assert.equal(r.body['status'], 'pending');
    return {
      id: r.body['approvalId'] as string,
      url: r.body['approvalUrl'] as string,
    };
  }

  it('signs only after a passkey approval, and the CLI cannot approve', async () => {
    const { env, port, auth, close } = await start();
    try {
      const { id, url } = await pending(env, 'big');
      assert.equal(url, `http://localhost:${port}/approve/${id}`);
      assert.equal(env.app.resolveApproval(id, 'approved'), false);
      assert.equal(
        resolveApproval(env.ledger, env.audit, id, 'approved', {
          method: 'passkey',
          now: env.clock.now,
        }),
        'passkey_required',
      );

      const page = await http(port, `/approve/${id}`);
      assert.equal(page.status, 200);
      assert.match(
        String(page.headers['content-security-policy']),
        /script-src 'nonce-[A-Za-z0-9_-]+'/,
      );
      assert.equal(page.headers['x-frame-options'], 'DENY');
      assert.match(page.text, /\$0\.70/);

      const approval = env.ledger.getApproval(id);
      assert.ok(approval);
      const body = auth.assert({
        challenge: approvalChallenge(id, approval.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      const ok = await http(port, `/approve/${id}`, { method: 'POST', body });
      assert.equal(ok.status, 200, ok.text);
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.7), key: 'big' }))).body[
          'status'
        ],
        'signed',
      );

      const replay = await http(port, `/approve/${id}`, {
        method: 'POST',
        body,
      });
      assert.equal(replay.status, 409);
      const events = auditEvents(env, 'nanocode');
      const resolved = events.find((e) => e['event'] === 'approval_resolved');
      assert.equal(resolved?.['via'], 'passkey');
      assert.equal(resolved?.['credential'], 'laptop');
    } finally {
      close();
    }
  });

  it('a signature for one approval cannot approve another, and deny works both ways', async () => {
    const { env, port, auth, close } = await start();
    try {
      const a = await pending(env, 'a');
      const b = await pending(env, 'b');
      const aRow = env.ledger.getApproval(a.id);
      assert.ok(aRow);
      const forA = auth.assert({
        challenge: approvalChallenge(a.id, aRow.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      const cross = await http(port, `/approve/${b.id}`, {
        method: 'POST',
        body: forA,
      });
      assert.equal(cross.status, 403);
      assert.equal(JSON.parse(cross.text).error, 'challenge_mismatch');

      const denyAsApprove = {
        ...auth.assert({
          challenge: approvalChallenge(a.id, aRow.intentJson, 'denied'),
          origin: `http://localhost:${port}`,
        }),
        decision: 'approved',
      };
      assert.equal(
        (
          await http(port, `/approve/${a.id}`, {
            method: 'POST',
            body: denyAsApprove,
          })
        ).status,
        403,
      );

      const deny = auth.assert({
        challenge: approvalChallenge(a.id, aRow.intentJson, 'denied'),
        origin: `http://localhost:${port}`,
        decision: 'denied',
      });
      assert.equal(
        (await http(port, `/approve/${a.id}`, { method: 'POST', body: deny }))
          .status,
        200,
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.7), key: 'a' }))).body[
          'reason'
        ],
        'approval_denied',
      );
      assert.equal(env.app.resolveApproval(b.id, 'denied'), true);
      assert.equal(env.ledger.spendCount(), 0);
    } finally {
      close();
    }
  });

  it('rejects unknown credentials, wrong content type, foreign Origin and IP hosts', async () => {
    const { env, port, auth, close } = await start();
    try {
      const { id } = await pending(env, 'x');
      const row = env.ledger.getApproval(id);
      assert.ok(row);
      const stranger = softAuthenticator();
      const strangerBody = stranger.assert({
        challenge: approvalChallenge(id, row.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      assert.equal(
        JSON.parse(
          (
            await http(port, `/approve/${id}`, {
              method: 'POST',
              body: strangerBody,
            })
          ).text,
        ).error,
        'unknown_credential',
      );
      const body = auth.assert({
        challenge: approvalChallenge(id, row.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      assert.equal(
        (
          await http(port, `/approve/${id}`, {
            method: 'POST',
            body,
            headers: { 'content-type': 'text/plain' },
          })
        ).status,
        415,
      );
      assert.equal(
        (
          await http(port, `/approve/${id}`, {
            method: 'POST',
            body,
            headers: { origin: 'https://evil.example' },
          })
        ).status,
        403,
      );
      const viaIp = await http(port, `/approve/${id}`, {
        host: `127.0.0.1:${port}`,
      });
      assert.equal(viaIp.status, 302);
      assert.equal(
        viaIp.headers['location'],
        `http://localhost:${port}/approve/${id}`,
      );
      assert.equal(
        (
          await http(port, `/approve/${id}`, {
            method: 'POST',
            body,
            host: `127.0.0.1:${port}`,
          })
        ).status,
        403,
      );
      assert.equal(
        (await http(port, `/approve/apr_ffffffffffffffffffffffff`)).status,
        404,
      );
      assert.equal(
        (await http(port, `/approve/${id}`, { host: 'evil.example' })).status,
        403,
      );
    } finally {
      close();
    }
  });

  it('persists the signature counter, so a cloned authenticator replaying an old count is refused', async () => {
    const { env, port, auth, close } = await start();
    try {
      const a = await pending(env, 'c1');
      const b = await pending(env, 'c2');
      const aRow = env.ledger.getApproval(a.id);
      const bRow = env.ledger.getApproval(b.id);
      assert.ok(aRow && bRow);
      const first = auth.assert({
        challenge: approvalChallenge(a.id, aRow.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      assert.equal(
        (await http(port, `/approve/${a.id}`, { method: 'POST', body: first }))
          .status,
        200,
      );
      assert.equal(env.ledger.getPasskey(auth.credentialId)?.signCount, 1);
      const cloned = auth.assert({
        challenge: approvalChallenge(b.id, bRow.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
        keepCount: true,
      });
      const r = await http(port, `/approve/${b.id}`, {
        method: 'POST',
        body: cloned,
      });
      assert.equal(r.status, 403);
      assert.equal(JSON.parse(r.text).error, 'sign_count_regressed');
    } finally {
      close();
    }
  });

  it('expired approvals cannot be approved', async () => {
    const { env, port, auth, close } = await start();
    try {
      const { id } = await pending(env, 'late');
      const row = env.ledger.getApproval(id);
      assert.ok(row);
      env.clock.advance(61_000);
      const body = auth.assert({
        challenge: approvalChallenge(id, row.intentJson, 'approved'),
        origin: `http://localhost:${port}`,
      });
      assert.equal(
        (await http(port, `/approve/${id}`, { method: 'POST', body })).status,
        409,
      );
      assert.equal(
        (await sign(env, x402Body({ amount: usdc(0.7), key: 'late' }))).body[
          'reason'
        ],
        'approval_timeout',
      );
    } finally {
      close();
    }
  });

  it('approval pages do not exist in cli mode', async () => {
    const env = makeEnv({ approval: '0.50' });
    const { server, port } = await env.app.listen(0, '127.0.0.1');
    try {
      const r = await sign(env, x402Body({ amount: usdc(0.7) }));
      assert.equal(r.body['approvalUrl'], undefined);
      assert.equal(
        (await http(port, `/approve/${r.body['approvalId'] as string}`)).status,
        404,
      );
    } finally {
      server.close();
      cleanup(env);
    }
  });
});

describe('passkey registration server', () => {
  it('serves a one-time page on a secret path and stores the credential', async () => {
    const env = makeEnv();
    try {
      const session = await startRegistration({
        ledger: env.ledger,
        name: 'laptop',
        userVerification: 'required',
      });
      const url = new URL(session.url);
      const port = Number(url.port);
      assert.equal(url.hostname, 'localhost');
      assert.match(url.pathname, /^\/[A-Za-z0-9_-]{32}$/);
      assert.equal((await http(port, '/')).status, 404);
      assert.equal((await http(port, `${url.pathname}x`)).status, 404);
      assert.equal(
        (await http(port, url.pathname, { host: `127.0.0.1:${port}` })).status,
        403,
      );
      const page = await http(port, url.pathname);
      assert.equal(page.status, 200);
      assert.match(
        String(page.headers['content-security-policy']),
        /default-src 'none'/,
      );
      const cfg = JSON.parse(
        /<script type="application\/json" id="cfg">(.*?)<\/script>/s.exec(
          page.text,
        )?.[1] ?? '{}',
      ) as { challenge: string };
      const challenge = new Uint8Array(Buffer.from(cfg.challenge, 'base64url'));

      const auth = softAuthenticator();
      const bad = await http(port, url.pathname, {
        method: 'POST',
        body: auth.register({
          challenge: randomBytes(32),
          origin: `http://localhost:${port}`,
        }),
      });
      assert.equal(JSON.parse(bad.text).error, 'challenge_mismatch');
      const ok = await http(port, url.pathname, {
        method: 'POST',
        body: auth.register({ challenge, origin: `http://localhost:${port}` }),
      });
      assert.equal(ok.status, 200, ok.text);
      // Nothing is stored until the operator types the page's code in the terminal.
      assert.equal(env.ledger.getPasskey(auth.credentialId), null);
      assert.equal(session.confirm('WRONG-CODE'), false);
      const { code } = JSON.parse(ok.text) as { code: string };
      assert.equal(session.confirm(code.toLowerCase()), true);
      const cred = await session.done;
      assert.equal(cred.name, 'laptop');
      assert.equal(env.ledger.getPasskey(auth.credentialId)?.name, 'laptop');
      await assert.rejects(http(port, url.pathname));
      session.close();
    } finally {
      cleanup(env);
    }
  });

  it('cancelling rejects the pending registration', async () => {
    const env = makeEnv();
    try {
      const session = await startRegistration({
        ledger: env.ledger,
        name: 'x',
        userVerification: 'required',
      });
      session.close();
      await assert.rejects(session.done, /cancelled/);
      assert.equal(env.ledger.listPasskeys().length, 0);
    } finally {
      cleanup(env);
    }
  });
});
