import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { describe, it } from 'node:test';
import { startRegistration } from '../src/approval/register.ts';
import { approvalChallenge } from '../src/approval/passkey.ts';
import { http, softAuthenticator } from './fixtures/authenticator.ts';
import { cleanup, makeEnv, sign, STRANGER, usdc, x402Body } from './helpers.ts';

// An unprivileged same-user process tries to take [::1]:<port> while bursar
// holds 127.0.0.1:<port>. Returns the squatting server, or null when the OS
// refused the bind (the secure outcome).
function squat(port: number, seen: string[]): Promise<Server | null> {
  const s = createServer((req, res) => {
    seen.push(req.url ?? '');
    res.writeHead(200, { 'content-type': 'text/html' }).end('attacker page');
  });
  return new Promise((resolve, reject) => {
    s.once('error', (e: NodeJS.ErrnoException) => {
      if (e.code === 'EADDRINUSE') resolve(null);
      else if (e.code === 'EADDRNOTAVAIL' || e.code === 'EAFNOSUPPORT')
        reject(new Error(`no IPv6 loopback here: ${e.code}`));
      else reject(e);
    });
    s.listen(port, '::1', () => resolve(s));
  });
}

// What a browser does: resolve "localhost" and connect to the first answer.
function getLocalhost(port: number, path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = request({ host: 'localhost', port, path }, (res) => {
      let t = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => (t += c));
      res.on('end', () => resolve(t));
    });
    r.on('error', reject);
    r.end();
  });
}

describe('audit: http://localhost approval origin vs 127.0.0.1-only bind', () => {
  it('a local process cannot capture http://localhost:<port>/approve/... and turn the human touch into a remember for its own payment', async () => {
    const env = makeEnv({
      approval: '0.50',
      approvalMethod: 'passkey',
      unknownRecipients: 'ask',
    });
    // Daemon as in production: policy.server.host (default 127.0.0.1).
    const { server, port } = await env.app.listen(0);
    const origin = `http://localhost:${port}`;
    const auth = softAuthenticator();
    const { verifyRegistration, parseRegistrationBody } =
      await import('../src/approval/passkey.ts');
    const { randomBytes } = await import('@noble/hashes/utils.js');
    const ch = randomBytes(32);
    env.ledger.addPasskey(
      {
        ...verifyRegistration(
          parseRegistrationBody(auth.register({ challenge: ch, origin })),
          { challenge: ch, origin, userVerification: 'required' },
        ),
        name: 'laptop',
      },
      env.clock.now(),
    );
    const seen: string[] = [];
    let evil: Server | null = null;
    let badId = '';
    try {
      // Benign approval the human is about to open.
      const ok = await sign(env, x402Body({ amount: usdc(0.7), key: 'ok' }));
      const okUrl = ok.body['approvalUrl'] as string;
      assert.equal(
        okUrl,
        `${origin}/approve/${ok.body['approvalId'] as string}`,
      );
      // The agent's own payment to an unknown address.
      const bad = await sign(
        env,
        x402Body({ amount: usdc(0.1), payTo: STRANGER, key: 'evil' }),
      );
      assert.equal(bad.body['status'], 'pending');
      badId = bad.body['approvalId'] as string;

      evil = await squat(port, seen);
      // Human's browser opens the benign link.
      const page = await getLocalhost(port, new URL(okUrl).pathname);
      assert.equal(
        seen.length,
        0,
        `browser request for ${okUrl} reached the [::1] squatter, not bursar`,
      );
      assert.notEqual(page, 'attacker page');
      assert.equal(evil, null, 'bind of [::1]:<port> must be refused');
    } catch (e) {
      // Show the full path when vulnerable: the captured touch yields a valid
      // 'remember' assertion for the agent's own approval.
      if (evil !== null && seen.length > 0) {
        const id = badId;
        const row = env.ledger.getApproval(id);
        assert.ok(row);
        const body = auth.assert({
          challenge: approvalChallenge(id, row.intentJson, 'remember'),
          origin,
          decision: 'remember',
        });
        const r = await http(port, `/approve/${id}`, {
          method: 'POST',
          body,
          headers: { origin },
        });
        const learned = env.ledger
          .listLearnedRecipients()
          .map((x: { address: string }) => x.address.toLowerCase());
        throw new Error(
          `${(e as Error).message}; captured page path=${seen[0]}; replayed remember -> ${r.status} ${r.text}; learned=${JSON.stringify(learned)}`,
        );
      }
      throw e;
    } finally {
      evil?.close();
      server.close();
      cleanup(env);
    }
  });

  it('a local process cannot capture the one-time registration URL', async () => {
    const env = makeEnv({ approvalMethod: 'passkey' });
    const reg = await startRegistration({
      ledger: env.ledger,
      name: 'laptop',
      userVerification: 'required',
    });
    const u = new URL(reg.url);
    const seen: string[] = [];
    let evil: Server | null = null;
    try {
      evil = await squat(Number(u.port), seen);
      await getLocalhost(Number(u.port), u.pathname).catch(() => '');
      assert.deepEqual(
        seen,
        [],
        'registration token leaked to the [::1] squatter',
      );
      assert.equal(evil, null, 'bind of [::1]:<port> must be refused');
    } finally {
      evil?.close();
      reg.close();
      cleanup(env);
    }
  });
});
