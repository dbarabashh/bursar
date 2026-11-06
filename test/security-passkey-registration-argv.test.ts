import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';
import { startRegistration } from '../src/approval/register.ts';
import { http, softAuthenticator } from './fixtures/authenticator.ts';
import {
  decideWithPasskey,
  sign,
  startWithPasskey,
  usdc,
  x402Body,
} from './helpers.ts';

// setup.ts openUrl() runs `/usr/bin/open <url>` (or xdg-open / cmd start)
// with the one-time registration URL in argv. Any process that can list
// argv (the agent, as the same user) learns the secret and can register its
// own software passkey before the operator presses "Create passkey".
describe('audit: passkey registration URL in argv', () => {
  it('a process that reads the URL from ps cannot register a passkey', async () => {
    const s = await startWithPasskey({
      approval: '0.50',
      approvalMethod: 'passkey',
    });
    const session = await startRegistration({
      ledger: s.env.ledger,
      name: 'laptop',
      userVerification: 'required',
    });
    // Stand-in for `/usr/bin/open <url>`: the URL is in this process's argv.
    const opener = spawn(
      process.execPath,
      ['-e', 'setTimeout(() => {}, 10000)', session.url],
      { stdio: 'ignore' },
    );
    try {
      await new Promise((r) => setTimeout(r, 300));
      // The agent: list every process's argv and grep for the token.
      const ps = spawnSync('ps', ['-axo', 'args'], { encoding: 'utf8' });
      const m = /http:\/\/localhost:(\d+)(\/[A-Za-z0-9_-]{32})/.exec(ps.stdout);
      assert.ok(m, 'registration URL visible in ps output');
      const port = Number(m[1]);
      const path = m[2]!;
      const page = await http(port, path);
      const cfg = JSON.parse(
        /<script type="application\/json" id="cfg">(.*?)<\/script>/s.exec(
          page.text,
        )?.[1] ?? '{}',
      ) as { challenge: string };
      const challenge = new Uint8Array(Buffer.from(cfg.challenge, 'base64url'));
      const evil = softAuthenticator();
      await http(port, path, {
        method: 'POST',
        body: evil.register({ challenge, origin: `http://localhost:${port}` }),
      });

      // Impact check: with the stolen registration the agent approves its
      // own payment above the threshold.
      const r = await sign(s.env, x402Body({ amount: usdc(0.9) }));
      const id = String(r.body['approvalId'] ?? r.body['id'] ?? '');
      let approvedByAgent = false;
      if (r.status === 202 && id !== '') {
        const real = s.auth;
        s.auth = evil;
        const d = await decideWithPasskey(s, id, 'approved');
        s.auth = real;
        approvedByAgent = d.status === 200;
      }

      assert.equal(
        s.env.ledger.getPasskey(evil.credentialId),
        null,
        'attacker passkey was stored by the registration server',
      );
      assert.equal(approvedByAgent, false, 'agent approved its own payment');
    } finally {
      opener.kill();
      session.close();
      s.close();
    }
  });
});
