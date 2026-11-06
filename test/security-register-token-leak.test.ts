import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { randomBytes } from '@noble/hashes/utils.js';
import { startRegistration } from '../src/approval/register.ts';
import { http, softAuthenticator } from './fixtures/authenticator.ts';
import { cleanup, makeEnv } from './helpers.ts';

function challengeOf(text: string): Uint8Array {
  const cfg = JSON.parse(
    /<script type="application\/json" id="cfg">(.*?)<\/script>/s.exec(
      text,
    )?.[1] ?? '{}',
  ) as { challenge: string };
  return new Uint8Array(Buffer.from(cfg.challenge, 'base64url'));
}

// An agent that learned the one-time URL (argv of `open`/xdg-open, browser
// history) must not be able to register its own passkey after the operator's
// browser has loaded the page.
describe('audit: leaked registration URL', () => {
  it('a second client with the URL cannot read the challenge or register', async () => {
    const env = makeEnv();
    const session = await startRegistration({
      ledger: env.ledger,
      name: 'laptop',
      userVerification: 'required',
    });
    try {
      const url = new URL(session.url);
      const port = Number(url.port);
      const origin = `http://localhost:${port}`;

      // Operator's browser opens the link.
      const human = await http(port, url.pathname);
      assert.equal(human.status, 200);

      // Agent replays the leaked URL: it must not get the challenge.
      const leaked = await http(port, url.pathname);
      assert.notEqual(leaked.status, 200, 'second GET served the challenge');

      // Without the challenge the agent's own registration fails.
      const attacker = softAuthenticator();
      const post = await http(port, url.pathname, {
        method: 'POST',
        body: attacker.register({
          challenge:
            leaked.status === 200 ? challengeOf(leaked.text) : randomBytes(32),
          origin,
        }),
      });
      assert.notEqual(post.status, 200, 'attacker registration accepted');
      assert.equal(
        env.ledger
          .listPasskeys()
          .some((p) => p.credentialId === attacker.credentialId),
        false,
      );

      // The operator's browser still completes.
      const op = softAuthenticator();
      const ok = await http(port, url.pathname, {
        method: 'POST',
        body: op.register({ challenge: challengeOf(human.text), origin }),
      });
      assert.equal(ok.status, 200);
      // ...and the operator types the code their page showed into the terminal.
      const { code } = JSON.parse(ok.text) as { code: string };
      assert.equal(session.confirm(code), true);
      assert.equal((await session.done).credentialId, op.credentialId);
    } finally {
      session.close();
      cleanup(env);
    }
  });
});
