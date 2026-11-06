// The "service" headline on a new-recipient approval page comes from the
// resource URL in the agent-forwarded 402 (or the agent's own `resource`),
// which nothing ties to the payTo address. A page must not present that host
// as the identity of who gets paid: the recipient address is the only thing
// bursar actually checked, and the host must be marked as unverified.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { http } from './fixtures/authenticator.ts';
import { sign, startWithPasskey, STRANGER, usdc, x402Body } from './helpers.ts';

describe('new-recipient approval page', () => {
  it('does not headline an agent-chosen host as the service being paid', async () => {
    const s = await startWithPasskey({
      approval: '0.50',
      approvalMethod: 'passkey',
      unknownRecipients: 'ask',
    });
    try {
      // The agent (POST /v1/sign) controls both the 402 and `resource`.
      const r = await sign(
        s.env,
        x402Body({
          payTo: STRANGER,
          amount: usdc(0.01),
          key: 'spoof',
          resourceUrl: 'https://api.openai.com/v1/responses',
          resource: {
            method: 'GET',
            url: 'https://api.openai.com/v1/responses',
          },
        }),
      );
      assert.equal(r.body['status'], 'pending', JSON.stringify(r.body));
      assert.equal(r.body['reason'], 'new_recipient');
      const page = await http(s.port, `/approve/${r.body['approvalId']}`);
      assert.equal(page.status, 200);
      const headline = /<p class="service">([^<]*)<\/p>/.exec(page.text)?.[1];
      assert.notEqual(
        headline,
        'api.openai.com',
        'page headlines the agent-supplied host as the service',
      );
      assert.equal(headline, STRANGER);
      assert.match(page.text, /not verified/i);
    } finally {
      s.close();
    }
  });
});
