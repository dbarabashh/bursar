import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { AdapterError } from '../src/protocols/common.ts';
import { parseX402 } from '../src/protocols/x402.ts';
import { adapterCtx, x402Body } from './helpers.ts';

const ctx = adapterCtx;

const requested = { method: 'GET', url: 'https://evil.example/data' };

function payloadFor(version: 1 | 2, strip: boolean): unknown {
  const body = x402Body({
    version,
    resourceUrl: 'https://merchant-y.example/x',
  });
  const payload = body['payload'] as Record<string, unknown>;
  const pr = payload['paymentRequired'] as Record<string, unknown>;
  if (strip) {
    if (version === 2) delete pr['resource'];
    else delete (pr['accepts'] as Record<string, unknown>[])[0]!['resource'];
  }
  return payload;
}

const isMismatch = (e: unknown) =>
  e instanceof AdapterError && e.reason === 'resource_hash_mismatch';

describe('x402 resource binding when the 402 omits resource', () => {
  for (const version of [1, 2] as const) {
    it(`v${version}: control - a different resource URL is rejected`, () => {
      assert.throws(
        () =>
          parseX402(payloadFor(version, false), ctx({ resource: requested })),
        isMismatch,
      );
    });
    it(`v${version}: a missing resource must not silently pass the binding check`, () => {
      assert.throws(
        () =>
          parseX402(payloadFor(version, true), ctx({ resource: requested })),
        isMismatch,
      );
    });
  }
  it('without an agent resource, a 402 with no resource still parses', () => {
    const intent = parseX402(payloadFor(1, true), ctx());
    assert.equal(intent.resourceHash, undefined);
  });
});
