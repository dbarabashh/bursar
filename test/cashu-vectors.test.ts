import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { hexToBytes } from '@noble/hashes/utils.js';
import { decodeCbor, encodeCbor } from '../src/cashu/cbor.ts';
import {
  blind,
  hashE,
  hashToCurve,
  keysetIdMatches,
  mintDleq,
  mintSign,
  point,
  unblind,
  verifyBlindDleq,
  verifyProofDleq,
} from '../src/cashu/crypto.ts';
import {
  decodePaymentRequest,
  decodeToken,
  encodePaymentRequestA,
  encodeTokenV4,
} from '../src/cashu/encoding.ts';

// The secp256k1 generator, compressed.
const G = `02${'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'}`;

// Vectors copied from cashubtc/nuts tests/ (NUT-02, NUT-18, NUT-26).
const vectors = JSON.parse(
  readFileSync(
    new URL('./fixtures/cashu-vectors.json', import.meta.url),
    'utf8',
  ),
) as {
  keysets: {
    id: string;
    unit?: string;
    fee?: number | null;
    expiry?: number | null;
    keys: Record<string, string>;
  }[];
  nut18: { json: Record<string, unknown>; encoded: string }[];
  nut26: { json: Record<string, unknown>; encoded: string }[];
};

describe('cashu crypto (NUT-00, NUT-12 vectors)', () => {
  it('hash_to_curve', () => {
    const cases: [string, string][] = [
      [
        '00'.repeat(32),
        '024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725',
      ],
      [
        `${'00'.repeat(31)}01`,
        '022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf',
      ],
      [
        `${'00'.repeat(31)}02`,
        '026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f',
      ],
    ];
    for (const [msg, pt] of cases)
      assert.equal(hashToCurve(hexToBytes(msg)).toHex(true), pt);
  });

  it('blinded messages and signatures', () => {
    // NUT-00 hashes the secret's bytes; these vectors give the bytes as hex.
    const Y = hashToCurve(
      hexToBytes(
        'd341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6',
      ),
    );
    const r = BigInt(
      '0x99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a',
    );
    assert.equal(
      Y.add(point(G).multiply(r)).toHex(true),
      '033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d',
    );
    assert.equal(
      mintSign(
        BigInt(
          '0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f',
        ),
        '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
      ),
      '0398bc70ce8184d27ba89834d19f5199c84443c31131e48d3c1214db24247d005d',
    );
  });

  it('blind, sign and unblind round-trip to k*Y', () => {
    const k = 12345n;
    const r = 999n;
    const { B_, Y } = blind('secret', r);
    const C_ = mintSign(k, B_);
    const K = point(G).multiply(k).toHex(true);
    assert.equal(unblind(C_, r, K), point(Y).multiply(k).toHex(true));
  });

  it('hash_e and DLEQ verification', () => {
    const one = point(`02${'00'.repeat(31)}01`);
    assert.equal(
      Buffer.from(
        hashE(
          one,
          one,
          one,
          point(
            '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
          ),
        ),
      ).toString('hex'),
      'a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e',
    );
    assert.equal(
      verifyBlindDleq(
        '9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9',
        '9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da',
        G,
        '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
        '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
      ),
      true,
    );
    assert.equal(
      verifyProofDleq(
        {
          secret:
            'daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9',
          C: '024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc',
          dleq: {
            e: 'b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4',
            s: '8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8',
            r: 'a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861',
          },
        },
        G,
      ),
      true,
    );
    // The deterministic-nonce vector: a mint's (e, s) must verify.
    assert.equal(
      verifyBlindDleq(
        '2a16ffee280aff3c429045607f9b8e0bf8b35910c44c1b20b9dfaf01b263d7b3',
        '9df27731238334718d120d4f74611a7c668233f988e687ac3fb188f0a34a2dab',
        '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
        '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
        '0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787',
      ),
      true,
    );
    assert.ok(
      hashE(
        point(
          '0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787',
        ),
      ).length === 32,
    );
  });

  it('a DLEQ from our test mint verifies, and a tampered one does not', () => {
    const k = 777n;
    const { B_ } = blind('x', 5n);
    const C_ = mintSign(k, B_);
    const A = point(G).multiply(k).toHex(true);
    const d = mintDleq(k, B_, C_, (n) => new Uint8Array(n).fill(3));
    assert.equal(verifyBlindDleq(d.e, d.s, A, B_, C_), true);
    assert.equal(verifyBlindDleq(d.e, d.s, A, B_, mintSign(k + 1n, B_)), false);
  });
});

describe('cashu keyset ids (NUT-02 vectors)', () => {
  it('recomputes every vector id', () => {
    assert.equal(vectors.keysets.length, 5);
    for (const k of vectors.keysets)
      assert.ok(
        keysetIdMatches(k.id, {
          keys: k.keys,
          unit: k.unit ?? 'sat',
          inputFeePpk: k.fee ?? null,
          finalExpiry: k.expiry ?? null,
        }),
        k.id,
      );
  });

  it('rejects a keyset whose keys were swapped', () => {
    const k = vectors.keysets[2]!;
    const keys = { ...k.keys };
    const [a, b] = Object.keys(keys);
    [keys[a!], keys[b!]] = [keys[b!]!, keys[a!]!];
    assert.equal(
      keysetIdMatches(k.id, {
        keys,
        unit: k.unit ?? 'sat',
        inputFeePpk: k.fee ?? null,
        finalExpiry: k.expiry ?? null,
      }),
      false,
    );
  });
});

describe('cashu payment requests (NUT-18, NUT-26 vectors)', () => {
  const same = (
    got: ReturnType<typeof decodePaymentRequest>,
    want: Record<string, unknown>,
  ) => {
    for (const f of ['i', 'a', 'u', 'd', 's', 'mp'] as const)
      assert.deepEqual(got[f], want[f], f);
    assert.deepEqual(got.m, want['m']);
    const n = want['nut10'] as
      | { k: string; d: string; t?: string[][] }
      | undefined;
    if (n === undefined) assert.equal(got.nut10, undefined);
    else assert.deepEqual(got.nut10, { k: n.k, d: n.d, t: n.t ?? [] });
    assert.equal(got.transports, ((want['t'] as unknown[]) ?? []).length);
  };

  it('decodes every creqA vector', () => {
    assert.ok(vectors.nut18.length >= 5);
    for (const v of vectors.nut18)
      same(decodePaymentRequest(v.encoded), v.json);
  });

  it('decodes every creqB vector', () => {
    assert.ok(vectors.nut26.length >= 10);
    for (const v of vectors.nut26)
      same(decodePaymentRequest(v.encoded), v.json);
  });

  it('round-trips a NUT-24 request through our encoder', () => {
    const s = encodePaymentRequestA({
      a: 21,
      u: 'sat',
      m: ['http://127.0.0.1:3338'],
      nut10: { k: 'P2PK', d: `02${'11'.repeat(32)}`, t: [] },
    });
    const d = decodePaymentRequest(s);
    assert.equal(d.a, 21);
    assert.deepEqual(d.m, ['http://127.0.0.1:3338']);
    assert.equal(d.nut10?.k, 'P2PK');
  });

  it('rejects garbage', () => {
    assert.throws(() => decodePaymentRequest('lnbc1...'));
    assert.throws(() => decodePaymentRequest('creqAAAAA'));
    assert.throws(() => decodePaymentRequest('creqb1qqqqqqq'));
  });
});

describe('cashu tokens (NUT-00)', () => {
  const V4 =
    'cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNjZjE4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWCECRFODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKjYWECYXN4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNzA4ZWIwZDYxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1XN6RBT6w659lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZmY4YjQ0MDJiMTc2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJjY8MzxWyvwObQGr5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA';

  it('decodes the spec V4 token', () => {
    const t = decodeToken(V4);
    assert.equal(t.mint, 'http://localhost:3338');
    assert.equal(t.unit, 'sat');
    assert.deepEqual(
      t.proofs.map((p) => [p.id, p.amount]),
      [
        ['00ffd48b8f5ecf80', 1],
        ['00ad268c4d1f5826', 2],
        ['00ad268c4d1f5826', 1],
      ],
    );
  });

  it('re-encodes it to the same token', () => {
    const t = decodeToken(V4);
    assert.deepEqual(decodeToken(encodeTokenV4(t)), t);
  });

  it('cbor round-trips nested values', () => {
    const v = {
      a: 1,
      b: [true, null, 'x', new Uint8Array([1, 2])],
      c: { d: -5, e: 70000 },
    };
    assert.deepEqual(decodeCbor(encodeCbor(v)), v);
  });
});
