import { request } from 'node:http';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { b64url } from '../../src/approval/passkey.ts';

const SPKI_PREFIX = Uint8Array.from(
  Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
);

export type SoftAuthenticator = ReturnType<typeof softAuthenticator>;

export function softAuthenticator(start = 0) {
  const sk = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(sk, false);
  const credId = randomBytes(16);
  let count = start;
  const x = pub.subarray(1, 33);
  const y = pub.subarray(33, 65);
  const cose = concatBytes(
    Uint8Array.from([
      0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
    ]),
    x,
    Uint8Array.from([0x22, 0x58, 0x20]),
    y,
  );

  function authData(
    rpId: string,
    flags: number,
    attested: boolean,
    coseOverride?: Uint8Array,
  ): Uint8Array {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, count, false);
    const head = concatBytes(
      sha256(utf8ToBytes(rpId)),
      Uint8Array.from([flags]),
      c,
    );
    if (!attested) return head;
    return concatBytes(
      head,
      new Uint8Array(16),
      Uint8Array.from([credId.length >> 8, credId.length & 0xff]),
      credId,
      coseOverride ?? cose,
    );
  }

  function clientData(
    type: string,
    challenge: Uint8Array,
    origin: string,
    crossOrigin = false,
  ): Uint8Array {
    return utf8ToBytes(
      JSON.stringify({
        type,
        challenge: b64url(challenge),
        origin,
        crossOrigin,
      }),
    );
  }

  return {
    credentialId: b64url(credId),
    spki: concatBytes(SPKI_PREFIX, pub),
    register(o: {
      challenge: Uint8Array;
      origin: string;
      rpId?: string;
      flags?: number;
      type?: string;
      publicKey?: Uint8Array;
      algorithm?: number;
      credentialId?: string;
      corruptCose?: 'x' | 'y';
    }) {
      let coseOverride: Uint8Array | undefined;
      if (o.corruptCose !== undefined) {
        coseOverride = cose.slice();
        const at = o.corruptCose === 'x' ? 10 : 45;
        coseOverride[at] = (coseOverride[at] ?? 0) ^ 0x01;
      }
      return {
        credentialId: o.credentialId ?? b64url(credId),
        clientDataJSON: b64url(
          clientData(o.type ?? 'webauthn.create', o.challenge, o.origin),
        ),
        authenticatorData: b64url(
          authData(o.rpId ?? 'localhost', o.flags ?? 0x45, true, coseOverride),
        ),
        publicKey: b64url(o.publicKey ?? concatBytes(SPKI_PREFIX, pub)),
        algorithm: o.algorithm ?? -7,
      };
    },
    assert(o: {
      challenge: Uint8Array;
      origin: string;
      decision?: 'approved' | 'denied' | 'remember';
      rpId?: string;
      flags?: number;
      type?: string;
      crossOrigin?: boolean;
      highS?: boolean;
      keepCount?: boolean;
      tamper?: boolean;
    }) {
      if (!o.keepCount) count++;
      const ad = authData(o.rpId ?? 'localhost', o.flags ?? 0x05, false);
      const cd = clientData(
        o.type ?? 'webauthn.get',
        o.challenge,
        o.origin,
        o.crossOrigin ?? false,
      );
      const compact = p256.sign(concatBytes(ad, sha256(cd)), sk, {
        prehash: true,
      });
      let sig = p256.Signature.fromBytes(compact);
      if (o.highS)
        sig = new p256.Signature(sig.r, p256.Point.CURVE().n - sig.s);
      if (o.tamper) ad[33] = (ad[33] ?? 0) ^ 0xff;
      return {
        decision: o.decision ?? 'approved',
        credentialId: b64url(credId),
        clientDataJSON: b64url(cd),
        authenticatorData: b64url(ad),
        signature: b64url(sig.toBytes('der')),
      };
    },
  };
}

export function http(
  port: number,
  path: string,
  o: {
    method?: string;
    host?: string;
    body?: unknown;
    headers?: Record<string, string>;
  } = {},
): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
  text: string;
}> {
  return new Promise((resolve, reject) => {
    const body = o.body === undefined ? undefined : JSON.stringify(o.body);
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: o.method ?? 'GET',
        headers: {
          host: o.host ?? `localhost:${port}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(o.headers ?? {}),
        },
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => {
          text += c;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, text }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}
