import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ctEqual, isRecord } from '../util.ts';

export const RP_ID = 'localhost';
export const ES256 = -7;

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const SPKI_P256_PREFIX = Uint8Array.from(
  Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
);

export type UserVerification = 'required' | 'preferred';

export type PasskeyCredential = {
  credentialId: string;
  publicKey: Uint8Array;
  signCount: number;
  name: string;
};

export type PasskeyAssertion = {
  credentialId: string;
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  signature: Uint8Array;
};

export type PasskeyRegistration = {
  credentialId: string;
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  publicKey: Uint8Array;
  algorithm: number;
};

export type Expectation = {
  challenge: Uint8Array;
  origin: string;
  rpId?: string;
  userVerification: UserVerification;
};

export class PasskeyError extends Error {
  override name = 'PasskeyError';
  readonly reason: string;
  constructor(reason: string) {
    super(reason);
    this.reason = reason;
  }
}

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function fromB64url(v: unknown, field: string): Uint8Array {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]*$/.test(v))
    throw new PasskeyError(`${field}_invalid`);
  return new Uint8Array(Buffer.from(v, 'base64url'));
}

export function approvalChallenge(
  approvalId: string,
  intentJson: string,
  decision: 'approved' | 'denied',
): Uint8Array {
  return sha256(
    utf8ToBytes(
      `bursar-approval:v1|${approvalId}|${decision}|${bytesToHex(sha256(utf8ToBytes(intentJson)))}`,
    ),
  );
}

function checkClientData(
  raw: Uint8Array,
  type: 'webauthn.get' | 'webauthn.create',
  exp: Expectation,
): void {
  let cd: unknown;
  try {
    cd = JSON.parse(Buffer.from(raw).toString('utf8'));
  } catch {
    throw new PasskeyError('client_data_invalid');
  }
  if (!isRecord(cd)) throw new PasskeyError('client_data_invalid');
  if (cd['type'] !== type) throw new PasskeyError('client_data_type_mismatch');
  if (!ctEqual(fromB64url(cd['challenge'], 'challenge'), exp.challenge))
    throw new PasskeyError('challenge_mismatch');
  if (cd['origin'] !== exp.origin) throw new PasskeyError('origin_mismatch');
  if (cd['crossOrigin'] === true)
    throw new PasskeyError('cross_origin_not_allowed');
}

type AuthData = { flags: number; signCount: number; rest: Uint8Array };

function checkAuthenticatorData(data: Uint8Array, exp: Expectation): AuthData {
  if (data.length < 37) throw new PasskeyError('authenticator_data_invalid');
  if (!ctEqual(data.subarray(0, 32), sha256(utf8ToBytes(exp.rpId ?? RP_ID))))
    throw new PasskeyError('rp_id_mismatch');
  const flags = data[32] ?? 0;
  if ((flags & FLAG_UP) === 0) throw new PasskeyError('user_not_present');
  if (exp.userVerification === 'required' && (flags & FLAG_UV) === 0)
    throw new PasskeyError('user_not_verified');
  const signCount = new DataView(
    data.buffer,
    data.byteOffset + 33,
    4,
  ).getUint32(0, false);
  return { flags, signCount, rest: data.subarray(37) };
}

export function parseSpkiP256(spki: Uint8Array): Uint8Array {
  if (
    spki.length !== SPKI_P256_PREFIX.length + 65 ||
    !ctEqual(spki.subarray(0, SPKI_P256_PREFIX.length), SPKI_P256_PREFIX)
  ) {
    throw new PasskeyError('public_key_not_p256');
  }
  const point = spki.slice(SPKI_P256_PREFIX.length);
  try {
    p256.Point.fromBytes(point).assertValidity();
  } catch {
    throw new PasskeyError('public_key_invalid');
  }
  return point;
}

// TODO: not ready yet: a real CBOR decoder; this scans the COSE key for the x/y coordinates.
function coseCoordinate(cose: Uint8Array, label: number): Uint8Array | null {
  for (let i = 0; i + 35 <= cose.length; i++) {
    if (cose[i] === label && cose[i + 1] === 0x58 && cose[i + 2] === 0x20)
      return cose.subarray(i + 3, i + 35);
  }
  return null;
}

// TODO: not ready yet: attestation verification (registration uses attestation "none") and algorithms other than ES256.
export function verifyRegistration(
  reg: PasskeyRegistration,
  exp: Expectation,
): PasskeyCredential {
  if (reg.algorithm !== ES256)
    throw new PasskeyError('algorithm_not_supported');
  checkClientData(reg.clientDataJSON, 'webauthn.create', exp);
  const auth = checkAuthenticatorData(reg.authenticatorData, exp);
  if ((auth.flags & FLAG_AT) === 0 || auth.rest.length < 18)
    throw new PasskeyError('attested_credential_missing');
  const idLen = ((auth.rest[16] ?? 0) << 8) | (auth.rest[17] ?? 0);
  const credId = auth.rest.subarray(18, 18 + idLen);
  if (credId.length !== idLen || b64url(credId) !== reg.credentialId)
    throw new PasskeyError('credential_id_mismatch');
  const point = parseSpkiP256(reg.publicKey);
  const cose = auth.rest.subarray(18 + idLen);
  const x = coseCoordinate(cose, 0x21);
  const y = coseCoordinate(cose, 0x22);
  if (
    x === null ||
    y === null ||
    !ctEqual(x, point.subarray(1, 33)) ||
    !ctEqual(y, point.subarray(33, 65))
  ) {
    throw new PasskeyError('public_key_mismatch');
  }
  return {
    credentialId: reg.credentialId,
    publicKey: point,
    signCount: auth.signCount,
    name: '',
  };
}

export function verifyAssertion(
  cred: PasskeyCredential,
  a: PasskeyAssertion,
  exp: Expectation,
): number {
  if (a.credentialId !== cred.credentialId)
    throw new PasskeyError('credential_mismatch');
  checkClientData(a.clientDataJSON, 'webauthn.get', exp);
  const auth = checkAuthenticatorData(a.authenticatorData, exp);
  const signed = concatBytes(a.authenticatorData, sha256(a.clientDataJSON));
  let ok = false;
  try {
    ok = p256.verify(a.signature, signed, cred.publicKey, {
      format: 'der',
      lowS: false,
      prehash: true,
    });
  } catch {
    ok = false;
  }
  if (!ok) throw new PasskeyError('signature_invalid');
  if (
    (auth.signCount !== 0 || cred.signCount !== 0) &&
    auth.signCount <= cred.signCount
  )
    throw new PasskeyError('sign_count_regressed');
  return auth.signCount;
}

export function parseAssertionBody(body: unknown): {
  decision: 'approved' | 'denied';
  assertion: PasskeyAssertion;
} {
  if (!isRecord(body)) throw new PasskeyError('body_invalid');
  const decision = body['decision'];
  if (decision !== 'approved' && decision !== 'denied')
    throw new PasskeyError('decision_invalid');
  const credentialId = body['credentialId'];
  if (
    typeof credentialId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,1366}$/.test(credentialId)
  )
    throw new PasskeyError('credentialId_invalid');
  return {
    decision,
    assertion: {
      credentialId,
      clientDataJSON: fromB64url(body['clientDataJSON'], 'clientDataJSON'),
      authenticatorData: fromB64url(
        body['authenticatorData'],
        'authenticatorData',
      ),
      signature: fromB64url(body['signature'], 'signature'),
    },
  };
}

export function parseRegistrationBody(body: unknown): PasskeyRegistration {
  if (!isRecord(body)) throw new PasskeyError('body_invalid');
  const credentialId = body['credentialId'];
  if (
    typeof credentialId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,1366}$/.test(credentialId)
  )
    throw new PasskeyError('credentialId_invalid');
  const algorithm = body['algorithm'];
  if (typeof algorithm !== 'number')
    throw new PasskeyError('algorithm_not_supported');
  return {
    credentialId,
    clientDataJSON: fromB64url(body['clientDataJSON'], 'clientDataJSON'),
    authenticatorData: fromB64url(
      body['authenticatorData'],
      'authenticatorData',
    ),
    publicKey: fromB64url(body['publicKey'], 'publicKey'),
    algorithm,
  };
}
