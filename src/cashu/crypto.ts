// Cashu cryptography on secp256k1 (NUT-00 BDHKE, NUT-02 keyset ids, NUT-11
// P2PK witnesses, NUT-12 DLEQ, NUT-20 quote signatures), built only on the
// audited noble primitives already used for EVM signing.
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';

const Point = secp256k1.Point;
type Pt = InstanceType<typeof Point>;
const N = Point.Fn.ORDER;

export class CashuCryptoError extends Error {
  override name = 'CashuCryptoError';
}

const H2C_DOMAIN = utf8ToBytes('Secp256k1_HashToCurve_Cashu_');

export function hashToCurve(message: Uint8Array): Pt {
  const msgHash = sha256(concatBytes(H2C_DOMAIN, message));
  const counter = new Uint8Array(4);
  for (let i = 0; i < 2 ** 16; i++) {
    new DataView(counter.buffer).setUint32(0, i, true);
    const candidate = concatBytes(
      Uint8Array.of(0x02),
      sha256(concatBytes(msgHash, counter)),
    );
    try {
      return Point.fromBytes(candidate);
    } catch {
      // not on the curve: try the next counter
    }
  }
  throw new CashuCryptoError('hash_to_curve found no point');
}

// Y = hash_to_curve(secret), the id the mint uses for a proof (NUT-07).
export function proofY(secret: string): string {
  return hashToCurve(utf8ToBytes(secret)).toHex(true);
}

export function point(hex: string): Pt {
  try {
    return Point.fromHex(hex);
  } catch {
    throw new CashuCryptoError(`not a curve point: ${hex.slice(0, 16)}…`);
  }
}

export function randomScalar(random: (n: number) => Uint8Array): bigint {
  for (;;) {
    const b = random(32);
    const v = BigInt(`0x${bytesToHex(b)}`);
    if (v > 0n && v < N) return v;
  }
}

function scalarHex(v: bigint): string {
  return v.toString(16).padStart(64, '0');
}

export function blind(secret: string, r: bigint): { B_: string; Y: string } {
  const Y = hashToCurve(utf8ToBytes(secret));
  return { B_: Y.add(Point.BASE.multiply(r)).toHex(true), Y: Y.toHex(true) };
}

export function unblind(C_: string, r: bigint, K: string): string {
  return point(C_).subtract(point(K).multiply(r)).toHex(true);
}

// NUT-12 hash(R1, R2, A, C'): sha256 over the concatenated uncompressed hex.
export function hashE(...pts: Pt[]): Uint8Array {
  return sha256(utf8ToBytes(pts.map((p) => p.toHex(false)).join('')));
}

// Alice's check of the DLEQ proof the mint attaches to a BlindSignature: the
// mint signed B_ with the same key it publishes as A for that amount.
export function verifyBlindDleq(
  e: string,
  s: string,
  A: string,
  B_: string,
  C_: string,
): boolean {
  try {
    const eS = BigInt(`0x${e}`);
    const sS = BigInt(`0x${s}`);
    if (eS <= 0n || eS >= N || sS <= 0n || sS >= N) return false;
    const a = point(A);
    const b = point(B_);
    const c = point(C_);
    const R1 = Point.BASE.multiply(sS).subtract(a.multiply(eS));
    const R2 = b.multiply(sS).subtract(c.multiply(eS));
    return bytesToHex(hashE(R1, R2, a, c)) === e.toLowerCase();
  } catch {
    return false;
  }
}

// Carol's check of a DLEQ carried inside a Proof (with Alice's r).
export function verifyProofDleq(
  proof: {
    secret: string;
    C: string;
    dleq: { e: string; s: string; r: string };
  },
  A: string,
): boolean {
  try {
    const r = BigInt(`0x${proof.dleq.r}`);
    const a = point(A);
    const C_ = point(proof.C).add(a.multiply(r));
    const B_ = hashToCurve(utf8ToBytes(proof.secret)).add(
      Point.BASE.multiply(r),
    );
    return verifyBlindDleq(
      proof.dleq.e,
      proof.dleq.s,
      A,
      B_.toHex(true),
      C_.toHex(true),
    );
  } catch {
    return false;
  }
}

// --- mint side, used by the test mint and the sandbox merchant ------------

export function mintSign(k: bigint, B_: string): string {
  return point(B_).multiply(k).toHex(true);
}

export function mintDleq(
  k: bigint,
  B_: string,
  C_: string,
  random: (n: number) => Uint8Array,
): { e: string; s: string } {
  const r = randomScalar(random);
  const A = Point.BASE.multiply(k);
  const R1 = Point.BASE.multiply(r);
  const R2 = point(B_).multiply(r);
  const e = BigInt(`0x${bytesToHex(hashE(R1, R2, A, point(C_)))}`);
  const s = (r + e * k) % N;
  return { e: scalarHex(e), s: scalarHex(s) };
}

export function verifyProofSignature(
  k: bigint,
  secret: string,
  C: string,
): boolean {
  try {
    return hashToCurve(utf8ToBytes(secret)).multiply(k).equals(point(C));
  } catch {
    return false;
  }
}

// --- keysets (NUT-02) ------------------------------------------------------

export type KeysetInput = {
  keys: Record<string, string>;
  unit: string;
  inputFeePpk: number | null;
  finalExpiry: number | null;
};

function sortedKeys(keys: Record<string, string>): [string, string][] {
  return Object.entries(keys).sort((a, b) => {
    const x = BigInt(a[0]);
    const y = BigInt(b[0]);
    return x < y ? -1 : x > y ? 1 : 0;
  });
}

export function keysetIdV1(keys: Record<string, string>): string {
  const concat = concatBytes(
    ...sortedKeys(keys).map(([, pk]) => hexToBytes(pk)),
  );
  return `00${bytesToHex(sha256(concat)).slice(0, 14)}`;
}

export function keysetIdV2(k: KeysetInput): string {
  let pre = sortedKeys(k.keys)
    .map(([amt, pk]) => `${amt}:${pk.toLowerCase()}`)
    .join(',');
  pre += `|unit:${k.unit.toLowerCase()}`;
  if (k.inputFeePpk !== null && k.inputFeePpk !== 0)
    pre += `|input_fee_ppk:${k.inputFeePpk}`;
  if (k.finalExpiry !== null && k.finalExpiry !== 0)
    pre += `|final_expiry:${k.finalExpiry}`;
  return `01${bytesToHex(sha256(utf8ToBytes(pre)))}`;
}

// A wallet must recompute the id itself, or a mint could hand out keys that
// do not belong to the keyset it names.
export function keysetIdMatches(id: string, k: KeysetInput): boolean {
  if (id.startsWith('00')) return keysetIdV1(k.keys) === id;
  if (id.startsWith('01')) return keysetIdV2(k) === id;
  return false;
}

// --- P2PK (NUT-10/11) and quote signatures (NUT-20) -----------------------

export function p2pkSecret(
  pubkey: string,
  tags: string[][],
  nonce: string,
): string {
  const body: Record<string, unknown> = { nonce, data: pubkey };
  if (tags.length > 0) body['tags'] = tags;
  return JSON.stringify(['P2PK', body]);
}

export function schnorrSign(message: Uint8Array, privKey: Uint8Array): string {
  return bytesToHex(schnorr.sign(sha256(message), privKey));
}

export function schnorrVerify(
  sig: string,
  message: Uint8Array,
  pubkey: string,
): boolean {
  try {
    const x = hexToBytes(pubkey.length === 66 ? pubkey.slice(2) : pubkey);
    return schnorr.verify(hexToBytes(sig), sha256(message), x);
  } catch {
    return false;
  }
}

export function p2pkWitness(secret: string, privKey: Uint8Array): string {
  return JSON.stringify({
    signatures: [schnorrSign(utf8ToBytes(secret), privKey)],
  });
}

function len32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function minimalBigEndian(n: number): Uint8Array {
  if (n === 0) return new Uint8Array();
  let hex = BigInt(n).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return hexToBytes(hex);
}

export function mintQuoteMessage(
  quote: string,
  outputs: readonly { amount: number; B_: string }[],
): Uint8Array {
  const parts: Uint8Array[] = [utf8ToBytes('Cashu_MintQuoteSig_v1')];
  const q = utf8ToBytes(quote);
  parts.push(len32(q.length), q);
  for (const o of outputs) {
    const a = minimalBigEndian(o.amount);
    const b = hexToBytes(o.B_);
    parts.push(len32(a.length), a, len32(b.length), b);
  }
  return concatBytes(...parts);
}

export function newKeyPair(random: (n: number) => Uint8Array): {
  priv: Uint8Array;
  pub: string;
} {
  const priv = hexToBytes(scalarHex(randomScalar(random)));
  return { priv, pub: bytesToHex(secp256k1.getPublicKey(priv, true)) };
}

export { bytesToHex, hexToBytes, scalarHex };
