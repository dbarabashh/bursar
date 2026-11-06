// Cashu payment requests (NUT-18 creqA, NUT-26 creqB) and tokens (NUT-00
// cashuB V4, cashuA V3 for receiving).
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { isRecord } from '../util.ts';
import {
  base64UrlDecode,
  base64UrlEncode,
  decodeCbor,
  encodeCbor,
  type CborValue,
} from './cbor.ts';

export class CashuFormatError extends Error {
  override name = 'CashuFormatError';
}

export type Nut10Option = { k: string; d: string; t: string[][] };

export type PaymentRequest = {
  i?: string;
  a?: number;
  u?: string;
  s?: boolean;
  m?: string[];
  mp?: boolean;
  d?: string;
  nut10?: Nut10Option;
  // Out-of-band transports; NUT-24 requests carry none (payment is in-band).
  transports: number;
};

const MAX_REQUEST = 8 * 1024;

const isObj = (v: unknown): v is Record<string, CborValue> => isRecord(v);

function strTags(v: unknown, field: string): string[][] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new CashuFormatError(`${field} must be a list`);
  return v.map((t) => {
    if (
      !Array.isArray(t) ||
      t.length === 0 ||
      !t.every((x) => typeof x === 'string' && x.length > 0)
    )
      throw new CashuFormatError(
        `${field}: tags are lists of non-empty strings`,
      );
    return t as string[];
  });
}

function fromJsonShape(o: Record<string, CborValue>): PaymentRequest {
  const out: PaymentRequest = { transports: 0 };
  const optStr = (k: string) => {
    const v = o[k];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== 'string') throw new CashuFormatError(`${k} must be text`);
    return v;
  };
  const i = optStr('i');
  if (i !== undefined) out.i = i;
  const u = optStr('u');
  if (u !== undefined) out.u = u;
  const d = optStr('d');
  if (d !== undefined) out.d = d;
  const a = o['a'];
  if (a !== undefined && a !== null) {
    if (typeof a !== 'number' || !Number.isSafeInteger(a) || a < 0)
      throw new CashuFormatError('a must be a non-negative integer');
    out.a = a;
  }
  if (typeof o['s'] === 'boolean') out.s = o['s'];
  if (typeof o['mp'] === 'boolean') out.mp = o['mp'];
  const m = o['m'];
  if (m !== undefined && m !== null) {
    if (!Array.isArray(m) || !m.every((x) => typeof x === 'string'))
      throw new CashuFormatError('m must be a list of mint URLs');
    out.m = m as string[];
  }
  const t = o['t'];
  if (Array.isArray(t)) out.transports = t.length;
  const n = o['nut10'];
  if (n !== undefined && n !== null) {
    if (!isObj(n) || typeof n['k'] !== 'string' || typeof n['d'] !== 'string')
      throw new CashuFormatError('nut10 must be {k, d, t?}');
    out.nut10 = { k: n['k'], d: n['d'], t: strTags(n['t'], 'nut10.t') };
  }
  return out;
}

// --- bech32m (BIP-350), no length limit: creqB strings run past 90 chars ---

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;

function polymod(values: number[]): number {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i] as number;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

export function bech32mDecode(s: string): { hrp: string; data: Uint8Array } {
  if (s !== s.toLowerCase() && s !== s.toUpperCase())
    throw new CashuFormatError('bech32m: mixed case');
  const str = s.toLowerCase();
  const sep = str.lastIndexOf('1');
  if (sep < 1 || sep + 7 > str.length)
    throw new CashuFormatError('bech32m: no separator');
  const hrp = str.slice(0, sep);
  const words: number[] = [];
  for (const c of str.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) throw new CashuFormatError('bech32m: bad character');
    words.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...words]) !== BECH32M_CONST)
    throw new CashuFormatError('bech32m: bad checksum');
  const data = words.slice(0, -6);
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const w of data) {
    acc = (acc << 5) | w;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0)
    throw new CashuFormatError('bech32m: bad padding');
  return { hrp, data: Uint8Array.from(out) };
}

export function bech32mEncode(hrp: string, data: Uint8Array): string {
  const words: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of data) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);
  const pm =
    polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  for (let i = 0; i < 6; i++) words.push((pm >>> (5 * (5 - i))) & 31);
  return `${hrp}1${words.map((w) => CHARSET[w]).join('')}`;
}

// --- NUT-26 TLV ------------------------------------------------------------

function tlv(bytes: Uint8Array): { tag: number; value: Uint8Array }[] {
  const out: { tag: number; value: Uint8Array }[] = [];
  let p = 0;
  while (p < bytes.length) {
    if (p + 3 > bytes.length) throw new CashuFormatError('tlv: truncated');
    const tag = bytes[p] as number;
    const len = ((bytes[p + 1] as number) << 8) | (bytes[p + 2] as number);
    p += 3;
    if (p + len > bytes.length) throw new CashuFormatError('tlv: truncated');
    out.push({ tag, value: bytes.subarray(p, p + len) });
    p += len;
  }
  return out;
}

const UTF8 = new TextDecoder('utf-8', { fatal: true });
const utf8 = (b: Uint8Array) => UTF8.decode(b);

function u64(b: Uint8Array): number {
  if (b.length !== 8) throw new CashuFormatError('tlv: u64 must be 8 bytes');
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  if (v > BigInt(Number.MAX_SAFE_INTEGER))
    throw new CashuFormatError('amount too large');
  return Number(v);
}

function tagTuple(b: Uint8Array): string[] {
  const out: string[] = [];
  let p = 0;
  while (p < b.length) {
    const len = b[p] as number;
    p += 1;
    if (p + len > b.length) throw new CashuFormatError('tlv: bad tag tuple');
    out.push(utf8(b.subarray(p, p + len)));
    p += len;
  }
  if (out.length === 0) throw new CashuFormatError('tlv: empty tag tuple');
  return out;
}

const NUT10_KINDS: Record<number, string> = { 0: 'P2PK', 1: 'HTLC' };

function decodeCreqB(s: string): PaymentRequest {
  const { hrp, data } = bech32mDecode(s);
  if (hrp !== 'creqb') throw new CashuFormatError('creqB: wrong prefix');
  const out: PaymentRequest = { transports: 0 };
  for (const { tag, value } of tlv(data)) {
    switch (tag) {
      case 0x01:
        out.i = utf8(value);
        break;
      case 0x02:
        out.a = u64(value);
        break;
      case 0x03:
        out.u = value.length === 1 && value[0] === 0 ? 'sat' : utf8(value);
        break;
      case 0x04:
        out.s = value[0] === 1;
        break;
      case 0x05:
        (out.m ??= []).push(utf8(value));
        break;
      case 0x06:
        out.d = utf8(value);
        break;
      case 0x07:
        out.transports += 1;
        break;
      case 0x08: {
        let k: string | null = null;
        let d = '';
        const t: string[][] = [];
        for (const sub of tlv(value)) {
          if (sub.tag === 0x01)
            k = NUT10_KINDS[sub.value[0] as number] ?? `kind:${sub.value[0]}`;
          else if (sub.tag === 0x02) d = utf8(sub.value);
          else if (sub.tag === 0x03) t.push(tagTuple(sub.value));
        }
        if (k === null) throw new CashuFormatError('creqB: nut10 without kind');
        out.nut10 = { k, d, t };
        break;
      }
      case 0x09:
        out.mp = value[0] === 1;
        break;
      default:
        break; // unknown tags are ignored (NUT-26)
    }
  }
  return out;
}

export function decodePaymentRequest(s: string): PaymentRequest {
  const v = s.trim();
  if (v.length > MAX_REQUEST)
    throw new CashuFormatError('payment request too long');
  if (/^creqa/i.test(v)) {
    const decoded = decodeCbor(base64UrlDecode(v.slice(5)));
    if (!isObj(decoded)) throw new CashuFormatError('creqA must encode a map');
    return fromJsonShape(decoded);
  }
  if (/^creqb1/i.test(v)) return decodeCreqB(v);
  throw new CashuFormatError('expected a creqA or creqB payment request');
}

export function encodePaymentRequestA(o: {
  a?: number;
  u?: string;
  m?: string[];
  i?: string;
  nut10?: Nut10Option;
}): string {
  const map: Record<string, CborValue> = {};
  if (o.i !== undefined) map['i'] = o.i;
  if (o.a !== undefined) map['a'] = o.a;
  if (o.u !== undefined) map['u'] = o.u;
  if (o.m !== undefined) map['m'] = o.m;
  if (o.nut10 !== undefined)
    map['nut10'] = {
      k: o.nut10.k,
      d: o.nut10.d,
      ...(o.nut10.t.length > 0 ? { t: o.nut10.t } : {}),
    };
  return `creqA${base64UrlEncode(encodeCbor(map))}`;
}

// --- tokens ----------------------------------------------------------------

export type TokenProof = {
  id: string;
  amount: number;
  secret: string;
  C: string;
  dleq?: { e: string; s: string; r: string };
  witness?: string;
};

export type Token = {
  mint: string;
  unit: string;
  memo?: string;
  proofs: TokenProof[];
};

export function encodeTokenV4(t: Token): string {
  const groups = new Map<string, TokenProof[]>();
  for (const p of t.proofs) {
    const g = groups.get(p.id) ?? [];
    g.push(p);
    groups.set(p.id, g);
  }
  const map: Record<string, CborValue> = {
    m: t.mint,
    u: t.unit,
    ...(t.memo === undefined ? {} : { d: t.memo }),
    t: [...groups].map(([id, ps]) => ({
      i: hexToBytes(id),
      p: ps.map((p) => {
        const o: Record<string, CborValue> = {
          a: p.amount,
          s: p.secret,
          c: hexToBytes(p.C),
        };
        if (p.dleq !== undefined)
          o['d'] = {
            e: hexToBytes(p.dleq.e),
            s: hexToBytes(p.dleq.s),
            r: hexToBytes(p.dleq.r),
          };
        if (p.witness !== undefined) o['w'] = p.witness;
        return o;
      }),
    })),
  };
  return `cashuB${base64UrlEncode(encodeCbor(map))}`;
}

function hexOf(v: unknown, field: string): string {
  if (!(v instanceof Uint8Array))
    throw new CashuFormatError(`${field} must be bytes`);
  return bytesToHex(v);
}

export function decodeToken(s: string): Token {
  const v = s.trim().replace(/^cashu:/, '');
  if (v.startsWith('cashuB')) {
    const o = decodeCbor(base64UrlDecode(v.slice(6)));
    if (!isObj(o) || typeof o['m'] !== 'string' || typeof o['u'] !== 'string')
      throw new CashuFormatError('cashuB: missing mint or unit');
    const groups = o['t'];
    if (!Array.isArray(groups))
      throw new CashuFormatError('cashuB: t must be a list');
    const proofs: TokenProof[] = [];
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g['p']))
        throw new CashuFormatError('cashuB: bad proof group');
      const id = hexOf(g['i'], 't.i');
      for (const p of g['p']) {
        if (
          !isObj(p) ||
          typeof p['a'] !== 'number' ||
          typeof p['s'] !== 'string'
        )
          throw new CashuFormatError('cashuB: bad proof');
        const proof: TokenProof = {
          id,
          amount: p['a'],
          secret: p['s'],
          C: hexOf(p['c'], 'p.c'),
        };
        const d = p['d'];
        if (isObj(d))
          proof.dleq = {
            e: hexOf(d['e'], 'd.e'),
            s: hexOf(d['s'], 'd.s'),
            r: hexOf(d['r'], 'd.r'),
          };
        if (typeof p['w'] === 'string') proof.witness = p['w'];
        proofs.push(proof);
      }
    }
    const out: Token = { mint: o['m'], unit: o['u'], proofs };
    if (typeof o['d'] === 'string') out.memo = o['d'];
    return out;
  }
  if (v.startsWith('cashuA')) {
    const json = JSON.parse(
      Buffer.from(base64UrlDecode(v.slice(6))).toString('utf8'),
    ) as {
      token?: { mint?: string; proofs?: TokenProof[] }[];
      unit?: string;
      memo?: string;
    };
    const entries = json.token ?? [];
    if (entries.length !== 1 || typeof entries[0]?.mint !== 'string')
      throw new CashuFormatError(
        'cashuA: only single-mint tokens are supported',
      );
    const out: Token = {
      mint: entries[0].mint,
      unit: json.unit ?? 'sat',
      proofs: entries[0].proofs ?? [],
    };
    if (json.memo !== undefined) out.memo = json.memo;
    return out;
  }
  throw new CashuFormatError('expected a cashuB or cashuA token');
}
