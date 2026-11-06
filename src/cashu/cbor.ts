// Minimal CBOR (RFC 8949) for Cashu payment requests (creqA) and V4 tokens
// (cashuB): unsigned/negative integers, byte and text strings, arrays, maps,
// booleans and null, definite lengths only. Map keys decode to strings.

export class CborError extends Error {
  override name = 'CborError';
}

export type CborValue =
  | number
  | string
  | boolean
  | null
  | Uint8Array
  | CborValue[]
  | { [k: string]: CborValue };

const MAX_DEPTH = 32;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const UTF8_ENCODER = new TextEncoder();
const MAX_ITEMS = 10_000;

export function decodeCbor(bytes: Uint8Array): CborValue {
  let pos = 0;
  let items = 0;

  const need = (n: number) => {
    if (pos + n > bytes.length) throw new CborError('truncated');
  };

  const readLength = (info: number): number => {
    if (info < 24) return info;
    let n: number;
    if (info === 24) {
      need(1);
      n = bytes[pos] as number;
      pos += 1;
    } else if (info === 25) {
      need(2);
      n = ((bytes[pos] as number) << 8) | (bytes[pos + 1] as number);
      pos += 2;
    } else if (info === 26) {
      need(4);
      n =
        (bytes[pos] as number) * 2 ** 24 +
        (((bytes[pos + 1] as number) << 16) |
          ((bytes[pos + 2] as number) << 8) |
          (bytes[pos + 3] as number));
      pos += 4;
    } else if (info === 27) {
      need(8);
      let v = 0n;
      for (let i = 0; i < 8; i++)
        v = (v << 8n) | BigInt(bytes[pos + i] as number);
      pos += 8;
      if (v > BigInt(Number.MAX_SAFE_INTEGER))
        throw new CborError('integer too large');
      n = Number(v);
    } else {
      throw new CborError('indefinite or reserved length not supported');
    }
    return n;
  };

  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new CborError('nested too deep');
    if (++items > MAX_ITEMS) throw new CborError('too many items');
    need(1);
    const head = bytes[pos] as number;
    pos += 1;
    const major = head >> 5;
    const info = head & 0x1f;
    switch (major) {
      case 0:
        return readLength(info);
      case 1:
        return -1 - readLength(info);
      case 2: {
        const n = readLength(info);
        need(n);
        const out = bytes.slice(pos, pos + n);
        pos += n;
        return out;
      }
      case 3: {
        const n = readLength(info);
        need(n);
        const out = UTF8_DECODER.decode(bytes.subarray(pos, pos + n));
        pos += n;
        return out;
      }
      case 4: {
        const n = readLength(info);
        const out: CborValue[] = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = readLength(info);
        const out: { [k: string]: CborValue } = {};
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (typeof k !== 'string' && typeof k !== 'number')
            throw new CborError('map keys must be text or integers');
          const key = String(k);
          if (Object.hasOwn(out, key)) throw new CborError('duplicate map key');
          Object.defineProperty(out, key, {
            value: item(depth + 1),
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
        return out;
      }
      case 6:
        // Tags carry no meaning for Cashu; decode the tagged item.
        readLength(info);
        return item(depth + 1);
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        throw new CborError('floats and simple values are not supported');
      default:
        throw new CborError('bad major type');
    }
  };

  const out = item(0);
  if (pos !== bytes.length) throw new CborError('trailing bytes');
  return out;
}

export function encodeCbor(value: CborValue): Uint8Array {
  const out: number[] = [];
  const head = (major: number, n: number) => {
    if (!Number.isSafeInteger(n) || n < 0)
      throw new CborError('length out of range');
    if (n < 24) out.push((major << 5) | n);
    else if (n < 0x100) out.push((major << 5) | 24, n);
    else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
    else if (n < 0x100000000)
      out.push(
        (major << 5) | 26,
        (n >>> 24) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 8) & 0xff,
        n & 0xff,
      );
    else {
      out.push((major << 5) | 27);
      const b = BigInt(n);
      for (let i = 7; i >= 0; i--)
        out.push(Number((b >> BigInt(i * 8)) & 0xffn));
    }
  };
  const enc = (v: CborValue) => {
    if (v === null) out.push(0xf6);
    else if (v === true) out.push(0xf5);
    else if (v === false) out.push(0xf4);
    else if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new CborError('only integers');
      if (v >= 0) head(0, v);
      else head(1, -1 - v);
    } else if (typeof v === 'string') {
      const b = UTF8_ENCODER.encode(v);
      head(3, b.length);
      for (const x of b) out.push(x);
    } else if (v instanceof Uint8Array) {
      head(2, v.length);
      for (const x of v) out.push(x);
    } else if (Array.isArray(v)) {
      head(4, v.length);
      for (const x of v) enc(x);
    } else {
      const entries = Object.entries(v);
      head(5, entries.length);
      for (const [k, x] of entries) {
        enc(k);
        enc(x);
      }
    }
  };
  enc(value);
  return Uint8Array.from(out);
}

export function base64UrlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_\-+/]*={0,2}$/.test(s))
    throw new CborError('not base64url');
  return new Uint8Array(
    Buffer.from(s.replace(/\+/g, '-').replace(/\//g, '_'), 'base64url'),
  );
}

export function base64UrlEncode(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}
