import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export const MICRO = 1_000_000n;

export function isRecord(v: unknown): v is Record<string, unknown> {
  return (
    typeof v === 'object' &&
    v !== null &&
    !Array.isArray(v) &&
    !(v instanceof Uint8Array)
  );
}

export function sha256Hex(input: string | Uint8Array): string {
  return bytesToHex(
    sha256(typeof input === 'string' ? utf8ToBytes(input) : input),
  );
}

export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeForJson(value));
}

function normalizeForJson(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `0x${bytesToHex(value)}`;
  if (Array.isArray(value)) return value.map(normalizeForJson);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      const v = value[k];
      if (v !== undefined) out[k] = normalizeForJson(v);
    }
    return out;
  }
  return value;
}

export function parseUsd(value: unknown, path: string): bigint {
  if (
    typeof value === 'number' &&
    !(
      Number.isFinite(value) &&
      value >= 0 &&
      value <= Number.MAX_SAFE_INTEGER / 1e6
    )
  ) {
    throw new Error(`${path}: number out of range, quote it as a string`);
  }
  const text = typeof value === 'number' ? String(value) : value;
  if (typeof text !== 'string' || !/^\d+(\.\d{1,6})?$/.test(text)) {
    throw new Error(
      `${path}: expected a non-negative USD amount with at most 6 decimals`,
    );
  }
  const [whole = '0', frac = ''] = text.split('.');
  return BigInt(whole) * MICRO + BigInt(frac.padEnd(6, '0'));
}

export function stablecoinUnitsToMicroUsd(
  amount: bigint,
  decimals: number,
): bigint {
  if (decimals === 6) return amount;
  if (decimals < 6) return amount * 10n ** BigInt(6 - decimals);
  const div = 10n ** BigInt(decimals - 6);
  return (amount + div - 1n) / div;
}

export function formatUsd(micro: bigint): string {
  const neg = micro < 0n;
  const abs = neg ? -micro : micro;
  const whole = abs / MICRO;
  let frac = (abs % MICRO).toString().padStart(6, '0').replace(/0+$/, '');
  if (frac.length < 2) frac = frac.padEnd(2, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

export function parseDecimalAmount(
  text: string,
  decimals: number,
): bigint | null {
  const cleaned = text
    .trim()
    .replace(/^\$/, '')
    .replace(/\s*(USD|USDC)$/i, '');
  const m = /^(\d+)(?:\.(\d+))?$/.exec(cleaned);
  if (!m) return null;
  const frac = m[2] ?? '';
  if (frac.length > decimals) return null;
  return (
    BigInt(m[1] ?? '0') * 10n ** BigInt(decimals) +
    BigInt(frac.padEnd(decimals, '0') || '0')
  );
}

export function parseUint(value: unknown, path: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    return BigInt(value);
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value))
    return BigInt(value);
  if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value))
    return BigInt(value);
  throw new Error(`${path}: expected a non-negative integer`);
}
