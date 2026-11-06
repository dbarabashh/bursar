import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { hexToBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

export type KeySource = {
  keyfile: string | null;
  envVar: string;
  env: Record<string, string | undefined>;
};

export type KeyMaterial = { evm: Uint8Array | null; solana: Uint8Array | null };

export class KeystoreError extends Error {
  override name = 'KeystoreError';
}

function parseKeyText(text: string, origin: string): KeyMaterial {
  const out: KeyMaterial = { evm: null, solana: null };
  const entries = text
    .split(/[\n;]+/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  for (const entry of entries) {
    const m = /^(?:(evm|solana)\s*[:=]\s*)?(?:0x)?([0-9a-fA-F]{64})$/.exec(
      entry,
    );
    if (!m)
      throw new KeystoreError(
        `${origin}: expected lines like "evm: 0x<64 hex>" or "solana: <64 hex>"`,
      );
    const kind = (m[1] ?? 'evm') as 'evm' | 'solana';
    if (out[kind] !== null)
      throw new KeystoreError(`${origin}: duplicate ${kind} key`);
    out[kind] = hexToBytes(m[2] as string);
  }
  if (out.evm !== null && !secp256k1.utils.isValidSecretKey(out.evm))
    throw new KeystoreError(`${origin}: invalid secp256k1 key`);
  if (out.evm === null && out.solana === null)
    throw new KeystoreError(`${origin}: no keys found`);
  return out;
}

export function loadKeys(src: KeySource): KeyMaterial {
  const fromEnv = src.env[src.envVar];
  if (fromEnv !== undefined && fromEnv !== '') {
    delete src.env[src.envVar];
    return parseKeyText(fromEnv, `env ${src.envVar}`);
  }
  if (src.keyfile === null)
    throw new KeystoreError(
      `no wallet.keyfile configured and ${src.envVar} is not set`,
    );
  let st;
  try {
    st = statSync(src.keyfile);
  } catch {
    throw new KeystoreError(
      `keyfile ${src.keyfile} not found (create one with: bursar keygen --out ${src.keyfile})`,
    );
  }
  if (!st.isFile())
    throw new KeystoreError(`keyfile ${src.keyfile} is not a regular file`);
  // Windows has no POSIX modes (Node reports 0o666 for every writable file);
  // there the installer locks the key down with an ACL instead.
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0)
    throw new KeystoreError(
      `keyfile ${src.keyfile} must be chmod 600 (is ${(st.mode & 0o777).toString(8)})`,
    );
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new KeystoreError(
      `keyfile ${src.keyfile} must be owned by the daemon user`,
    );
  }
  const buf = readFileSync(src.keyfile);
  try {
    return parseKeyText(buf.toString('utf8'), `keyfile ${src.keyfile}`);
  } finally {
    buf.fill(0);
  }
}

export function generateKeyFile(path: string): void {
  let evm = randomBytes(32);
  while (!secp256k1.utils.isValidSecretKey(evm)) evm = randomBytes(32);
  const sol = randomBytes(32);
  const text = `evm: 0x${evm.toString('hex')}\nsolana: ${sol.toString('hex')}\n`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, text, { mode: 0o600, flag: 'wx' });
  evm.fill(0);
  sol.fill(0);
}
