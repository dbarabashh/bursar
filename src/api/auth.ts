import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import type { Policy } from '../config.ts';
import { ctEqual } from '../util.ts';

export function authenticate(
  policy: Policy,
  header: string | undefined,
): string | null {
  if (header === undefined) return null;
  const m = /^Bearer ([\x21-\x7e]{1,512})$/.exec(header);
  if (!m || m[1] === undefined) return null;
  const digest = sha256(utf8ToBytes(m[1]));
  let found: string | null = null;
  for (const agent of policy.agents) {
    if (ctEqual(digest, agent.tokenHash) && found === null) found = agent.id;
  }
  return found;
}
