import {
  appendFileSync,
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, sha256Hex } from './util.ts';

export type AuditEvent = {
  ts: number;
  agent: string;
  event:
    | 'signed'
    | 'denied'
    | 'pending'
    | 'dry_run'
    | 'approval_expired'
    | 'approval_resolved'
    | 'conflict'
    | 'task_opened';
  idempotencyKey?: string;
  reason?: string;
  usd?: string;
  intent?: Record<string, unknown>;
  approvalId?: string;
  txRef?: string;
  via?: string;
  taskId?: string;
  credential?: string;
};

const GENESIS = '0'.repeat(64);

export type WriteLock = <T>(fn: () => T) => T;

const TAIL_BYTES = 64 * 1024;

export class AuditLog {
  readonly path: string;
  private readonly lock: WriteLock;

  constructor(path: string, lock: WriteLock = (fn) => fn()) {
    this.path = path;
    this.lock = lock;
    mkdirSync(dirname(path), { recursive: true });
    if (!existsSync(path)) closeSync(openSync(path, 'a', 0o600));
  }

  private lastLine(): string | undefined {
    const fd = openSync(this.path, 'r');
    try {
      const size = fstatSync(fd).size;
      if (size === 0) return undefined;
      const len = Math.min(size, TAIL_BYTES);
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, size - len);
      const text = buf.toString('utf8').replace(/\n+$/, '');
      const nl = text.lastIndexOf('\n');
      if (nl >= 0 || len === size) return text.slice(nl + 1);
    } finally {
      closeSync(fd);
    }
    const all = this.lines();
    return all[all.length - 1];
  }

  private lines(): string[] {
    return readFileSync(this.path, 'utf8')
      .split('\n')
      .filter((l) => l.length > 0);
  }

  append(event: AuditEvent): void {
    this.lock(() => {
      const last = this.lastLine();
      const line = canonicalJson({
        ...event,
        prev: last === undefined ? GENESIS : sha256Hex(last),
      });
      appendFileSync(this.path, `${line}\n`, { mode: 0o600, flag: 'a' });
    });
  }

  readSince(since: number, agent: string | null): string[] {
    return this.lines().filter((l) => {
      const e = JSON.parse(l) as { ts: number; agent: string };
      return e.ts >= since && (agent === null || e.agent === agent);
    });
  }

  verifyChain(): boolean {
    let prev = GENESIS;
    for (const l of this.lines()) {
      const e = JSON.parse(l) as { prev: string };
      if (e.prev !== prev) return false;
      prev = sha256Hex(l);
    }
    return true;
  }
}
