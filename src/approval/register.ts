import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from '@noble/hashes/utils.js';
import type { Ledger } from '../ledger/store.ts';
import { registrationPage } from './pages.ts';
import {
  b64url,
  parseRegistrationBody,
  PasskeyError,
  RP_ID,
  verifyRegistration,
  type PasskeyCredential,
  type UserVerification,
} from './passkey.ts';

export type RegistrationSession = {
  url: string;
  done: Promise<PasskeyCredential>;
  close: () => void;
};

const MAX_BODY = 16 * 1024;

function send(
  res: ServerResponse,
  status: number,
  body: string | Record<string, unknown>,
  headers: Record<string, string> = {},
): void {
  const isText = typeof body === 'string';
  res
    .writeHead(status, {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'content-type': isText ? 'text/plain' : 'application/json',
      ...headers,
    })
    .end(isText ? body : JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new PasskeyError('body_too_large');
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new PasskeyError('body_invalid');
  }
}

export function startRegistration(opts: {
  ledger: Ledger;
  name: string;
  userVerification: UserVerification;
  timeoutMs?: number;
  now?: () => number;
}): Promise<RegistrationSession> {
  const now = opts.now ?? Date.now;
  const token = b64url(randomBytes(24));
  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  let finished = false;
  let resolveDone!: (c: PasskeyCredential) => void;
  let rejectDone!: (e: Error) => void;
  const done = new Promise<PasskeyCredential>((res, rej) => {
    resolveDone = res;
    rejectDone = rej;
  });
  done.catch(() => {});

  const server = createServer((req, res) => {
    void (async () => {
      const host = req.headers.host ?? '';
      if (host.split(':')[0] !== 'localhost')
        return send(res, 403, { error: 'open this page via http://localhost' });
      const path = new URL(req.url ?? '/', 'http://localhost').pathname;
      if (finished || path !== `/${token}`)
        return send(res, 404, { error: 'not_found' });
      if (req.method === 'GET') {
        const page = registrationPage({
          rpId: RP_ID,
          challenge: b64url(challenge),
          userId: b64url(userId),
          name: opts.name,
          userVerification: opts.userVerification,
          exclude: opts.ledger.listPasskeys().map((p) => p.credentialId),
        });
        return send(res, 200, page.body, page.headers);
      }
      if (req.method !== 'POST')
        return send(res, 405, { error: 'method_not_allowed' });
      if (!(req.headers['content-type'] ?? '').startsWith('application/json'))
        return send(res, 415, { error: 'content_type' });
      try {
        const reg = parseRegistrationBody(await readJson(req));
        const cred = verifyRegistration(reg, {
          challenge,
          origin: `http://localhost:${port}`,
          userVerification: opts.userVerification,
        });
        const stored = { ...cred, name: opts.name };
        if (opts.ledger.getPasskey(stored.credentialId) !== null)
          throw new PasskeyError('credential_already_registered');
        opts.ledger.addPasskey(stored, now());
        finished = true;
        send(res, 200, {
          status: 'registered',
          credentialId: stored.credentialId,
        });
        resolveDone(stored);
        server.close();
      } catch (e) {
        send(res, e instanceof PasskeyError ? 400 : 500, {
          error: e instanceof PasskeyError ? e.reason : 'internal_error',
        });
      }
    })();
  });

  let port = 0;
  const timer = setTimeout(() => {
    if (finished) return;
    finished = true;
    server.close();
    rejectDone(new Error('registration timed out'));
  }, opts.timeoutMs ?? 300_000);
  timer.unref();

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://localhost:${port}/${token}`,
        done,
        close: () => {
          clearTimeout(timer);
          if (!finished) {
            finished = true;
            rejectDone(new Error('registration cancelled'));
          }
          server.close();
          server.closeAllConnections();
        },
      });
    });
  });
}
