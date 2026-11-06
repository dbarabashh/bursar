// A NUT-24 merchant for the Cashu sandbox. Each route answers 402 with an
// X-Cashu payment request; a retry carrying a cashuB token is served only
// after the merchant has redeemed the token at the mint (swapped it for
// fresh ecash), which is what makes the payment final.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from '@noble/hashes/utils.js';
import { normalizeMintUrl } from '../src/config.ts';
import { newKeyPair, p2pkWitness } from '../src/cashu/crypto.ts';
import { decodeToken, encodePaymentRequestA } from '../src/cashu/encoding.ts';
import {
  createMintClient,
  MintRefused,
  type WireProof,
} from '../src/cashu/mint.ts';
import { feeOf, splitAmount } from '../src/cashu/wallet.ts';

type Route = { amount: number; locked: boolean; redeem: boolean };

export type Receipt = { path: string; amount: number; locked: boolean };

export async function startCashuMerchant(mintUrl: string): Promise<{
  url: string;
  pubkey: string;
  receipts: Receipt[];
  close: () => void;
}> {
  const key = newKeyPair(randomBytes);
  const mint = createMintClient(mintUrl);
  const receipts: Receipt[] = [];
  const keyCache = new Map<string, Record<string, string>>();
  const activeKeys = async (id: string) => {
    const known = keyCache.get(id);
    if (known !== undefined) return known;
    const keys = await mint.keys(id);
    keyCache.set(id, keys);
    return keys;
  };
  const routes: Record<string, Route> = {
    '/locked': { amount: 21, locked: true, redeem: true },
    '/open': { amount: 34, locked: false, redeem: true },
    '/expensive': { amount: 600, locked: true, redeem: true },
    // Takes the payment request seriously but never redeems the token.
    '/broken': { amount: 13, locked: false, redeem: false },
  };

  async function redeem(token: string, route: Route): Promise<string | null> {
    let t;
    try {
      t = decodeToken(token);
    } catch {
      return 'not a cashu token';
    }
    if (normalizeMintUrl(t.mint) !== mintUrl || t.unit !== 'sat')
      return 'wrong mint or unit';
    const keysets = await mint.keysets();
    const active = keysets.find((k) => k.active && k.unit === 'sat');
    if (active === undefined) return 'mint has no keyset';
    const ppk = new Map(keysets.map((k) => [k.id, k.input_fee_ppk]));
    const ids = [...ppk.keys()];
    if (route.locked && t.proofs.some((p) => !p.secret.startsWith('["P2PK"')))
      return 'token is not locked to our key';
    const ins: WireProof[] = t.proofs.map((p) => {
      const out: WireProof = {
        id: ids.find((i) => i.startsWith(p.id)) ?? p.id,
        amount: p.amount,
        secret: p.secret,
        C: p.C,
      };
      if (p.secret.startsWith('['))
        out.witness = p2pkWitness(p.secret, key.priv);
      return out;
    });
    const fee = feeOf(ins.map((p) => ppk.get(p.id) ?? 0));
    const net = ins.reduce((s, p) => s + p.amount, 0) - fee;
    if (net < route.amount) return `paid ${net}, need ${route.amount}`;
    // Fresh outputs for the merchant's own wallet (not unblinded here).
    const outputs = splitAmount(net, await activeKeys(active.id)).map(
      (amount) => ({ amount, id: active.id, B_: newKeyPair(randomBytes).pub }),
    );
    try {
      await mint.swap(
        ins,
        outputs.sort((a, b) => a.amount - b.amount),
      );
      return null;
    } catch (e) {
      return e instanceof MintRefused
        ? e.message
        : `mint: ${(e as Error).message}`;
    }
  }

  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    const route = routes[path];
    if (route === undefined) return void res.writeHead(404).end();
    const token = req.headers['x-cashu'];
    if (typeof token !== 'string') {
      res.writeHead(402, {
        'x-cashu': encodePaymentRequestA({
          a: route.amount,
          u: 'sat',
          m: [mintUrl],
          ...(route.locked ? { nut10: { k: 'P2PK', d: key.pub, t: [] } } : {}),
        }),
        'content-type': 'application/json',
      });
      return void res.end(
        JSON.stringify({ error: 'payment required', sat: route.amount }),
      );
    }
    if (!route.redeem)
      return void res
        .writeHead(400)
        .end('token rejected (this route is broken on purpose)');
    redeem(token, route).then(
      (err) => {
        if (err !== null) return void res.writeHead(400).end(err);
        receipts.push({ path, amount: route.amount, locked: route.locked });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            path,
            data: `paid content for ${route.amount} sat`,
          }),
        );
      },
      (e: unknown) => res.writeHead(500).end((e as Error).message),
    );
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    pubkey: key.pub,
    receipts,
    close: () => server.close(),
  };
}
