// An in-memory Cashu mint for tests: real BDHKE, DLEQ, input fees, spent
// set, P2PK (NUT-11) witness checks, restore (NUT-09), NUT-20 quote locks.
// Exposed as a fetch function so no sockets are needed.
import { randomBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import {
  keysetIdV2,
  mintDleq,
  mintQuoteMessage,
  mintSign,
  newKeyPair,
  p2pkWitness,
  proofY,
  randomScalar,
  schnorrVerify,
  verifyProofSignature,
} from '../../src/cashu/crypto.ts';
import type { Fetch } from '../../src/cashu/mint.ts';
import { feeOf, splitAmount } from '../../src/cashu/wallet.ts';

type Keyset = {
  id: string;
  unit: string;
  active: boolean;
  feePpk: number;
  priv: Map<number, bigint>;
  pub: Record<string, string>;
};

export type FakeMintOptions = {
  url?: string;
  feePpk?: number;
  units?: string[];
  p2pk?: boolean;
  nut20?: boolean;
};

export function fakeMint(o: FakeMintOptions = {}) {
  const url = o.url ?? 'http://127.0.0.1:3338';
  const keysets: Keyset[] = [];
  for (const unit of o.units ?? ['sat', 'usd']) {
    const priv = new Map<number, bigint>();
    const pub: Record<string, string> = {};
    for (let i = 0; i < 21; i++) {
      const amt = 2 ** i;
      const k = randomScalar(randomBytes);
      priv.set(amt, k);
      pub[String(amt)] = secp256k1.Point.BASE.multiply(k).toHex(true);
    }
    const feePpk = o.feePpk ?? 0;
    keysets.push({
      id: keysetIdV2({
        keys: pub,
        unit,
        inputFeePpk: feePpk,
        finalExpiry: null,
      }),
      unit,
      active: true,
      feePpk,
      priv,
      pub,
    });
  }
  const spent = new Set<string>();
  const signed = new Map<
    string,
    { amount: number; id: string; C_: string; dleq: { e: string; s: string } }
  >();
  const quotes = new Map<
    string,
    {
      amount: number;
      unit: string;
      paid: boolean;
      issued: boolean;
      pubkey: string | null;
    }
  >();
  type Melt = {
    amount: number;
    unit: string;
    fee: number;
    state: 'UNPAID' | 'PENDING' | 'PAID';
    ys: string[];
    sumIn: number;
    feeIn: number;
    outputs: Out[];
  };
  const melts = new Map<string, Melt>();
  const pending = new Set<string>();
  let qn = 0;

  const state = {
    url,
    keysets,
    spent,
    // Test hooks
    dropNextSwapResponse: false,
    refuseNextSwap: false,
    // Paths that fail as if the mint were unreachable, e.g. '/v1/swap'.
    downPaths: new Set<string>(),
    swaps: 0,
    // 'pending': lightning payments stay in flight until finishMelt().
    meltMode: 'pay' as 'pay' | 'pending',
  };

  const err = (detail: string, code: number) =>
    new Response(JSON.stringify({ detail, code }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  const ok = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });

  const ks = (id: string) => keysets.find((k) => k.id === id);
  const fee = (inputs: { id: string }[]) =>
    feeOf(inputs.map((p) => ks(p.id)?.feePpk ?? 0));

  type In = {
    amount: number;
    id: string;
    secret: string;
    C: string;
    witness?: string;
  };
  type Out = { amount: number; id: string; B_: string };

  function checkInputs(inputs: In[]): Response | null {
    const ys = new Set<string>();
    for (const p of inputs) {
      const k = ks(p.id);
      const priv = k?.priv.get(p.amount);
      if (k === undefined || priv === undefined)
        return err('unknown keyset', 12001);
      if (!verifyProofSignature(priv, p.secret, p.C))
        return err('proof verification failed', 10001);
      const y = proofY(p.secret);
      if (spent.has(y)) return err('proofs already spent', 11001);
      if (ys.has(y)) return err('duplicate inputs', 11007);
      ys.add(y);
      if (p.secret.startsWith('[')) {
        const [kind, body] = JSON.parse(p.secret) as [
          string,
          { data: string; tags?: string[][] },
        ];
        if (kind === 'P2PK' && o.p2pk !== false) {
          if (
            (body.tags ?? []).some(
              (t) =>
                t[0] === 'locktime' || t[0] === 'refund' || t[0] === 'pubkeys',
            )
          )
            return err('test mint: only basic P2PK', 10001);
          const w =
            p.witness === undefined
              ? null
              : (JSON.parse(p.witness) as { signatures?: string[] });
          const sig = w?.signatures?.[0];
          if (
            sig === undefined ||
            !schnorrVerify(sig, utf8ToBytes(p.secret), body.data)
          )
            return err('no valid P2PK signature', 10001);
        }
      }
    }
    return null;
  }

  function sign(outputs: Out[]) {
    return outputs.map((b) => {
      const k = ks(b.id);
      const priv = k?.priv.get(b.amount);
      if (k === undefined || priv === undefined || !k.active)
        throw new Error('bad output');
      const C_ = mintSign(priv, b.B_);
      const s = {
        amount: b.amount,
        id: b.id,
        C_,
        dleq: mintDleq(priv, b.B_, C_, randomBytes),
      };
      signed.set(b.B_, s);
      return s;
    });
  }

  const fetchFn: Fetch = async (u, init) => {
    const path = u.slice(url.length);
    if (state.downPaths.has(path)) throw new Error('connect ECONNREFUSED');
    const body =
      init?.body === undefined
        ? null
        : (JSON.parse(String(init.body)) as Record<string, unknown>);
    if (path === '/v1/info')
      return ok({
        name: 'test mint',
        nuts: {
          '7': { supported: true },
          '9': { supported: true },
          '10': { supported: o.p2pk !== false },
          '11': { supported: o.p2pk !== false },
          '12': { supported: true },
          '20': { supported: o.nut20 !== false },
        },
      });
    if (path === '/v1/keysets')
      return ok({
        keysets: keysets.map((k) => ({
          id: k.id,
          unit: k.unit,
          active: k.active,
          input_fee_ppk: k.feePpk,
        })),
      });
    if (path.startsWith('/v1/keys/')) {
      const k = ks(path.slice('/v1/keys/'.length));
      if (k === undefined) return err('unknown keyset', 12001);
      return ok({
        keysets: [
          {
            id: k.id,
            unit: k.unit,
            active: k.active,
            input_fee_ppk: k.feePpk,
            keys: k.pub,
          },
        ],
      });
    }
    if (path === '/v1/swap') {
      state.swaps++;
      if (state.refuseNextSwap) {
        state.refuseNextSwap = false;
        return err('test mint refuses', 11000);
      }
      const inputs = body?.['inputs'] as In[];
      const outputs = body?.['outputs'] as Out[];
      const bad = checkInputs(inputs);
      if (bad !== null) return bad;
      const units = new Set([...inputs, ...outputs].map((p) => ks(p.id)?.unit));
      if (units.size !== 1) return err('mixed units', 11009);
      const sumIn = inputs.reduce((s, p) => s + p.amount, 0);
      const sumOut = outputs.reduce((s, p) => s + p.amount, 0);
      if (sumIn - fee(inputs) !== sumOut)
        return err('transaction is not balanced', 11005);
      for (const b of outputs)
        if (signed.has(b.B_)) return err('outputs already signed', 11003);
      const sigs = sign(outputs);
      for (const p of inputs) spent.add(proofY(p.secret));
      if (state.dropNextSwapResponse) {
        state.dropNextSwapResponse = false;
        throw new Error('socket hang up');
      }
      return ok({ signatures: sigs });
    }
    if (path === '/v1/checkstate') {
      const ys = body?.['Ys'] as string[];
      return ok({
        states: ys.map((Y) => ({
          Y,
          state: spent.has(Y)
            ? 'SPENT'
            : pending.has(Y)
              ? 'PENDING'
              : 'UNSPENT',
          witness: null,
        })),
      });
    }
    if (path === '/v1/restore') {
      const outs = (body?.['outputs'] as Out[]).filter((b) => signed.has(b.B_));
      return ok({
        outputs: outs,
        signatures: outs.map((b) => signed.get(b.B_)),
      });
    }
    if (path === '/v1/mint/quote/bolt11' && init?.method === 'POST') {
      const id = `q${++qn}`;
      // Test invoices are paid the moment they are created.
      quotes.set(id, {
        amount: Number(body?.['amount']),
        unit: String(body?.['unit']),
        paid: true,
        issued: false,
        pubkey: (body?.['pubkey'] as string | undefined) ?? null,
      });
      const q = quotes.get(id)!;
      return ok({
        quote: id,
        request: `lntest${id}`,
        amount: q.amount,
        unit: q.unit,
        expiry: null,
        amount_paid: q.amount,
        amount_issued: 0,
        updated_at: 1,
        pubkey: q.pubkey,
      });
    }
    if (path.startsWith('/v1/mint/quote/bolt11/')) {
      const id = decodeURIComponent(
        path.slice('/v1/mint/quote/bolt11/'.length),
      );
      const q = quotes.get(id);
      if (q === undefined) return err('unknown quote', 20000);
      return ok({
        quote: id,
        request: `lntest${id}`,
        amount: q.amount,
        unit: q.unit,
        expiry: null,
        amount_paid: q.amount,
        amount_issued: q.issued ? q.amount : 0,
        updated_at: 2,
      });
    }
    if (path === '/v1/mint/bolt11') {
      const q = quotes.get(String(body?.['quote']));
      const outputs = body?.['outputs'] as Out[];
      if (q === undefined || q.issued)
        return err('quote already issued', 20002);
      if (q.pubkey !== null) {
        const sig = body?.['signature'];
        if (
          typeof sig !== 'string' ||
          !schnorrVerify(
            sig,
            mintQuoteMessage(String(body?.['quote']), outputs),
            q.pubkey,
          )
        )
          return err('signature for mint request invalid', 20008);
      }
      if (outputs.reduce((s, b) => s + b.amount, 0) > q.amount)
        return err('too much', 11005);
      q.issued = true;
      return ok({ signatures: sign(outputs) });
    }
    if (path === '/v1/melt/quote/bolt11') {
      const id = `m${++qn}`;
      const amount = Number(
        /(\d+)/.exec(String(body?.['request']))?.[1] ?? '0',
      );
      melts.set(id, {
        amount,
        unit: String(body?.['unit']),
        fee: 2,
        state: 'UNPAID',
        ys: [],
        sumIn: 0,
        feeIn: 0,
        outputs: [],
      });
      return ok(meltJson(id));
    }
    if (path.startsWith('/v1/melt/quote/bolt11/')) {
      const id = decodeURIComponent(
        path.slice('/v1/melt/quote/bolt11/'.length),
      );
      if (!melts.has(id)) return err('unknown quote', 20000);
      // Like real mints, the quote check does not repeat the change.
      return ok(meltJson(id));
    }
    if (path === '/v1/melt/bolt11') {
      const id = String(body?.['quote']);
      const m = melts.get(id);
      const inputs = body?.['inputs'] as In[];
      if (m === undefined) return err('unknown quote', 20000);
      if (m.state !== 'UNPAID') return err('quote is pending or paid', 20005);
      const bad = checkInputs(inputs);
      if (bad !== null) return bad;
      m.sumIn = inputs.reduce((s, p) => s + p.amount, 0);
      m.feeIn = fee(inputs);
      if (m.sumIn - m.feeIn < m.amount + m.fee) return err('not enough', 11005);
      m.ys = inputs.map((p) => proofY(p.secret));
      m.outputs = (body?.['outputs'] as Out[]) ?? [];
      for (const y of m.ys) pending.add(y);
      m.state = 'PENDING';
      if (state.meltMode === 'pending') return ok(meltJson(id));
      return ok({ ...meltJson(id, true), change: settle(id, true) });
    }
    return new Response('not found', { status: 404 });
  };

  function meltJson(id: string, paidNow = false) {
    const m = melts.get(id) as Melt;
    return {
      quote: id,
      amount: m.amount,
      unit: m.unit,
      fee_reserve: m.fee,
      state: paidNow ? 'PAID' : m.state,
      expiry: 0,
      payment_preimage: m.state === 'PAID' || paidNow ? '00'.repeat(32) : null,
    };
  }

  // The lightning payment of a melt ends: paid (inputs spent, change signed
  // on the blank outputs) or failed (inputs usable again).
  function settle(id: string, paid: boolean) {
    const m = melts.get(id) as Melt;
    for (const y of m.ys) pending.delete(y);
    if (!paid) {
      m.state = 'UNPAID';
      return [];
    }
    for (const y of m.ys) spent.add(y);
    m.state = 'PAID';
    // The route cost 1 of the 2 reserved: the rest comes back as change.
    let back = m.sumIn - m.feeIn - m.amount - 1;
    const change: Out[] = [];
    for (const b of m.outputs) {
      if (back <= 0) break;
      let d = 1;
      while (d * 2 <= back) d *= 2;
      change.push({ ...b, amount: d });
      back -= d;
    }
    return sign(change);
  }

  return Object.assign(state, {
    fetch: fetchFn,
    finishMelt(id: string, paid: boolean): void {
      settle(id, paid);
    },
    pendingMelts(): string[] {
      return [...melts]
        .filter(([, m]) => m.state === 'PENDING')
        .map(([id]) => id);
    },
    // A merchant redeeming a token it was paid with: swaps the proofs for
    // fresh ones, signing P2PK inputs with `priv` when they are locked.
    redeem(
      proofs: { id: string; amount: number; secret: string; C: string }[],
      priv: Uint8Array | null,
    ): Promise<Response> {
      const k = keysets.find((x) => x.id === proofs[0]?.id);
      const total = proofs.reduce((s, p) => s + p.amount, 0) - fee(proofs);
      const outs: Out[] = splitAmount(total, k?.pub ?? {}).map((amount) => ({
        amount,
        id: k?.id ?? '',
        B_: newKeyPair(randomBytes).pub,
      }));
      const inputs = proofs.map((p) => {
        const out: In = {
          id: p.id,
          amount: p.amount,
          secret: p.secret,
          C: p.C,
        };
        if (priv !== null && p.secret.startsWith('['))
          out.witness = p2pkWitness(p.secret, priv);
        return out;
      });
      return fetchFn(`${url}/v1/swap`, {
        method: 'POST',
        body: JSON.stringify({ inputs, outputs: outs }),
      });
    },
  });
}

export type FakeMint = ReturnType<typeof fakeMint>;
