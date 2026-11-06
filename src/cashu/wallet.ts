// The Cashu wallet inside the daemon. Proofs live in the ledger (SQLite, mode
// 600, owned by the daemon user) and never leave it except as the token of a
// payment the policy allowed.
//
// Every swap is two-phase: the inputs are reserved and the outputs (secrets
// and blinding factors) written to the ledger first, then the mint is asked.
// If its answer is lost, the outputs are recovered with NUT-09 restore, or the
// inputs are found unspent with NUT-07 and released. Nothing depends on
// process memory surviving.
import { normalizeMintUrl, type CashuUnit } from '../config.ts';
import type {
  CashuKeysetRow,
  CashuOpRow,
  CashuProofRow,
  Ledger,
} from '../ledger/store.ts';
import { isRecord } from '../util.ts';
import {
  blind,
  bytesToHex,
  hexToBytes,
  keysetIdMatches,
  mintQuoteMessage,
  newKeyPair,
  p2pkSecret,
  proofY,
  randomScalar,
  scalarHex,
  schnorrSign,
  unblind,
  verifyBlindDleq,
} from './crypto.ts';
import { decodeToken, encodeTokenV4, type TokenProof } from './encoding.ts';
import {
  MintRefused,
  MintUnavailable,
  type BlindedMessage,
  type BlindSignature,
  type MintClient,
  type MeltQuote,
  type MintInfo,
  type WireProof,
} from './mint.ts';

export class WalletError extends Error {
  override name = 'WalletError';
  readonly reason: string;
  constructor(reason: string, detail?: string) {
    super(detail === undefined ? reason : `${reason}: ${detail}`);
    this.reason = reason;
  }
}

type OutputRow = {
  amount: number;
  id: string;
  B_: string;
  Y: string;
  secret: string;
  r: string;
  role: 'send' | 'keep';
};

// Inputs as recorded in an op: the wire proof plus its Y (NUT-07 id).
type InputRow = WireProof & { y: string };

export type Lock = { pubkey: string; tags: string[][] };

export type SendPlan = {
  mint: string;
  unit: CashuUnit;
  amount: number;
  sendTotal: number;
  fee: number;
  inputs: CashuProofRow[];
  sendAmounts: number[];
  keepAmounts: number[];
  keysetId: string;
};

export type SwapOutcome =
  | { kind: 'ok'; token: string | null; amount: number }
  | { kind: 'refused'; detail: string }
  | { kind: 'unknown'; detail: string };

export type WalletDeps = {
  ledger: Ledger;
  client: (mint: string) => MintClient;
  random: (n: number) => Uint8Array;
  now: () => number;
};

// NUT-02 input fee: per-input ppk summed, rounded up to a whole unit.
export function feeOf(ppks: readonly number[]): number {
  return feeOfPpk(ppks.reduce((a, b) => a + b, 0));
}

function feeOfPpk(sum: number): number {
  return Math.floor((sum + 999) / 1000);
}

const KEYSET_TTL_MS = 5 * 60_000;

const PENDING_HINT =
  'The ecash stays reserved until the mint says how it ended; the daemon checks every minute, or run: bursar cashu recover';

const ownsInputs = (op: CashuOpRow) => op.kind === 'send' || op.kind === 'melt';

const toInput = ({ y, id, amount, secret, C }: CashuProofRow): InputRow => ({
  id,
  amount,
  secret,
  C,
  y,
});

// Greedy split into the denominations the keyset has (powers of two).
export function splitAmount(
  amount: number,
  keys: Record<string, string>,
): number[] {
  const denoms = Object.keys(keys)
    .map(Number)
    .filter((n) => Number.isSafeInteger(n) && n > 0)
    .sort((a, b) => b - a);
  const out: number[] = [];
  let left = amount;
  for (const d of denoms) {
    while (left >= d) {
      out.push(d);
      left -= d;
    }
  }
  if (left !== 0)
    throw new WalletError('amount_not_representable', String(amount));
  return out.sort((a, b) => a - b);
}

export function createWallet(deps: WalletDeps) {
  const { ledger, random, now } = deps;
  const infos = new Map<string, { info: MintInfo; at: number }>();
  // Keysets per mint, loaded once from the ledger; keys never change, only
  // the active flag, which syncKeysets refreshes at most every few minutes.
  const keysetCache = new Map<string, Map<string, CashuKeysetRow>>();
  const synced = new Map<string, number>();

  const hex32 = () => bytesToHex(random(32));

  async function mintInfo(mint: string): Promise<MintInfo> {
    const cached = infos.get(mint);
    if (cached !== undefined && now() - cached.at < 10 * 60_000)
      return cached.info;
    const info = await deps.client(mint).info();
    infos.set(mint, { info, at: now() });
    return info;
  }

  function supports(info: MintInfo, nut: string): boolean {
    const v = info.nuts[nut];
    return isRecord(v) && v['supported'] === true;
  }

  function keysetMap(mint: string): Map<string, CashuKeysetRow> {
    let m = keysetCache.get(mint);
    if (m === undefined) {
      m = new Map(ledger.listKeysets(mint).map((k) => [k.id, k]));
      keysetCache.set(mint, m);
    }
    return m;
  }

  function storeKeyset(k: CashuKeysetRow): void {
    ledger.putKeyset(k);
    keysetMap(k.mint).set(k.id, k);
  }

  // Fetch keysets, verify every new keyset id against its keys (NUT-02), and
  // keep the active flags current. Skipped if done in the last few minutes.
  async function syncKeysets(mint: string): Promise<void> {
    if (now() - (synced.get(mint) ?? -Infinity) < KEYSET_TTL_MS) return;
    const c = deps.client(mint);
    const known = keysetMap(mint);
    const remote = (await c.keysets()).filter(
      (k) => k.unit === 'sat' || k.unit === 'usd',
    );
    for (const k of remote) {
      const have = known.get(k.id);
      if (have !== undefined && have.active !== k.active)
        storeKeyset({ ...have, active: k.active, updated: now() });
    }
    const fresh = remote.filter((k) => !known.has(k.id));
    const keys = await Promise.all(fresh.map((k) => c.keys(k.id)));
    fresh.forEach((k, i) => {
      const ks = keys[i] as Record<string, string>;
      if (
        !keysetIdMatches(k.id, {
          keys: ks,
          unit: k.unit,
          inputFeePpk: k.input_fee_ppk,
          finalExpiry: k.final_expiry,
        })
      )
        throw new WalletError(
          'keyset_id_mismatch',
          `${mint} keyset ${k.id} does not match its keys`,
        );
      storeKeyset({
        id: k.id,
        mint,
        unit: k.unit,
        active: k.active,
        feePpk: k.input_fee_ppk,
        keys: ks,
        updated: now(),
      });
    });
    synced.set(mint, now());
  }

  function activeKeyset(mint: string, unit: string): CashuKeysetRow | null {
    let best: CashuKeysetRow | null = null;
    for (const k of keysetMap(mint).values())
      if (
        k.unit === unit &&
        k.active &&
        (best === null || k.feePpk < best.feePpk)
      )
        best = k;
    return best;
  }

  function balance(mint: string, unit: string): number {
    return ledger.proofBalance(mint, unit);
  }

  function makeOutputs(
    keyset: CashuKeysetRow,
    amounts: readonly number[],
    role: 'send' | 'keep',
    lock: Lock | null,
  ): OutputRow[] {
    return amounts.map((amount) => {
      const secret =
        lock === null ? hex32() : p2pkSecret(lock.pubkey, lock.tags, hex32());
      const r = randomScalar(random);
      const { B_, Y } = blind(secret, r);
      return {
        amount,
        id: keyset.id,
        B_,
        Y,
        secret,
        r: scalarHex(r),
        role,
      };
    });
  }

  const wire = (o: readonly OutputRow[]): BlindedMessage[] =>
    o.map(({ amount, id, B_ }) => ({ amount, id, B_ }));

  // Pick inputs for a payment of `amount` (net of the receiver's input fee,
  // NUT-18) and work out every fee. Pure: reads the ledger, writes nothing.
  function planSend(
    mint: string,
    unit: CashuUnit,
    amount: number,
  ): SendPlan | WalletError {
    const active = activeKeyset(mint, unit);
    if (active === null) return new WalletError('mint_has_no_active_keyset');
    // Send enough that the receiver still nets `amount` after redeeming.
    let sendTotal = amount;
    for (let i = 0; i < 64; i++) {
      const recvFee = feeOf(
        splitAmount(sendTotal, active.keys).map(() => active.feePpk),
      );
      if (sendTotal - recvFee >= amount) break;
      sendTotal = amount + recvFee;
    }
    const keysets = keysetMap(mint);
    const proofs = ledger
      .listProofs(mint, unit, 'unspent')
      .filter((p) => keysets.has(p.id))
      .sort((a, b) => {
        // Spend proofs of inactive keysets first (NUT-02), then big ones.
        const ia = keysets.get(a.id)?.active ? 1 : 0;
        const ib = keysets.get(b.id)?.active ? 1 : 0;
        return ia - ib || b.amount - a.amount;
      });
    const picked: typeof proofs = [];
    let sum = 0;
    let ppk = 0;
    let feeIn = 0;
    for (const p of proofs) {
      if (sum >= sendTotal + feeIn) break;
      picked.push(p);
      sum += p.amount;
      ppk += keysets.get(p.id)?.feePpk ?? 0;
      feeIn = feeOfPpk(ppk);
    }
    if (sum < sendTotal + feeIn)
      return new WalletError(
        'insufficient_balance',
        `${mint} has ${balance(mint, unit)} ${unit}, needs ${sendTotal + feeIn}`,
      );
    return {
      mint,
      unit,
      amount,
      sendTotal,
      fee: sendTotal - amount + feeIn,
      inputs: picked,
      sendAmounts: splitAmount(sendTotal, active.keys),
      keepAmounts: splitAmount(sum - sendTotal - feeIn, active.keys),
      keysetId: active.id,
    };
  }

  // Phase 1 (inside the caller's ledger transaction): reserve the inputs and
  // record the outputs before anything is sent to the mint.
  function reserveSend(
    plan: SendPlan,
    opId: string,
    lock: Lock | null,
    extra: Record<string, unknown>,
  ): void {
    const keyset = keysetMap(plan.mint).get(plan.keysetId);
    if (keyset === undefined) throw new WalletError('keyset_missing');
    const ys = plan.inputs.map((p) => p.y);
    if (ledger.setProofState(ys, 'unspent', 'reserved', opId) !== ys.length)
      throw new WalletError('proofs_busy');
    const outputs = [
      ...makeOutputs(keyset, plan.sendAmounts, 'send', lock),
      ...makeOutputs(keyset, plan.keepAmounts, 'keep', null),
    ].sort((a, b) => a.amount - b.amount);
    ledger.putOp({
      id: opId,
      kind: 'send',
      mint: plan.mint,
      unit: plan.unit,
      state: 'swap_pending',
      data: {
        ...extra,
        lock,
        amount: plan.amount,
        fee: plan.fee,
        inputs: plan.inputs.map(toInput),
        outputs,
      },
      ts: now(),
      updated: now(),
    });
  }

  function opInputs(op: CashuOpRow): WireProof[] {
    return (op.data['inputs'] as InputRow[]).map(({ y: _y, ...w }) => w);
  }

  function inputYs(op: CashuOpRow): string[] {
    return (op.data['inputs'] as InputRow[]).map((p) => p.y);
  }

  function opOutputs(op: CashuOpRow): OutputRow[] {
    return op.data['outputs'] as OutputRow[];
  }

  // Unblind, check the DLEQ proofs, and settle the ledger. Runs in a
  // transaction so the inputs, the change and the token change together.
  function finalize(
    op: CashuOpRow,
    sigs: readonly BlindSignature[],
  ): string | null {
    const outputs = opOutputs(op);
    if (sigs.length !== outputs.length)
      throw new WalletError('mint_bad_response', 'signature count');
    const keysets = keysetMap(op.mint);
    const sent: TokenProof[] = [];
    const sentRows: CashuProofRow[] = [];
    const keep: CashuProofRow[] = [];
    outputs.forEach((o, i) => {
      const s = sigs[i] as BlindSignature;
      if (s.amount !== o.amount || s.id !== o.id)
        throw new WalletError('mint_bad_response', 'signature mismatch');
      const K = keysets.get(o.id)?.keys[String(o.amount)];
      if (K === undefined) throw new WalletError('keyset_missing');
      if (
        s.dleq !== undefined &&
        !verifyBlindDleq(s.dleq.e, s.dleq.s, K, o.B_, s.C_)
      )
        throw new WalletError('mint_bad_dleq');
      const row = {
        y: o.Y,
        id: o.id,
        amount: o.amount,
        secret: o.secret,
        C: unblind(s.C_, BigInt(`0x${o.r}`), K),
      };
      if (o.role === 'keep') return void keep.push(row);
      sentRows.push(row);
      const p: TokenProof = {
        id: o.id,
        amount: o.amount,
        secret: o.secret,
        C: row.C,
      };
      if (s.dleq !== undefined) p.dleq = { e: s.dleq.e, s: s.dleq.s, r: o.r };
      sent.push(p);
    });
    return ledger.transaction(() => {
      if (ownsInputs(op))
        ledger.setProofState(inputYs(op), 'reserved', 'spent', op.id);
      ledger.addProofs(op.mint, op.unit, keep, 'unspent', null, now());
      let token: string | null = null;
      if (sent.length > 0) {
        token = encodeTokenV4({ mint: op.mint, unit: op.unit, proofs: sent });
        ledger.addProofs(op.mint, op.unit, sentRows, 'spent', op.id, now());
      }
      ledger.putOp({
        ...op,
        state: 'swapped',
        data: { ...op.data, token },
        updated: now(),
      });
      return token;
    });
  }

  function release(op: CashuOpRow, spentYs: ReadonlySet<string>): void {
    ledger.transaction(() => {
      if (ownsInputs(op)) {
        const ys = inputYs(op);
        const spent = ys.filter((y) => spentYs.has(y));
        ledger.setProofState(spent, 'reserved', 'spent', null);
        ledger.setProofState(
          ys.filter((y) => !spentYs.has(y)),
          'reserved',
          'unspent',
          null,
        );
      }
      ledger.putOp({ ...op, state: 'released', updated: now() });
    });
  }

  // The mint's answer to a swap was lost. Ask it to re-issue the signatures
  // (NUT-09); if it never signed, find out whether the inputs are still ours.
  async function recover(op: CashuOpRow): Promise<SwapOutcome> {
    const c = deps.client(op.mint);
    const outputs = opOutputs(op);
    try {
      const r = await c.restore(wire(outputs));
      const byB = new Map(r.outputs.map((o, i) => [o.B_, r.signatures[i]]));
      const sigs = outputs.map((o) => byB.get(o.B_));
      if (sigs.every((s) => s !== undefined))
        return ok(op, finalize(op, sigs as BlindSignature[]));
      const ys = inputYs(op);
      // A mint operation has no inputs to check: only restore can tell.
      if (ys.length === 0)
        return { kind: 'unknown', detail: 'mint did not re-issue the outputs' };
      const states = await c.checkState(ys);
      if (states.some((s) => s.state === 'PENDING'))
        return { kind: 'unknown', detail: 'inputs pending at the mint' };
      if (states.every((s) => s.state === 'UNSPENT')) {
        release(op, new Set());
        return { kind: 'refused', detail: 'mint did not process the swap' };
      }
      ledger.putOp({ ...op, state: 'failed', updated: now() });
      return {
        kind: 'unknown',
        detail: 'inputs spent but outputs not restorable',
      };
    } catch (e) {
      if (e instanceof MintUnavailable || e instanceof MintRefused)
        return { kind: 'unknown', detail: e.message };
      throw e;
    }
  }

  const ok = (op: CashuOpRow, token: string | null): SwapOutcome => ({
    kind: 'ok',
    token,
    amount: Number(op.data['amount'] ?? 0),
  });

  // Phase 2: ask the mint. Never throws for mint problems.
  async function runSwap(opId: string): Promise<SwapOutcome> {
    const op = ledger.getOp(opId);
    if (op === null) throw new WalletError('op_missing', opId);
    if (op.state === 'swapped')
      return ok(op, (op.data['token'] as string | null) ?? null);
    if (op.state === 'released') return { kind: 'refused', detail: 'released' };
    if (op.state !== 'swap_pending')
      return { kind: 'unknown', detail: op.state };
    // A swap that was already sent once (before a crash or a lost answer) is
    // never sent again: if the mint processed it, a second swap would fail as
    // "already spent" and the signed outputs would be given up. Restore them.
    if (op.data['attempted'] === true) return recover(op);
    ledger.putOp({
      ...op,
      data: { ...op.data, attempted: true },
      updated: now(),
    });
    const c = deps.client(op.mint);
    let sigs: BlindSignature[];
    try {
      sigs = await c.swap(opInputs(op), wire(opOutputs(op)));
    } catch (e) {
      if (e instanceof MintRefused) {
        // 11001: some input was already spent; learn which before releasing.
        const spent = new Set<string>();
        try {
          for (const s of await c.checkState(inputYs(op)))
            if (s.state !== 'UNSPENT') spent.add(s.Y);
        } catch {
          // keep them all unspent; the next swap will find out again
        }
        release(op, spent);
        return { kind: 'refused', detail: e.message };
      }
      if (e instanceof MintUnavailable) return recover(op);
      throw e;
    }
    try {
      return ok(op, finalize(op, sigs));
    } catch (e) {
      if (!(e instanceof WalletError)) throw e;
      // The mint consumed the inputs but sent signatures we cannot use.
      ledger.putOp({ ...op, state: 'failed', updated: now() });
      return { kind: 'unknown', detail: e.message };
    }
  }

  // Take back an unlocked token that was handed out but not redeemed (the
  // merchant refused it or never answered). Returns 'reclaimed' when the
  // ecash is back in the wallet, 'spent' when the merchant has it.
  async function reclaim(
    opId: string,
  ): Promise<
    { kind: 'reclaimed'; amount: number } | { kind: 'spent' | 'unknown' }
  > {
    const op = ledger.getOp(opId);
    const token = op?.data['token'];
    if (op === null || typeof token !== 'string') return { kind: 'unknown' };
    if (op.data['lock'] !== null) return { kind: 'unknown' };
    const t = decodeToken(token);
    try {
      const states = await deps
        .client(op.mint)
        .checkState(t.proofs.map((p) => proofY(p.secret)));
      if (states.some((s) => s.state !== 'UNSPENT')) return { kind: 'spent' };
      const rid = `${opId}:reclaim`;
      const r = await receiveProofs(op.mint, op.unit, t.proofs, rid);
      if (r.kind !== 'ok')
        return { kind: r.kind === 'refused' ? 'spent' : 'unknown' };
      ledger.putOp({ ...op, state: 'reclaimed', updated: now() });
      return { kind: 'reclaimed', amount: r.amount };
    } catch (e) {
      if (e instanceof MintUnavailable || e instanceof MintRefused)
        return { kind: 'unknown' };
      throw e;
    }
  }

  async function receiveProofs(
    mint: string,
    unit: string,
    proofs: readonly TokenProof[],
    opId: string,
  ): Promise<SwapOutcome> {
    const keyset = activeKeyset(mint, unit);
    if (keyset === null) throw new WalletError('mint_has_no_active_keyset');
    const keysets = keysetMap(mint);
    const inputs: InputRow[] = proofs.map((p) => {
      // V4 tokens may carry the 8-byte short id of a V2 keyset (NUT-00).
      let id = p.id;
      if (!keysets.has(id)) {
        const full = [...keysets.keys()].filter((k) => k.startsWith(id));
        if (full.length !== 1) throw new WalletError('unknown_keyset', id);
        id = full[0] as string;
      }
      return {
        id,
        amount: p.amount,
        secret: p.secret,
        C: p.C,
        y: proofY(p.secret),
      };
    });
    const total = inputs.reduce((s, p) => s + p.amount, 0);
    const fee = feeOf(inputs.map((p) => keysets.get(p.id)?.feePpk ?? 0));
    if (total - fee <= 0) throw new WalletError('token_too_small');
    const outputs = makeOutputs(
      keyset,
      splitAmount(total - fee, keyset.keys),
      'keep',
      null,
    );
    ledger.putOp({
      id: opId,
      kind: 'receive',
      mint,
      unit,
      state: 'swap_pending',
      data: {
        lock: null,
        inputs,
        outputs,
        amount: total - fee,
        fee,
      },
      ts: now(),
      updated: now(),
    });
    return runSwap(opId);
  }

  function checkMaxBalance(
    mint: string,
    unit: string,
    adding: number,
    max: bigint | null,
  ): void {
    if (max !== null && BigInt(balance(mint, unit) + adding) > max)
      throw new WalletError(
        'max_balance',
        `${mint} would hold more than its max_balance of ${max} ${unit}`,
      );
  }

  // --- operator commands -----------------------------------------------

  async function receive(
    token: string,
    allowed: (
      mint: string,
      unit: string,
    ) => { maxBalance: bigint | null } | null,
  ): Promise<{ mint: string; unit: string; amount: number }> {
    const t = decodeToken(token);
    const mint = normalizeMintUrl(t.mint);
    const rule = allowed(mint, t.unit);
    if (rule === null)
      throw new WalletError(
        'mint_not_allowed',
        `${mint} (${t.unit}) is not in cashu.mints`,
      );
    if (t.proofs.some((p) => p.secret.startsWith('[')))
      throw new WalletError(
        'locked_token',
        'tokens with spending conditions are not supported',
      );
    await syncKeysets(mint);
    const amount = t.proofs.reduce((s, p) => s + p.amount, 0);
    checkMaxBalance(mint, t.unit, amount, rule.maxBalance);
    const r = await receiveProofs(
      mint,
      t.unit,
      t.proofs,
      `rcv_${hex32().slice(0, 24)}`,
    );
    if (r.kind !== 'ok')
      throw new WalletError(
        r.kind === 'refused' ? 'token_rejected' : 'mint_unavailable',
        r.detail,
      );
    return { mint, unit: t.unit, amount };
  }

  async function fundStart(
    mint: string,
    unit: CashuUnit,
    amount: number,
    maxBalance: bigint | null,
  ): Promise<{ opId: string; invoice: string }> {
    await syncKeysets(mint);
    if (activeKeyset(mint, unit) === null)
      throw new WalletError(
        'mint_has_no_active_keyset',
        `${mint} has no ${unit} keyset`,
      );
    checkMaxBalance(mint, unit, amount, maxBalance);
    const info = await mintInfo(mint);
    // NUT-20: lock the quote to a key so nobody who learns its id can mint it.
    const kp = supports(info, '20') ? newKeyPair(random) : null;
    const q = await deps.client(mint).mintQuote(amount, unit, kp?.pub ?? null);
    const opId = `mint_${hex32().slice(0, 24)}`;
    ledger.putOp({
      id: opId,
      kind: 'mint',
      mint,
      unit,
      state: 'quote',
      data: {
        quote: q.quote,
        invoice: q.request,
        amount,
        priv: kp === null ? null : bytesToHex(kp.priv),
      },
      ts: now(),
      updated: now(),
    });
    return { opId, invoice: q.request };
  }

  async function fundFinish(
    opId: string,
    opts: {
      timeoutMs: number;
      pollMs: number;
      sleep: (ms: number) => Promise<void>;
    },
  ): Promise<number> {
    let op = ledger.getOp(opId);
    if (op === null || op.kind !== 'mint')
      throw new WalletError('op_missing', opId);
    const c = deps.client(op.mint);
    const quote = String(op.data['quote']);
    const deadline = now() + opts.timeoutMs;
    if (op.state === 'quote') {
      for (;;) {
        const q = await c.checkMintQuote(quote);
        if (q.amount_paid - q.amount_issued >= Number(op.data['amount'])) break;
        if (now() > deadline)
          throw new WalletError(
            'invoice_not_paid',
            'timed out waiting for payment',
          );
        await opts.sleep(opts.pollMs);
      }
      const keyset = activeKeyset(op.mint, op.unit);
      if (keyset === null) throw new WalletError('mint_has_no_active_keyset');
      const outputs = makeOutputs(
        keyset,
        splitAmount(Number(op.data['amount']), keyset.keys),
        'keep',
        null,
      );
      op = {
        ...op,
        state: 'minting',
        data: { ...op.data, inputs: [], outputs },
        updated: now(),
      };
      ledger.putOp(op);
    }
    if (op.state === 'swapped') return Number(op.data['amount']);
    const outputs = opOutputs(op);
    const priv = op.data['priv'];
    const sig =
      typeof priv === 'string'
        ? schnorrSign(mintQuoteMessage(quote, wire(outputs)), hexToBytes(priv))
        : null;
    try {
      const sigs = await c.mint(quote, wire(outputs), sig);
      finalize(op, sigs);
    } catch (e) {
      if (e instanceof MintUnavailable) {
        const r = await recover(op);
        if (r.kind !== 'ok')
          throw new WalletError(
            'mint_unavailable',
            'run the command again to finish',
          );
      } else throw e;
    }
    return Number(op.data['amount']);
  }

  async function withdraw(
    mint: string,
    unit: CashuUnit,
    invoice: string,
  ): Promise<{ amount: number; fee: number }> {
    await syncKeysets(mint);
    const c = deps.client(mint);
    const q = await c.meltQuote(invoice, unit);
    const keyset = activeKeyset(mint, unit);
    if (keyset === null) throw new WalletError('mint_has_no_active_keyset');
    const opId = `melt_${hex32().slice(0, 24)}`;
    const op = ledger.transaction(() => {
      const plan = planSend(mint, unit, q.amount + q.fee_reserve);
      if (plan instanceof WalletError) throw plan;
      // Melt spends the inputs directly: fee is only the keyset input fee.
      const keysets = keysetMap(mint);
      const inputs = plan.inputs;
      // Everything above the invoice comes back as NUT-08 change: the unused
      // fee reserve and the overshoot of the picked proofs. Enough blank
      // outputs for that whole amount, or the rest is lost to the mint.
      const over = inputs.reduce((s, p) => s + p.amount, 0) - q.amount;
      const blanks = over > 0 ? Math.ceil(Math.log2(over + 1)) : 0;
      const ys = inputs.map((p) => p.y);
      if (ledger.setProofState(ys, 'unspent', 'reserved', opId) !== ys.length)
        throw new WalletError('proofs_busy');
      const outputs = makeOutputs(
        keyset,
        Array.from({ length: blanks }, () => 0),
        'keep',
        null,
      );
      const row: CashuOpRow = {
        id: opId,
        kind: 'melt',
        mint,
        unit,
        state: 'melt_pending',
        data: {
          quote: q.quote,
          amount: q.amount,
          inputs: inputs.map(toInput),
          outputs,
          feeIn: feeOf(inputs.map((p) => keysets.get(p.id)?.feePpk ?? 0)),
        },
        ts: now(),
        updated: now(),
      };
      ledger.putOp(row);
      return row;
    });
    let res: MeltQuote;
    try {
      res = await c.melt(q.quote, opInputs(op), wire(opOutputs(op)));
    } catch (e) {
      if (e instanceof MintRefused) {
        release(op, new Set());
        throw new WalletError('melt_refused', e.message);
      }
      throw new WalletError(
        'melt_pending',
        `no answer from the mint (${(e as Error).message}). ${PENDING_HINT}`,
      );
    }
    if (res.state === 'PAID') {
      const r = settleMelt(op.id, changeFromMelt(op, res.change ?? []));
      if (r !== null) return r;
    }
    // Not finished (or a failure the mint reports as UNPAID): settle it the
    // same way the background recovery does.
    const r = await finishMelt(op);
    if (r.kind === 'paid') return r;
    if (r.kind === 'failed')
      throw new WalletError(
        'melt_failed',
        'the lightning payment failed; the ecash is back in the wallet',
      );
    throw new WalletError(
      'melt_pending',
      `the lightning payment is still in flight. ${PENDING_HINT}`,
    );
  }

  // Change for overpaid fees comes back on the first blank outputs (NUT-08).
  function changeFromMelt(
    op: CashuOpRow,
    change: readonly BlindSignature[],
  ): { o: OutputRow; s: BlindSignature }[] {
    const blanks = opOutputs(op);
    return change.map((s, i) => ({ o: blanks[i] as OutputRow, s }));
  }

  // Record a paid melt once: inputs spent, change in the wallet. Returns null
  // when someone (the CLI or the daemon's sweep) already settled it.
  function settleMelt(
    opId: string,
    change: readonly { o: OutputRow; s: BlindSignature }[],
  ): { kind: 'paid'; amount: number; fee: number } | null {
    return ledger.transaction(() => {
      const op = ledger.getOp(opId);
      if (op === null || op.state !== 'melt_pending') return null;
      const keysets = keysetMap(op.mint);
      const keep: CashuProofRow[] = change.map(({ o, s }) => {
        const K = keysets.get(s.id)?.keys[String(s.amount)];
        if (K === undefined) throw new WalletError('keyset_missing');
        return {
          y: o.Y,
          id: s.id,
          amount: s.amount,
          secret: o.secret,
          C: unblind(s.C_, BigInt(`0x${o.r}`), K),
        };
      });
      ledger.setProofState(inputYs(op), 'reserved', 'spent', op.id);
      ledger.addProofs(op.mint, op.unit, keep, 'unspent', null, now());
      ledger.putOp({ ...op, state: 'done', updated: now() });
      const amount = Number(op.data['amount']);
      const spentIn = opInputs(op).reduce((s, p) => s + p.amount, 0);
      const back = keep.reduce((s, p) => s + p.amount, 0);
      return { kind: 'paid' as const, amount, fee: spentIn - back - amount };
    });
  }

  // Find out how a withdrawal ended and settle it: paid (inputs spent, change
  // restored with NUT-09), failed (inputs back in the wallet), or still in
  // flight. Safe to run from the CLI and the daemon at the same time.
  async function finishMelt(
    op: CashuOpRow,
  ): Promise<
    | { kind: 'paid'; amount: number; fee: number }
    | { kind: 'failed' | 'pending' | 'unknown' }
  > {
    const c = deps.client(op.mint);
    try {
      const q = await c.checkMeltQuote(String(op.data['quote']));
      if (q.state === 'PENDING') return { kind: 'pending' };
      if (q.state === 'PAID') {
        let change =
          q.change === undefined ? null : changeFromMelt(op, q.change);
        if (change === null) {
          // The quote check does not have to repeat the change; the mint
          // re-issues it for our blank outputs (NUT-09).
          const outputs = opOutputs(op);
          const r =
            outputs.length === 0
              ? { outputs: [], signatures: [] }
              : await c.restore(wire(outputs));
          const byB = new Map(outputs.map((o) => [o.B_, o]));
          change = r.outputs.flatMap((w, i) => {
            const o = byB.get(w.B_);
            const s = r.signatures[i];
            return o === undefined || s === undefined ? [] : [{ o, s }];
          });
        }
        return settleMelt(op.id, change) ?? { kind: 'unknown' };
      }
      const states = await c.checkState(inputYs(op));
      if (states.some((s) => s.state === 'PENDING')) return { kind: 'pending' };
      release(
        op,
        new Set(states.filter((s) => s.state === 'SPENT').map((s) => s.Y)),
      );
      return { kind: 'failed' };
    } catch (e) {
      if (e instanceof MintUnavailable || e instanceof MintRefused)
        return { kind: 'unknown' };
      throw e;
    }
  }

  // Release or settle operations whose answer was lost (crash, network) and
  // withdrawals still in flight. Payment
  // ops ('send') are settled by the server, which also refunds the limits.
  async function sweep(
    olderThanMs: number,
  ): Promise<{ id: string; outcome: string }[]> {
    const out: { id: string; outcome: string }[] = [];
    for (const op of ledger.listOps('swap_pending')) {
      if (op.kind === 'send' || now() - op.updated < olderThanMs) continue;
      const r = await recover(op);
      out.push({ id: op.id, outcome: r.kind });
    }
    // Withdrawals whose lightning payment was still in flight.
    for (const op of ledger.listOps('melt_pending')) {
      if (now() - op.updated < olderThanMs) continue;
      const r = await finishMelt(op);
      out.push({ id: op.id, outcome: r.kind });
    }
    return out;
  }

  return {
    mintInfo,
    supports,
    syncKeysets,
    activeKeyset,
    balance,
    planSend,
    reserveSend,
    runSwap,
    reclaim,
    receive,
    fundStart,
    fundFinish,
    withdraw,
    sweep,
  };
}

export type Wallet = ReturnType<typeof createWallet>;
