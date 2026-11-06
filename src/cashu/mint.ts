// HTTP client for one Cashu mint (NUT-01..09, 12, 20, 23).
import { isRecord } from '../util.ts';

export type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export type BlindedMessage = { amount: number; id: string; B_: string };
export type BlindSignature = {
  amount: number;
  id: string;
  C_: string;
  dleq?: { e: string; s: string };
};
export type WireProof = {
  amount: number;
  id: string;
  secret: string;
  C: string;
  witness?: string;
};

// The mint answered and refused: nothing it was asked to do happened.
export class MintRefused extends Error {
  override name = 'MintRefused';
  readonly code: number | null;
  constructor(detail: string, code: number | null) {
    super(detail);
    this.code = code;
  }
}

// No usable answer (network, timeout, 5xx, garbage): the request may or may
// not have been processed, so callers must find out before retrying.
export class MintUnavailable extends Error {
  override name = 'MintUnavailable';
}

export type MintInfo = { nuts: Record<string, unknown>; name: string | null };

export type MintKeyset = {
  id: string;
  unit: string;
  active: boolean;
  input_fee_ppk: number;
  final_expiry: number | null;
};

export type MintQuote = {
  quote: string;
  request: string;
  amount: number | null;
  unit: string;
  expiry: number | null;
  amount_paid: number;
  amount_issued: number;
  state?: string;
};

export type MeltQuote = {
  quote: string;
  amount: number;
  fee_reserve: number;
  unit: string;
  state: 'UNPAID' | 'PENDING' | 'PAID';
  expiry: number;
  payment_preimage?: string | null;
  change?: BlindSignature[];
};

const MAX_RESPONSE = 4 * 1024 * 1024;

function int(v: unknown, field: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0)
    throw new MintUnavailable(`mint sent a bad ${field}`);
  return v;
}

function sigs(v: unknown): BlindSignature[] {
  if (!Array.isArray(v)) throw new MintUnavailable('mint sent no signatures');
  return v.map((s) => {
    if (
      !isRecord(s) ||
      typeof s['C_'] !== 'string' ||
      typeof s['id'] !== 'string'
    )
      throw new MintUnavailable('mint sent a bad signature');
    const out: BlindSignature = {
      amount: int(s['amount'], 'amount'),
      id: s['id'],
      C_: s['C_'],
    };
    const d = s['dleq'];
    if (isRecord(d) && typeof d['e'] === 'string' && typeof d['s'] === 'string')
      out.dleq = { e: d['e'], s: d['s'] };
    return out;
  });
}

export function createMintClient(
  url: string,
  opts: { fetch?: Fetch; timeoutMs?: number } = {},
) {
  const doFetch: Fetch = opts.fetch ?? ((u, i) => fetch(u, i));
  const timeout = opts.timeoutMs ?? 15_000;

  async function call(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    timeoutMs = timeout,
  ): Promise<Record<string, unknown> | unknown[]> {
    let res: Response;
    try {
      const init: RequestInit = {
        method,
        headers: { accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      };
      if (body !== undefined) {
        init.body = JSON.stringify(body);
        init.headers = { ...init.headers, 'content-type': 'application/json' };
      }
      res = await doFetch(`${url}${path}`, init);
    } catch (e) {
      throw new MintUnavailable(`${url}${path}: ${(e as Error).message}`);
    }
    let text: string;
    try {
      text = await res.text();
    } catch (e) {
      throw new MintUnavailable(`${url}${path}: ${(e as Error).message}`);
    }
    if (text.length > MAX_RESPONSE)
      throw new MintUnavailable(`${url}${path}: response too large`);
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new MintUnavailable(`${url}${path}: HTTP ${res.status}, not JSON`);
    }
    if (res.status === 400 && isRecord(json)) {
      const code = typeof json['code'] === 'number' ? json['code'] : null;
      const detail =
        typeof json['detail'] === 'string' ? json['detail'] : 'refused';
      throw new MintRefused(detail.slice(0, 300), code);
    }
    if (!res.ok) throw new MintUnavailable(`${url}${path}: HTTP ${res.status}`);
    if (!isRecord(json) && !Array.isArray(json))
      throw new MintUnavailable(`${url}${path}: unexpected response`);
    return json;
  }

  const obj = async (
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    t?: number,
  ) => {
    const j = await call(method, path, body, t);
    if (!isRecord(j)) throw new MintUnavailable(`${path}: expected an object`);
    return j;
  };

  return {
    url,
    async info(): Promise<MintInfo> {
      const j = await obj('GET', '/v1/info');
      return {
        nuts: isRecord(j['nuts']) ? j['nuts'] : {},
        name: typeof j['name'] === 'string' ? j['name'] : null,
      };
    },
    async keysets(): Promise<MintKeyset[]> {
      const j = await obj('GET', '/v1/keysets');
      if (!Array.isArray(j['keysets']))
        throw new MintUnavailable('mint sent no keysets');
      return j['keysets'].filter(isRecord).map((k) => ({
        id: String(k['id']),
        unit: String(k['unit']),
        active: k['active'] === true,
        input_fee_ppk:
          typeof k['input_fee_ppk'] === 'number' ? k['input_fee_ppk'] : 0,
        final_expiry:
          typeof k['final_expiry'] === 'number' ? k['final_expiry'] : null,
      }));
    },
    async keys(id: string): Promise<Record<string, string>> {
      if (!/^[0-9a-f]{16,66}$/.test(id))
        throw new MintUnavailable('bad keyset id');
      const j = await obj('GET', `/v1/keys/${id}`);
      const ks = Array.isArray(j['keysets']) ? j['keysets'] : [];
      const k = ks.find((x) => isRecord(x) && x['id'] === id);
      if (!isRecord(k) || !isRecord(k['keys']))
        throw new MintUnavailable(`mint sent no keys for ${id}`);
      const out: Record<string, string> = {};
      for (const [amt, pk] of Object.entries(k['keys'])) {
        if (
          !/^\d+$/.test(amt) ||
          typeof pk !== 'string' ||
          !/^0[23][0-9a-fA-F]{64}$/.test(pk)
        )
          throw new MintUnavailable('mint sent a bad key');
        out[amt] = pk.toLowerCase();
      }
      return out;
    },
    async swap(
      inputs: WireProof[],
      outputs: BlindedMessage[],
    ): Promise<BlindSignature[]> {
      const j = await obj('POST', '/v1/swap', { inputs, outputs });
      return sigs(j['signatures']);
    },
    async restore(outputs: BlindedMessage[]): Promise<{
      outputs: BlindedMessage[];
      signatures: BlindSignature[];
    }> {
      const j = await obj('POST', '/v1/restore', { outputs });
      const outs = Array.isArray(j['outputs']) ? j['outputs'] : [];
      return {
        outputs: outs.filter(isRecord).map((o) => ({
          amount: Number(o['amount']),
          id: String(o['id']),
          B_: String(o['B_']),
        })),
        signatures: sigs(j['signatures'] ?? []),
      };
    },
    async checkState(
      ys: string[],
    ): Promise<{ Y: string; state: 'UNSPENT' | 'PENDING' | 'SPENT' }[]> {
      const j = await obj('POST', '/v1/checkstate', { Ys: ys });
      if (!Array.isArray(j['states']))
        throw new MintUnavailable('mint sent no states');
      return j['states'].filter(isRecord).map((s) => {
        const st = s['state'];
        if (st !== 'UNSPENT' && st !== 'PENDING' && st !== 'SPENT')
          throw new MintUnavailable('mint sent a bad state');
        return { Y: String(s['Y']), state: st };
      });
    },
    async mintQuote(
      amount: number,
      unit: string,
      pubkey: string | null,
    ): Promise<MintQuote> {
      const body: Record<string, unknown> = { amount, unit };
      if (pubkey !== null) body['pubkey'] = pubkey;
      return mintQuoteOf(await obj('POST', '/v1/mint/quote/bolt11', body));
    },
    async checkMintQuote(id: string): Promise<MintQuote> {
      return mintQuoteOf(
        await obj('GET', `/v1/mint/quote/bolt11/${encodeURIComponent(id)}`),
      );
    },
    async mint(
      quote: string,
      outputs: BlindedMessage[],
      signature: string | null,
    ): Promise<BlindSignature[]> {
      const body: Record<string, unknown> = { quote, outputs };
      if (signature !== null) body['signature'] = signature;
      const j = await obj('POST', '/v1/mint/bolt11', body);
      return sigs(j['signatures']);
    },
    async meltQuote(request: string, unit: string): Promise<MeltQuote> {
      return meltQuoteOf(
        await obj('POST', '/v1/melt/quote/bolt11', { request, unit }),
      );
    },
    async checkMeltQuote(id: string): Promise<MeltQuote> {
      return meltQuoteOf(
        await obj('GET', `/v1/melt/quote/bolt11/${encodeURIComponent(id)}`),
      );
    },
    async melt(
      quote: string,
      inputs: WireProof[],
      outputs: BlindedMessage[],
    ): Promise<MeltQuote> {
      return meltQuoteOf(
        await obj(
          'POST',
          '/v1/melt/bolt11',
          { quote, inputs, outputs },
          10 * 60_000,
        ),
      );
    },
  };
}

function mintQuoteOf(j: Record<string, unknown>): MintQuote {
  if (typeof j['quote'] !== 'string' || typeof j['request'] !== 'string')
    throw new MintUnavailable('mint sent a bad quote');
  // Older mints only send `state`; derive the NUT-04 accounting from it.
  const state = typeof j['state'] === 'string' ? j['state'] : undefined;
  const amount = typeof j['amount'] === 'number' ? j['amount'] : null;
  const paid =
    typeof j['amount_paid'] === 'number'
      ? j['amount_paid']
      : state === 'PAID' || state === 'ISSUED'
        ? (amount ?? 0)
        : 0;
  const issued =
    typeof j['amount_issued'] === 'number'
      ? j['amount_issued']
      : state === 'ISSUED'
        ? (amount ?? 0)
        : 0;
  const out: MintQuote = {
    quote: j['quote'],
    request: j['request'],
    amount,
    unit: String(j['unit'] ?? ''),
    expiry: typeof j['expiry'] === 'number' ? j['expiry'] : null,
    amount_paid: paid,
    amount_issued: issued,
  };
  if (state !== undefined) out.state = state;
  return out;
}

function meltQuoteOf(j: Record<string, unknown>): MeltQuote {
  const st = j['state'];
  if (
    typeof j['quote'] !== 'string' ||
    (st !== 'UNPAID' && st !== 'PENDING' && st !== 'PAID')
  )
    throw new MintUnavailable('mint sent a bad melt quote');
  const out: MeltQuote = {
    quote: j['quote'],
    amount: int(j['amount'], 'amount'),
    fee_reserve: typeof j['fee_reserve'] === 'number' ? j['fee_reserve'] : 0,
    unit: String(j['unit'] ?? ''),
    state: st,
    expiry: typeof j['expiry'] === 'number' ? j['expiry'] : 0,
  };
  if (typeof j['payment_preimage'] === 'string')
    out.payment_preimage = j['payment_preimage'];
  if (Array.isArray(j['change'])) out.change = sigs(j['change']);
  return out;
}

export type MintClient = ReturnType<typeof createMintClient>;
