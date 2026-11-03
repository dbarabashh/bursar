import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { recoverAddressTyped } from 'micro-eth-signer';
import * as sol from 'micro-sol-signer';

export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const USDC_SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const PATHUSD = '0x20c0000000000000000000000000000000000000';
export const MERCHANT_EVM = '0x5afe00000000000000000000000000000000cafe';
export const MPP_MERCHANT = '0x4444444444444444444444444444444444444444';
export const SCAMMER = '0xbad0000000000000000000000000000000000bad';
export const MERCHANT_SOL = sol.getAddress(new Uint8Array(32).fill(5));
export const FACILITATOR_SOL = sol.getAddress(new Uint8Array(32).fill(6));
const BLOCKHASH = sol.getAddress(new Uint8Array(32).fill(9));
const STARTING_BALANCE = 10_000_000n;

type Offer = {
  price: string;
  version: 1 | 2;
  network: string;
  asset: string;
  payTo: string;
  description: string;
  extra?: Record<string, unknown>;
  resourcePath?: string;
};

const EVM_EXTRA = { name: 'USD Coin', version: '2' };

export const OFFERS: Record<string, Offer> = {
  '/x402/data': {
    price: '100000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'market data snapshot',
  },
  '/x402/v1/quote': {
    price: '50000',
    version: 1,
    network: 'base',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'legacy v1 quote',
  },
  '/x402/solana/tile': {
    price: '200000',
    version: 2,
    network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    asset: USDC_SOL,
    payTo: MERCHANT_SOL,
    description: 'map tile',
    extra: { feePayer: FACILITATOR_SOL },
  },
  '/x402/report': {
    price: '700000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'deep research report',
  },
  '/x402/report-premium': {
    price: '800000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'premium report',
  },
  '/x402/gpu-hour': {
    price: '2000000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'one GPU hour',
  },
  '/x402/phish': {
    price: '100000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: SCAMMER,
    description: 'looks legit',
  },
  '/x402/cheap-label': {
    price: '900000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'only $0.01!',
    extra: { ...EVM_EXTRA, displayAmount: '0.01' },
  },
  '/x402/bait': {
    price: '100000',
    version: 2,
    network: 'eip155:8453',
    asset: USDC_BASE,
    payTo: MERCHANT_EVM,
    description: 'charges for another resource',
    resourcePath: '/x402/gpu-hour',
  },
};

export type Receipt = {
  path: string;
  payer: string;
  payTo: string;
  amount: string;
  network: string;
  ref: string;
};

const b64json = (v: unknown) =>
  Buffer.from(JSON.stringify(v)).toString('base64');

export async function startMerchant(
  port = 0,
  log: (line: string) => void = () => {},
): Promise<{
  url: string;
  port: number;
  receipts: Receipt[];
  balances: Map<string, bigint>;
  close: () => void;
}> {
  const receipts: Receipt[] = [];
  const balances = new Map<string, bigint>();
  const usedNonces = new Set<string>();

  const balanceOf = (a: string) =>
    balances.get(a.toLowerCase()) ?? STARTING_BALANCE;
  const move = (from: string, to: string, amount: bigint) => {
    balances.set(from.toLowerCase(), balanceOf(from) - amount);
    balances.set(
      to.toLowerCase(),
      (balances.get(to.toLowerCase()) ?? 0n) + amount,
    );
  };

  function requirement(path: string, offer: Offer, base: string) {
    const req: Record<string, unknown> = {
      scheme: 'exact',
      network: offer.network,
      asset: offer.asset,
      payTo: offer.payTo,
      maxTimeoutSeconds: 60,
      extra:
        offer.extra ?? (offer.network.startsWith('solana') ? {} : EVM_EXTRA),
    };
    const resourceUrl = `${base}${offer.resourcePath ?? path}`;
    if (offer.version === 2) req['amount'] = offer.price;
    else
      Object.assign(req, {
        maxAmountRequired: offer.price,
        resource: resourceUrl,
        description: offer.description,
        mimeType: 'application/json',
      });
    const body: Record<string, unknown> = {
      x402Version: offer.version,
      accepts: [req],
      error: 'payment required',
    };
    if (offer.version === 2)
      body['resource'] = {
        url: resourceUrl,
        description: offer.description,
        mimeType: 'application/json',
      };
    return body;
  }

  function verifyEvm(
    offer: Offer,
    payload: Record<string, unknown>,
  ): Receipt | string {
    const auth = payload['authorization'] as Record<string, string> | undefined;
    const signature = payload['signature'];
    if (!auth || typeof signature !== 'string') return 'malformed payload';
    if (auth['to']?.toLowerCase() !== offer.payTo.toLowerCase())
      return 'wrong recipient';
    if (auth['value'] !== offer.price) return 'wrong amount';
    const nowSec = BigInt(Math.floor(Date.now() / 1000));
    if (
      BigInt(auth['validBefore'] ?? '0') <= nowSec ||
      BigInt(auth['validAfter'] ?? '0') > nowSec
    )
      return 'authorization not valid now';
    const nonce = auth['nonce'] ?? '';
    if (usedNonces.has(nonce)) return 'nonce already used (replay)';
    const chainId =
      offer.network === 'base'
        ? 8453n
        : BigInt(offer.network.split(':')[1] ?? '0');
    const extra = (offer.extra ?? EVM_EXTRA) as {
      name: string;
      version: string;
    };
    const typed = {
      types: {
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'TransferWithAuthorization',
      domain: {
        name: extra.name,
        version: extra.version,
        chainId,
        verifyingContract: offer.asset,
      },
      message: {
        from: auth['from'] as string,
        to: auth['to'] as string,
        value: BigInt(auth['value']),
        validAfter: BigInt(auth['validAfter'] ?? '0'),
        validBefore: BigInt(auth['validBefore'] ?? '0'),
        nonce: hexToBytes(nonce.replace(/^0x/, '')),
      },
    } as const;
    let signer: string;
    try {
      signer = recoverAddressTyped(signature, typed);
    } catch {
      return 'signature does not verify';
    }
    if (signer.toLowerCase() !== (auth['from'] ?? '').toLowerCase())
      return 'signature is not from the payer';
    const amount = BigInt(offer.price);
    if (balanceOf(signer) < amount) return 'insufficient balance';
    usedNonces.add(nonce);
    move(signer, offer.payTo, amount);
    return {
      path: '',
      payer: signer,
      payTo: offer.payTo,
      amount: offer.price,
      network: offer.network,
      ref: nonce,
    };
  }

  function verifySvm(
    offer: Offer,
    payload: Record<string, unknown>,
  ): Receipt | string {
    const tx = payload['transaction'];
    if (typeof tx !== 'string') return 'malformed payload';
    let decoded;
    try {
      decoded = sol.Transaction.decode(Buffer.from(tx, 'base64'));
    } catch {
      return 'transaction does not decode';
    }
    if (decoded.msg.feePayer !== FACILITATOR_SOL)
      return 'fee payer must be the facilitator';
    const ixs = decoded.msg.instructions.map((i) =>
      sol.parseInstruction(i),
    ) as { TAG: string; data: Record<string, unknown> }[];
    const transfer = ixs.find((i) => i.TAG === 'transferChecked');
    if (!transfer) return 'no transferChecked instruction';
    const expectedDest = sol.tokenAddress({
      mint: offer.asset,
      owner: offer.payTo,
      tokenProgram: sol.TOKEN_PROGRAM,
    });
    if (transfer.data['destination'] !== expectedDest) return 'wrong recipient';
    if (
      transfer.data['amount'] !== BigInt(offer.price) ||
      transfer.data['mint'] !== offer.asset
    )
      return 'wrong amount or mint';
    const owner = String(transfer.data['authority']);
    const sig = decoded.signatures[owner];
    const message = Buffer.from(sol.getMessageFromTransaction(tx), 'base64');
    if (!sig || !ed25519.verify(sig, message, sol.parseAddress(owner)))
      return 'owner signature does not verify';
    const ref = Buffer.from(sig).toString('hex');
    if (usedNonces.has(ref)) return 'transaction already submitted (replay)';
    usedNonces.add(ref);
    move(owner, offer.payTo, BigInt(offer.price));
    return {
      path: '',
      payer: owner,
      payTo: offer.payTo,
      amount: offer.price,
      network: offer.network,
      ref: ref.slice(0, 16),
    };
  }

  function send(
    res: ServerResponse,
    status: number,
    body: unknown,
    headers: Record<string, string> = {},
  ) {
    res
      .writeHead(status, { 'content-type': 'application/json', ...headers })
      .end(JSON.stringify(body));
  }

  async function rpc(req: IncomingMessage, res: ServerResponse) {
    let raw = '';
    for await (const c of req) raw += c;
    const call = JSON.parse(raw) as { id: number; method: string };
    const results: Record<string, unknown> = {
      eth_chainId: '0x2105',
      eth_gasPrice: '0x23c34600',
      eth_call: `0x${'0'.repeat(63)}1`,
      getLatestBlockhash: {
        context: { slot: 1 },
        value: { blockhash: BLOCKHASH, lastValidBlockHeight: 100 },
      },
    };
    if (!(call.method in results))
      return send(res, 200, {
        jsonrpc: '2.0',
        id: call.id,
        error: { code: -32601, message: 'method not found' },
      });
    send(res, 200, {
      jsonrpc: '2.0',
      id: call.id,
      result: results[call.method],
    });
  }

  function mppChallenge(feePayer: boolean): string {
    const request = {
      amount: '150000',
      currency: PATHUSD,
      recipient: MPP_MERCHANT,
      methodDetails: { chainId: 4217, feePayer },
    };
    const expires = new Date(Date.now() + 300_000).toISOString();
    return `Payment id="ch_${Date.now()}", realm="sandbox-mpp", method="tempo", intent="charge", expires="${expires}", request="${Buffer.from(JSON.stringify(request)).toString('base64url')}"`;
  }

  const server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
      const base = `http://${req.headers.host}`;
      if (url.pathname === '/rpc') return rpc(req, res);
      if (url.pathname === '/ledger')
        return send(res, 200, {
          receipts,
          balances: Object.fromEntries(
            [...balances].map(([k, v]) => [k, v.toString()]),
          ),
        });
      if (
        url.pathname === '/mpp/chat' ||
        url.pathname === '/mpp/chat-client-fees'
      ) {
        log(`402  ${url.pathname}  MPP/Tempo challenge $0.15`);
        return send(
          res,
          402,
          { error: 'payment required' },
          { 'www-authenticate': mppChallenge(url.pathname === '/mpp/chat') },
        );
      }
      const offer = OFFERS[url.pathname];
      if (!offer) return send(res, 404, { error: 'not found' });
      const header =
        offer.version === 2
          ? req.headers['payment-signature']
          : req.headers['x-payment'];
      if (typeof header !== 'string') {
        const body = requirement(url.pathname, offer, base);
        log(
          `402  ${url.pathname}  asks $${Number(offer.price) / 1e6} on ${offer.network}`,
        );
        return send(
          res,
          402,
          body,
          offer.version === 2 ? { 'payment-required': b64json(body) } : {},
        );
      }
      let payment: { payload?: Record<string, unknown> };
      try {
        payment = JSON.parse(
          Buffer.from(header, 'base64').toString('utf8'),
        ) as { payload?: Record<string, unknown> };
      } catch {
        return send(res, 402, { error: 'payment header is not base64 JSON' });
      }
      const out = offer.network.startsWith('solana')
        ? verifySvm(offer, payment.payload ?? {})
        : verifyEvm(offer, payment.payload ?? {});
      if (typeof out === 'string') {
        log(`REJECTED  ${url.pathname}  ${out}`);
        return send(res, 402, { error: `payment rejected: ${out}` });
      }
      const receipt = { ...out, path: url.pathname };
      receipts.push(receipt);
      log(
        `PAID  ${url.pathname}  $${Number(receipt.amount) / 1e6} from ${receipt.payer}`,
      );
      const responseHeader =
        offer.version === 2 ? 'payment-response' : 'x-payment-response';
      send(
        res,
        200,
        {
          data: `${offer.description} for ${receipt.payer.slice(0, 10)}…`,
          paid: receipt.amount,
        },
        {
          [responseHeader]: b64json({
            success: true,
            transaction: receipt.ref,
            network: offer.network,
            payer: receipt.payer,
          }),
        },
      );
    })();
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const p = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${p}`,
        port: p,
        receipts,
        balances,
        close: () => server.close(),
      });
    });
  });
}
