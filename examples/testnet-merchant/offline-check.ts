import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { recoverAddressTyped } from 'micro-eth-signer';

const NETWORK = 'eip155:84532';
const settled: string[] = [];

type Body = {
  paymentPayload: {
    accepted: Record<string, unknown>;
    payload: { signature: string; authorization: Record<string, string> };
  };
  paymentRequirements: Record<string, unknown>;
};

function check(
  b: Body,
): { ok: true; payer: string } | { ok: false; reason: string } {
  const req = b.paymentRequirements;
  const auth = b.paymentPayload.payload.authorization;
  if (JSON.stringify(b.paymentPayload.accepted) !== JSON.stringify(req))
    return { ok: false, reason: 'accepted_does_not_match_requirements' };
  if (auth['to']?.toLowerCase() !== String(req['payTo']).toLowerCase())
    return { ok: false, reason: 'wrong_recipient' };
  if (auth['value'] !== req['amount'])
    return { ok: false, reason: 'wrong_amount' };
  const extra = req['extra'] as { name: string; version: string };
  const payer = recoverAddressTyped(b.paymentPayload.payload.signature, {
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
      chainId: 84532n,
      verifyingContract: req['asset'] as string,
    },
    message: {
      ...auth,
      value: BigInt(auth['value'] ?? '0'),
      validAfter: BigInt(auth['validAfter'] ?? '0'),
      validBefore: BigInt(auth['validBefore'] ?? '0'),
    },
  } as never);
  if (payer.toLowerCase() !== auth['from']?.toLowerCase())
    return { ok: false, reason: 'signature_not_from_payer' };
  return { ok: true, payer };
}

const facilitator = createServer((req, res) => {
  let raw = '';
  req.on('data', (c: Buffer) => (raw += c));
  req.on('end', () => {
    const send = (v: unknown) =>
      res
        .writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify(v));
    if (req.url === '/supported')
      return send({
        kinds: [{ x402Version: 2, scheme: 'exact', network: NETWORK }],
        extensions: [],
        signers: {},
      });
    const result = check(JSON.parse(raw) as Body);
    if (req.url === '/verify')
      return send(
        result.ok
          ? { isValid: true, payer: result.payer }
          : { isValid: false, invalidReason: result.reason },
      );
    if (req.url === '/settle') {
      if (!result.ok)
        return send({
          success: false,
          errorReason: result.reason,
          transaction: '',
          network: NETWORK,
        });
      settled.push(result.payer);
      return send({
        success: true,
        transaction: `0x${'ab'.repeat(32)}`,
        network: NETWORK,
        payer: result.payer,
      });
    }
    res.writeHead(404).end();
  });
});
await new Promise<void>((r) => facilitator.listen(0, '127.0.0.1', r));
const facilitatorUrl = `http://127.0.0.1:${(facilitator.address() as AddressInfo).port}`;

const merchant = spawn(
  process.execPath,
  [new URL('./server.ts', import.meta.url).pathname],
  {
    env: {
      ...process.env,
      PAY_TO: '0x5afe00000000000000000000000000000000cafe',
      FACILITATOR_URL: facilitatorUrl,
      PORT: process.env['PORT'] ?? '4021',
    },
    stdio: ['ignore', 'inherit', 'inherit'],
  },
);
console.log(
  `offline facilitator on ${facilitatorUrl} (checks the EIP-3009 signature, settles nothing on chain)`,
);
process.on('SIGINT', () => {
  merchant.kill();
  console.log(`\nsettled ${settled.length} payments`);
  process.exit(0);
});
