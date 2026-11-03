import express from 'express';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';

const payTo = process.env['PAY_TO'];
if (!payTo || !/^0x[0-9a-fA-F]{40}$/.test(payTo)) {
  console.error(
    'set PAY_TO to the address that should receive the test payments (a second wallet you control)',
  );
  process.exit(1);
}
const network = (process.env['NETWORK'] ??
  'eip155:84532') as `${string}:${string}`;
const facilitatorUrl =
  process.env['FACILITATOR_URL'] ?? 'https://x402.org/facilitator';
const port = Number(process.env['PORT'] ?? 4021);

const server = new x402ResourceServer(
  new HTTPFacilitatorClient({ url: facilitatorUrl }),
).register(network, new ExactEvmScheme());

const offer = (price: string, description: string) => ({
  accepts: [{ scheme: 'exact', price, network, payTo, maxTimeoutSeconds: 120 }],
  description,
  mimeType: 'application/json',
});

const app = express();
app.use(
  paymentMiddleware(
    {
      'GET /joke': offer('$0.01', 'a programming joke'),
      'GET /report': offer(
        '$0.06',
        'a short market report, above the approval threshold',
      ),
      'GET /gpu-hour': offer(
        '$0.50',
        'one GPU hour, above the per-payment limit',
      ),
    },
    server,
  ),
);

app.get('/', (_req, res) => {
  res.json({
    network,
    payTo,
    facilitator: facilitatorUrl,
    paid: ['/joke $0.01', '/report $0.06', '/gpu-hour $0.50'],
  });
});
app.get('/joke', (_req, res) => {
  res.json({
    joke: 'There are 10 kinds of people: those who understand binary and those who do not.',
  });
});
app.get('/report', (_req, res) => {
  res.json({
    report: 'USDC is still worth one dollar. Agents keep paying for APIs.',
  });
});
app.get('/gpu-hour', (_req, res) => {
  res.json({ gpu: 'you should never see this with the default policy' });
});

app.listen(port, '127.0.0.1', () => {
  console.log(
    `test merchant on http://127.0.0.1:${port}  network=${network}  payTo=${payTo}`,
  );
  console.log(`facilitator ${facilitatorUrl}`);
});
