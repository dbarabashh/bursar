import { fileURLToPath } from 'node:url';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { OFFERS, startMerchant } from './merchant.ts';

const PORT = 8500;
const root = fileURLToPath(new URL('..', import.meta.url));
const dir = join(root, 'sandbox', '.local');
const envFile = join(dir, 'env');

if (process.argv.includes('--reset'))
  rmSync(dir, { recursive: true, force: true });

if (!existsSync(envFile)) {
  mkdirSync(join(dir, 'state'), { recursive: true });
  const vars: Record<string, string> = {
    BURSAR_KEY: `evm: 0x${bytesToHex(secp256k1.utils.randomSecretKey())}; solana: ${bytesToHex(randomBytes(32))}`,
    BURSAR_TOKEN_NANOCODE: bytesToHex(randomBytes(24)),
    BURSAR_TOKEN_RESEARCHER: bytesToHex(randomBytes(24)),
    SANDBOX_RPC: `http://127.0.0.1:${PORT}/rpc`,
    SANDBOX_STATE: join(dir, 'state'),
    SANDBOX_APPROVAL: 'cli',
    MERCHANT_URL: `http://127.0.0.1:${PORT}`,
    BURSAR_URL: 'http://127.0.0.1:8402',
  };
  writeFileSync(
    envFile,
    Object.entries(vars)
      .map(([k, v]) => `export ${k}='${v}'`)
      .join('\n') + '\n',
    { mode: 0o600 },
  );
  console.log(`new sandbox env written to ${envFile}`);
} else {
  console.log(
    `using ${envFile} (npm run sandbox:manual -- --reset starts from scratch)`,
  );
}

const approval = /SANDBOX_APPROVAL='(\w+)'/.exec(
  readFileSync(envFile, 'utf8'),
)?.[1];
const merchant = await startMerchant(PORT, (line) =>
  console.log(`${new Date().toISOString().slice(11, 19)}  ${line}`),
);

console.log(`
fake merchant + RPC stub on ${merchant.url}   (approval method: ${approval})

in every other terminal first run:
  cd ${root} && source sandbox/.local/env

terminal 2, the daemon:
  node src/index.ts serve --policy sandbox/policy.yaml

terminal 3, the agent:
  python3 sandbox/pay.py /x402/data
  python3 sandbox/pay.py /x402/report                 # $0.70, waits for a human
  python3 sandbox/pay.py --agent researcher /x402/data
  python3 sandbox/pay.py --open-task 0.30 /x402/data  # then --task <id> for the next calls

the human:
  node src/index.ts approvals --policy sandbox/policy.yaml
  node src/index.ts approve <id> --policy sandbox/policy.yaml
  node src/index.ts report --policy sandbox/policy.yaml --period day

paid endpoints:`);
for (const [path, o] of Object.entries(OFFERS))
  console.log(
    `  ${path.padEnd(22)} $${(Number(o.price) / 1e6).toFixed(2).padStart(5)}  ${o.description}`,
  );
console.log(`  ${'/mpp/chat'.padEnd(22)} $ 0.15  MPP/Tempo, server pays fees
  ${'/mpp/chat-client-fees'.padEnd(22)} $ 0.15  MPP/Tempo, wallet pays fees
  ${'/ledger'.padEnd(22)}         what the merchant received

live log (ctrl-c to stop):`);
