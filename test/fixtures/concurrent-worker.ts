import { parentPort, workerData } from 'node:worker_threads';
import { makeClock, openEnv, sign, type PolicyOptions } from '../helpers.ts';

const { dir, opts, body, gate, now } = workerData as {
  dir: string;
  opts: PolicyOptions;
  body: Record<string, unknown>;
  gate: SharedArrayBuffer;
  now: number;
};
const env = openEnv(dir, opts, makeClock(now));
const flags = new Int32Array(gate);
Atomics.add(flags, 1, 1);
Atomics.notify(flags, 1);
Atomics.wait(flags, 0, 0);
const r = await sign(env, body);
env.close();
parentPort?.postMessage(r.body);
