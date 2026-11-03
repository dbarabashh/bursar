import { workerData, parentPort } from 'node:worker_threads';
import { AuditLog } from '../../src/audit.ts';
import { Ledger } from '../../src/ledger/store.ts';

const { db, log, name, count } = workerData as {
  db: string;
  log: string;
  name: string;
  count: number;
};
const ledger = new Ledger(db);
const audit = new AuditLog(log, (fn) => ledger.transaction(fn));
for (let i = 0; i < count; i++)
  audit.append({
    ts: Date.now(),
    agent: name,
    event: 'pending',
    reason: `${name}-${i}`,
  });
ledger.close();
parentPort?.postMessage('done');
