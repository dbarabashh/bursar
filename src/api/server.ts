import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { normalizeAddress, type Policy } from '../config.ts';
import { NotImplementedError } from '../errors.ts';
import {
  intentSummary,
  PROTOCOLS,
  type PaymentIntent,
  type Protocol,
  type ResourceDescriptor,
  type SignPlan,
} from '../intent.ts';
import type { AuditEvent, AuditLog } from '../audit.ts';
import type { Ledger, StoredResponse } from '../ledger/store.ts';
import { findAsset, isRouteAllowed } from '../policy/allowlist.ts';
import { evaluate } from '../policy/engine.ts';
import {
  monthEnd,
  monthStart,
  recipientDayLimit,
  velocityStart,
  windowEnd,
  windowStart,
} from '../policy/limits.ts';
import { AdapterError, type AdapterContext } from '../protocols/common.ts';
import { fetchGasPrice, parseEvm, simulateEvmCall } from '../protocols/evm.ts';
import { applyTempoGasPrice, parseMpp } from '../protocols/mpp.ts';
import {
  fetchSolanaBlockhash,
  parseX402,
  x402Response,
} from '../protocols/x402.ts';
import type { Signer, SignOutput } from '../signer/index.ts';
import {
  canonicalJson,
  formatUsd,
  isRecord,
  parseUsd,
  sha256Hex,
} from '../util.ts';
import { authenticate } from './auth.ts';
import { handleApprovalRoute } from './approvals.ts';
import { resolveApproval } from '../approval/resolve.ts';

export type HttpResult = {
  status: number;
  body: unknown;
  contentType?: string;
  headers?: Record<string, string>;
};

export type AppDeps = {
  policy: Policy;
  signer: Signer;
  ledger: Ledger;
  audit: AuditLog;
  now?: () => number;
  random?: (n: number) => Uint8Array;
  approvalOrigin?: string;
};

type SignRequest = {
  protocol: Protocol;
  payload: Record<string, unknown>;
  idempotencyKey: string;
  resourceHash: string | null;
  resource: ResourceDescriptor | null;
  taskId: string | null;
};

const TASK_ID = /^task_[0-9a-f]{24}$/;

class BadRequest extends Error {
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

const MAX_BODY = 64 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const ROUTES: Record<string, string> = {
  '/v1/sign': 'POST',
  '/v1/budget': 'GET',
  '/v1/audit': 'GET',
  '/v1/tasks': 'POST',
};

function parseSignRequest(input: unknown): SignRequest {
  if (!isRecord(input)) throw new BadRequest('body must be a JSON object');
  for (const k of Object.keys(input)) {
    if (
      ![
        'protocol',
        'payload',
        'idempotencyKey',
        'resourceHash',
        'resource',
        'taskId',
      ].includes(k)
    )
      throw new BadRequest(`unknown field ${k}`);
  }
  const protocol = input['protocol'];
  if (typeof protocol !== 'string' || !PROTOCOLS.includes(protocol as Protocol))
    throw new BadRequest('protocol_not_supported');
  const payload = input['payload'];
  if (!isRecord(payload)) throw new BadRequest('payload must be an object');
  const key = input['idempotencyKey'];
  if (typeof key !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(key))
    throw new BadRequest('idempotencyKey must match [A-Za-z0-9_.:-]{1,128}');
  const rh = input['resourceHash'];
  let resourceHash: string | null = null;
  if (rh !== undefined && rh !== null) {
    if (typeof rh !== 'string' || !/^(0x)?[0-9a-fA-F]{64}$/.test(rh))
      throw new BadRequest('resourceHash must be 32 bytes hex');
    resourceHash = rh.replace(/^0x/, '').toLowerCase();
  }
  const r = input['resource'];
  let resource: ResourceDescriptor | null = null;
  if (r !== undefined && r !== null) {
    if (
      !isRecord(r) ||
      typeof r['method'] !== 'string' ||
      typeof r['url'] !== 'string'
    )
      throw new BadRequest('resource must be {method, url, bodySha256?}');
    resource = { method: r['method'], url: r['url'] };
    if (r['bodySha256'] !== undefined) {
      if (
        typeof r['bodySha256'] !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(r['bodySha256'])
      )
        throw new BadRequest('resource.bodySha256 must be hex sha256');
      resource.bodySha256 = r['bodySha256'];
    }
  }
  const t = input['taskId'];
  if (
    t !== undefined &&
    t !== null &&
    (typeof t !== 'string' || !TASK_ID.test(t))
  )
    throw new BadRequest('taskId must be an id returned by POST /v1/tasks');
  return {
    protocol: protocol as Protocol,
    payload,
    idempotencyKey: key,
    resourceHash,
    resource,
    taskId: typeof t === 'string' ? t : null,
  };
}

function requestHash(req: SignRequest): string {
  return sha256Hex(
    canonicalJson({
      protocol: req.protocol,
      payload: req.payload,
      resourceHash: req.resourceHash,
      resource: req.resource,
      taskId: req.taskId ?? undefined,
    }),
  );
}

function errorResult(status: number, error: string): HttpResult {
  return { status, body: { status: 'error', error } };
}

export type App = ReturnType<typeof createApp>;

export function createApp(deps: AppDeps) {
  const { policy, signer, ledger, audit } = deps;
  const now = deps.now ?? (() => Date.now());
  const random = deps.random ?? randomBytes;
  const approvalMethod = policy.limits.approval?.method ?? 'cli';
  let boundPort = policy.server.port;
  const approvalOrigin = () =>
    deps.approvalOrigin ?? `http://localhost:${boundPort}`;

  function adapterContext(agentId: string, req: SignRequest): AdapterContext {
    return {
      agentId,
      idempotencyKey: req.idempotencyKey,
      resourceHash: req.resourceHash,
      resource: req.resource,
      now: now(),
      random,
      decimalsFor: (chain, asset) => findAsset(policy, chain, asset)?.decimals,
      isRouteAllowed: (chain, asset) => isRouteAllowed(policy, chain, asset),
      evm: policy.evm,
      tempo: policy.tempo,
    };
  }

  function buildIntent(agentId: string, req: SignRequest): PaymentIntent {
    const ctx = adapterContext(agentId, req);
    switch (req.protocol) {
      case 'x402':
        return parseX402(req.payload, ctx);
      case 'mpp':
        return parseMpp(req.payload, ctx);
      case 'evm':
        return parseEvm(req.payload, ctx);
    }
  }

  async function prepare(intent: PaymentIntent): Promise<string | null> {
    const p = intent.raw as SignPlan;
    if (p.kind === 'x402-svm' && p.blockhash === null) {
      const url = policy.rpc[intent.chain];
      if (url === undefined) return 'missing_recent_blockhash';
      const bh = await fetchSolanaBlockhash(url);
      if (bh === null) return 'rpc_unavailable';
      p.blockhash = bh;
    }
    if (
      p.kind === 'mpp-tempo' &&
      p.fee !== null &&
      p.fee.maxFeePerGas === null
    ) {
      const url = policy.rpc[intent.chain];
      if (url === undefined) return 'fee_price_unavailable';
      const price = await fetchGasPrice(url);
      if (price === null) return 'fee_price_unavailable';
      const err = applyTempoGasPrice(intent, price, policy.tempo.maxFeeUsd);
      if (err !== null) return err;
    }
    if (p.kind === 'evm-tx' && policy.evm.simulateBeforeSign) {
      const url = policy.rpc[intent.chain];
      const from = signer.addresses().evm;
      if (url === undefined || from === null) return 'simulation_unavailable';
      const err = await simulateEvmCall(url, from, p.tx);
      if (err !== null) return 'simulation_failed';
    }
    return null;
  }

  type Pre =
    | { kind: 'done'; result: StoredResponse }
    | { kind: 'proceed'; approvalId: string | null; approved: boolean };

  function store(
    key: string,
    hash: string,
    result: StoredResponse,
  ): StoredResponse {
    ledger.putIdempotency(key, hash, result, now());
    return result;
  }

  function denied(
    reason: string,
    extra: Record<string, unknown> = {},
  ): StoredResponse {
    return { httpStatus: 200, body: { status: 'denied', reason, ...extra } };
  }

  function resolveExisting(
    agentId: string,
    req: SignRequest,
    key: string,
    hash: string,
    events: AuditEvent[],
  ): Pre {
    const row = ledger.getIdempotency(key);
    if (row === null)
      return { kind: 'proceed', approvalId: null, approved: false };
    if (row.intentHash !== hash) {
      events.push({
        ts: now(),
        agent: agentId,
        event: 'conflict',
        idempotencyKey: req.idempotencyKey,
      });
      return {
        kind: 'done',
        result: {
          httpStatus: 409,
          body: { status: 'error', error: 'idempotency_conflict' },
        },
      };
    }
    const body = row.result.body;
    if (body['status'] !== 'pending' || typeof body['approvalId'] !== 'string')
      return { kind: 'done', result: row.result };
    const approval = ledger.getApproval(body['approvalId']);
    if (approval === null)
      return {
        kind: 'done',
        result: store(key, hash, denied('approval_missing')),
      };
    const base = {
      ts: now(),
      agent: agentId,
      idempotencyKey: req.idempotencyKey,
      approvalId: approval.id,
    };
    if (approval.status === 'approved')
      return { kind: 'proceed', approvalId: approval.id, approved: true };
    if (approval.status === 'pending' && now() < approval.expiresAt)
      return { kind: 'done', result: row.result };
    if (approval.status === 'pending' || approval.status === 'expired') {
      ledger.setApprovalStatus(approval.id, 'pending', 'expired', now());
      events.push({ ...base, event: 'denied', reason: 'approval_timeout' });
      return {
        kind: 'done',
        result: store(
          key,
          hash,
          denied('approval_timeout', { approvalId: approval.id }),
        ),
      };
    }
    if (approval.status === 'denied') {
      events.push({ ...base, event: 'denied', reason: 'approval_denied' });
      return {
        kind: 'done',
        result: store(
          key,
          hash,
          denied('approval_denied', { approvalId: approval.id }),
        ),
      };
    }
    return { kind: 'done', result: row.result };
  }

  function signedBody(
    intent: PaymentIntent,
    out: SignOutput,
    usd: bigint,
    feeUsd: bigint,
  ): Record<string, unknown> {
    const p = intent.raw as SignPlan;
    const base = {
      status: 'signed',
      usd: formatUsd(usd),
      feeUsd: formatUsd(feeUsd),
      chain: intent.chain,
      recipient: intent.recipient,
      amount: intent.amount.toString(),
    };
    if (
      (p.kind === 'x402-evm' || p.kind === 'x402-svm') &&
      out.kind !== 'evm-tx'
    )
      return { ...base, ...x402Response(p, out) };
    if (out.kind === 'evm-tx')
      return { ...base, signedTx: out.signedTx, txHash: out.hash };
    if (out.kind === 'svm')
      return { ...base, signature: out.signature, signedTx: out.transaction };
    return {
      ...base,
      signature: out.signature,
      authorization: out.authorization,
    };
  }

  function decideAndSign(
    agentId: string,
    req: SignRequest,
    key: string,
    hash: string,
    intent: PaymentIntent,
    events: AuditEvent[],
  ): StoredResponse {
    const pre = resolveExisting(agentId, req, key, hash, events);
    if (pre.kind === 'done') return pre.result;
    const t = now();
    const recipient = normalizeAddress(intent.recipient);
    const summary = intentSummary(intent);
    const intentJson = canonicalJson(summary);
    const base = {
      ts: t,
      agent: agentId,
      idempotencyKey: req.idempotencyKey,
      intent: summary,
      ...(req.taskId === null ? {} : { taskId: req.taskId }),
    };
    const taskError = checkTask(agentId, req.taskId, t);
    if (taskError !== null) {
      events.push({ ...base, event: 'denied', reason: taskError });
      return store(key, hash, denied(taskError));
    }
    const snap = ledger.snapshot(agentId, recipient, {
      dayStart: windowStart(policy, t),
      monthStart: monthStart(policy, t),
      velocityStart: velocityStart(policy, t),
      taskId: req.taskId,
    });
    const decision = evaluate(policy, intent, snap, { approved: pre.approved });

    if (decision.kind === 'deny') {
      events.push({
        ...base,
        event: 'denied',
        reason: decision.reason,
        ...(decision.usd === null ? {} : { usd: formatUsd(decision.usd) }),
      });
      return store(key, hash, denied(decision.reason));
    }
    const usd = formatUsd(decision.usd);
    if (policy.mode === 'dry_run') {
      events.push({ ...base, event: 'dry_run', reason: decision.kind, usd });
      return {
        httpStatus: 200,
        body: { status: 'dry_run', decision: decision.kind, usd },
      };
    }
    if (decision.kind === 'require_approval') {
      const approval = policy.limits.approval;
      const id = `apr_${bytesToHex(random(12))}`;
      const expiresAt = t + (approval?.timeoutSeconds ?? 300) * 1000;
      ledger.createApproval({
        id,
        agent: agentId,
        intentJson,
        status: 'pending',
        ts: t,
        expiresAt,
      });
      events.push({ ...base, event: 'pending', approvalId: id, usd });
      const pendingBody: Record<string, unknown> = {
        status: 'pending',
        approvalId: id,
        expiresAt: new Date(expiresAt).toISOString(),
      };
      if (approvalMethod === 'passkey')
        pendingBody['approvalUrl'] = `${approvalOrigin()}/approve/${id}`;
      return store(key, hash, { httpStatus: 202, body: pendingBody });
    }

    let out: SignOutput;
    try {
      out = signer.sign(intent);
    } catch (e) {
      const reason =
        e instanceof NotImplementedError
          ? 'signer_not_implemented'
          : 'signer_error';
      events.push({ ...base, event: 'denied', reason, usd });
      return store(key, hash, denied(reason, { detail: (e as Error).message }));
    }
    const body = signedBody(intent, out, decision.usd, decision.feeUsd);
    if (snap.task !== null && req.taskId !== null) {
      body['task'] = {
        id: req.taskId,
        remainingUsd: formatUsd(
          snap.task.budget - snap.task.spent - decision.usd,
        ),
      };
    }
    ledger.addSpend({
      id: key,
      agent: agentId,
      recipient,
      intentJson,
      usd: decision.usd,
      feeUsd: decision.feeUsd,
      taskId: req.taskId,
      ts: t,
    });
    if (pre.approvalId !== null)
      ledger.setApprovalStatus(pre.approvalId, 'approved', 'consumed', t);
    const txRef = out.kind === 'evm-tx' ? out.hash : out.signature;
    events.push({
      ...base,
      event: 'signed',
      usd,
      txRef,
      ...(pre.approvalId === null ? {} : { approvalId: pre.approvalId }),
    });
    return store(key, hash, { httpStatus: 200, body });
  }

  function checkTask(
    agentId: string,
    taskId: string | null,
    t: number,
  ): string | null {
    if (taskId === null)
      return policy.limits.perTask.required ? 'task_required' : null;
    const task = ledger.getTask(taskId);
    if (task === null || task.agent !== agentId) return 'task_not_found';
    if (t >= task.expiresAt) return 'task_expired';
    return null;
  }

  function openTask(agentId: string, input: unknown): HttpResult {
    if (!isRecord(input)) return errorResult(400, 'body must be a JSON object');
    for (const k of Object.keys(input)) {
      if (!['budgetUsd', 'ttlSeconds', 'label'].includes(k))
        return errorResult(400, `unknown field ${k}`);
    }
    let budget: bigint;
    try {
      budget = parseUsd(input['budgetUsd'], 'budgetUsd');
    } catch (e) {
      return errorResult(400, (e as Error).message);
    }
    const ttl = input['ttlSeconds'] ?? 3600;
    if (typeof ttl !== 'number' || !Number.isSafeInteger(ttl) || ttl <= 0)
      return errorResult(400, 'ttlSeconds must be a positive integer');
    const label = input['label'] ?? '';
    if (typeof label !== 'string' || label.length > 200)
      return errorResult(400, 'label must be a string up to 200 chars');
    const limits = policy.limits.perTask;
    if (budget <= 0n || budget > limits.maxUsd)
      return errorResult(
        400,
        `budgetUsd must be between 0 and ${formatUsd(limits.maxUsd)}`,
      );
    if (ttl > limits.maxTtlSeconds)
      return errorResult(
        400,
        `ttlSeconds must be at most ${limits.maxTtlSeconds}`,
      );
    const t = now();
    const task = {
      id: `task_${bytesToHex(random(12))}`,
      agent: agentId,
      label,
      budgetUsd: budget,
      created: t,
      expiresAt: t + ttl * 1000,
    };
    ledger.createTask(task);
    audit.append({
      ts: t,
      agent: agentId,
      event: 'task_opened',
      taskId: task.id,
      usd: formatUsd(budget),
      reason: label,
    });
    return {
      status: 201,
      body: {
        taskId: task.id,
        budgetUsd: formatUsd(budget),
        expiresAt: new Date(task.expiresAt).toISOString(),
        label,
      },
    };
  }

  function flush(events: AuditEvent[]): void {
    for (const e of events) audit.append(e);
  }

  async function sign(agentId: string, input: unknown): Promise<HttpResult> {
    let req: SignRequest;
    try {
      req = parseSignRequest(input);
    } catch (e) {
      if (e instanceof BadRequest) return errorResult(400, e.message);
      throw e;
    }
    const key = `${agentId}:${req.idempotencyKey}`;
    const hash = requestHash(req);
    const events: AuditEvent[] = [];
    const denyFresh = (
      reason: string,
      extra: Record<string, unknown>,
      event: Pick<AuditEvent, 'intent'> = {},
    ) =>
      ledger.transaction(() => {
        const again = resolveExisting(agentId, req, key, hash, events);
        if (again.kind === 'done') return again.result;
        events.push({
          ts: now(),
          agent: agentId,
          event: 'denied',
          idempotencyKey: req.idempotencyKey,
          reason,
          ...event,
        });
        return store(key, hash, denied(reason, extra));
      });
    const pre = ledger.transaction(() =>
      resolveExisting(agentId, req, key, hash, events),
    );
    flush(events.splice(0));
    if (pre.kind === 'done')
      return { status: pre.result.httpStatus, body: pre.result.body };

    let intent: PaymentIntent;
    try {
      intent = buildIntent(agentId, req);
    } catch (e) {
      if (!(e instanceof AdapterError)) throw e;
      const r = denyFresh(e.reason, { detail: e.message });
      flush(events);
      return { status: r.httpStatus, body: r.body };
    }

    const prepError = await prepare(intent);
    const result =
      prepError === null
        ? ledger.transaction(() =>
            decideAndSign(agentId, req, key, hash, intent, events),
          )
        : denyFresh(prepError, {}, { intent: intentSummary(intent) });
    flush(events);
    return { status: result.httpStatus, body: result.body };
  }

  function budget(agentId: string, taskId: string | null = null): HttpResult {
    const t = now();
    let taskBlock: Record<string, unknown> | null = null;
    if (taskId !== null) {
      const task = TASK_ID.test(taskId) ? ledger.getTask(taskId) : null;
      if (task === null || task.agent !== agentId)
        return errorResult(404, 'task_not_found');
      const spent = ledger.taskSpent(task.id);
      taskBlock = {
        id: task.id,
        label: task.label,
        budgetUsd: formatUsd(task.budgetUsd),
        spentUsd: formatUsd(spent),
        remainingUsd: formatUsd(
          task.budgetUsd > spent ? task.budgetUsd - spent : 0n,
        ),
        expiresAt: new Date(task.expiresAt).toISOString(),
        expired: t >= task.expiresAt,
      };
    }
    const pm = policy.limits.perMonth;
    const mStart = monthStart(policy, t);
    const mEnd = monthEnd(policy, t);
    const start = windowStart(policy, t);
    const end = windowEnd(policy, t);
    const daySpent = ledger.daySpent(agentId, start);
    const byRecipient = ledger.spentByRecipient(agentId, start);
    const remaining = (limit: bigint, spent: bigint) =>
      formatUsd(limit > spent ? limit - spent : 0n);
    const row = (
      address: string,
      label: string | null,
      spent: bigint,
      limit: bigint | null,
    ) => ({
      address,
      label,
      spentUsd: formatUsd(spent),
      limitUsd: limit === null ? null : formatUsd(limit),
      remainingUsd: limit === null ? null : remaining(limit, spent),
    });
    const recipients =
      policy.allow.recipients === 'any'
        ? [...byRecipient].map(([address, spent]) =>
            row(address, null, spent, recipientDayLimit(policy, null)),
          )
        : policy.allow.recipients.map((r) =>
            row(
              r.address,
              r.label,
              byRecipient.get(r.address) ?? 0n,
              recipientDayLimit(policy, r),
            ),
          );
    const v = policy.limits.velocity;
    return {
      status: 200,
      body: {
        agent: agentId,
        mode: policy.mode,
        window: policy.limits.window,
        windowStart: new Date(start).toISOString(),
        windowResetsAt: end === null ? null : new Date(end).toISOString(),
        perTxUsd: formatUsd(policy.limits.perTx),
        approvalThresholdUsd:
          policy.limits.approval === null
            ? null
            : formatUsd(policy.limits.approval.threshold),
        perDay: {
          limitUsd: formatUsd(policy.limits.perDay),
          spentUsd: formatUsd(daySpent),
          remainingUsd: remaining(policy.limits.perDay, daySpent),
        },
        perMonth:
          pm === null
            ? null
            : (() => {
                const m = ledger.daySpent(agentId, mStart);
                return {
                  window: pm.window,
                  limitUsd: formatUsd(pm.usd),
                  spentUsd: formatUsd(m),
                  remainingUsd: formatUsd(pm.usd > m ? pm.usd - m : 0n),
                  resetsAt: mEnd === null ? null : new Date(mEnd).toISOString(),
                };
              })(),
        task: taskBlock,
        walletPerDay:
          policy.limits.walletPerDay === null
            ? null
            : (() => {
                const w = ledger.walletDaySpent(start);
                return {
                  limitUsd: formatUsd(policy.limits.walletPerDay),
                  spentUsd: formatUsd(w),
                  remainingUsd: remaining(policy.limits.walletPerDay, w),
                };
              })(),
        velocity:
          v === null
            ? null
            : {
                maxTx: v.maxTx,
                perSeconds: v.perSeconds,
                used: ledger.recentTxCount(agentId, velocityStart(policy, t)),
              },
        recipients,
      },
    };
  }

  function auditSince(agentId: string, since: string | null): HttpResult {
    let ts = 0;
    if (since !== null && since !== '') {
      ts = /^\d+$/.test(since) ? Number(since) : Date.parse(since);
      if (!Number.isFinite(ts))
        return errorResult(400, 'since must be epoch ms or ISO-8601');
    }
    const lines = audit.readSince(ts, agentId);
    return {
      status: 200,
      body: lines.length === 0 ? '' : `${lines.join('\n')}\n`,
      contentType: 'application/x-ndjson',
    };
  }

  function hostAllowed(req: IncomingMessage): boolean {
    if (policy.server.allowRemote) return true;
    const host = req.headers.host;
    if (host === undefined) return false;
    const name = host.startsWith('[')
      ? host.slice(0, host.indexOf(']') + 1)
      : (host.split(':')[0] ?? '');
    return LOOPBACK_HOSTS.has(name);
  }

  async function readBody(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      const b = chunk as Buffer;
      size += b.length;
      if (size > MAX_BODY) throw new BadRequest('body too large', 413);
      chunks.push(b);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    } catch {
      throw new BadRequest('body must be valid JSON');
    }
  }

  async function route(req: IncomingMessage): Promise<HttpResult> {
    if (!hostAllowed(req)) return errorResult(403, 'host_not_allowed');
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (approvalMethod === 'passkey' && url.pathname.startsWith('/approve/')) {
      return handleApprovalRoute(req, url, {
        policy,
        ledger,
        audit,
        now,
        origin: approvalOrigin(),
      });
    }
    const method = ROUTES[url.pathname];
    if (method === undefined) return errorResult(404, 'not_found');
    const agentId = authenticate(policy, req.headers.authorization);
    if (agentId === null) return errorResult(401, 'unauthorized');
    if (req.method !== method) return errorResult(405, 'method_not_allowed');
    if (url.pathname === '/v1/budget')
      return budget(agentId, url.searchParams.get('taskId'));
    if (url.pathname === '/v1/audit')
      return auditSince(agentId, url.searchParams.get('since'));
    let body: unknown;
    try {
      body = await readBody(req);
    } catch (e) {
      if (e instanceof BadRequest) return errorResult(e.status, e.message);
      throw e;
    }
    if (url.pathname === '/v1/tasks') return openTask(agentId, body);
    return sign(agentId, body);
  }

  async function handle(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    let result: HttpResult;
    try {
      result = await route(req);
    } catch {
      result = errorResult(500, 'internal_error');
    }
    const headers: Record<string, string> = {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...(result.headers ?? {}),
    };
    if (result.status === 401)
      headers['www-authenticate'] = 'Bearer realm="bursar"';
    if (typeof result.body === 'string') {
      headers['content-type'] ??= result.contentType ?? 'text/plain';
      res.writeHead(result.status, headers).end(result.body);
    } else {
      headers['content-type'] = 'application/json';
      res.writeHead(result.status, headers).end(JSON.stringify(result.body));
    }
  }

  function listen(
    port = policy.server.port,
    host = policy.server.host,
  ): Promise<{ server: Server; port: number }> {
    if (!policy.server.allowRemote && !LOOPBACK_HOSTS.has(host)) {
      return Promise.reject(
        new Error(
          `refusing to listen on ${host}: set server.allow_remote: true to expose bursar beyond loopback`,
        ),
      );
    }
    const server = createServer((req, res) => void handle(req, res));
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        boundPort = (server.address() as AddressInfo).port;
        resolve({ server, port: boundPort });
      });
    });
  }

  return {
    sign,
    budget,
    openTask,
    auditSince,
    resolveApproval: (id: string, decision: 'approved' | 'denied') =>
      resolveApproval(ledger, audit, id, decision, {
        now,
        method: approvalMethod,
      }) === 'resolved',
    handle,
    listen,
  };
}
