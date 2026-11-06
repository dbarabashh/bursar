import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import {
  CASHU_DECIMALS,
  currencyOfChain,
  findMintRule,
  normalizeAddress,
  type Currency,
  type Policy,
  type RecipientRule,
} from '../config.ts';
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
import type { Ledger, StoredResponse, TaskRow } from '../ledger/store.ts';
import {
  findAsset,
  isRouteAllowed,
  learnedRule,
  listedRecipients,
} from '../policy/allowlist.ts';
import { evaluate, type Decision } from '../policy/engine.ts';
import {
  budgetFor,
  toBudgetUnits,
  type Budget,
  type LedgerSnapshot,
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
  holdLoopbackTwin,
  isRecord,
  parseUint,
  parseUsd,
  sha256Hex,
} from '../util.ts';
import { authenticate } from './auth.ts';
import { createMintClient, type Fetch } from '../cashu/mint.ts';
import {
  createWallet,
  WalletError,
  type SendPlan,
  type Wallet,
} from '../cashu/wallet.ts';
import {
  parseCashu,
  type CashuDelivery,
  type CashuPlan,
} from '../protocols/cashu.ts';
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
  // Cashu: the wallet (default: one talking to the mints in the policy) and
  // the fetch bursar uses to deliver unlocked tokens to merchants.
  wallet?: Wallet;
  deliverFetch?: Fetch;
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

type AllowedDecision = Extract<Decision, { kind: 'allow' }>;

type AllowedContext = {
  agentId: string;
  req: SignRequest;
  key: string;
  hash: string;
  intent: PaymentIntent;
  events: AuditEvent[];
  base: Omit<AuditEvent, 'event'>;
  decision: AllowedDecision;
  snap: LedgerSnapshot;
  approvalId: string | null;
  recipient: string;
  intentJson: string;
  t: number;
  currency: Currency;
};

// What the server keeps about a Cashu payment in its wallet op, to finish it
// (respond, audit, refund) in phase 2.
type CashuPaymentMeta = {
  key: string;
  hash: string;
  delivery: CashuDelivery | null;
  recipient: string;
  total: string;
  feeTotal: string;
  base: Omit<AuditEvent, 'event'>;
  approvalId: string | null;
  task: Record<string, unknown> | null;
};

type DecideHooks = {
  // Runs inside the ledger transaction before the policy is evaluated; may
  // complete the intent (e.g. the Cashu fee once proofs are picked) or refuse.
  beforeEvaluate?: () => string | null;
  onAllowed: (c: AllowedContext) => StoredResponse;
};

// Amounts in audit lines and responses keep their own currency; with `fee`,
// also the fee field (feeUsd / feeSat).
function amountField(
  currency: Currency,
  v: bigint,
  fee?: bigint,
): Record<string, string> {
  if (currency === 'sat')
    return fee === undefined
      ? { sat: v.toString() }
      : { sat: v.toString(), feeSat: fee.toString() };
  return fee === undefined
    ? { usd: formatUsd(v) }
    : { usd: formatUsd(v), feeUsd: formatUsd(fee) };
}

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
  // The blockhash is the only thing binding a Solana tx to a cluster, so an
  // agent-supplied one is trusted only when the policy allows a single cluster.
  const oneSolanaCluster =
    policy.allow.chains.filter((c) => c.startsWith('solana:')).length === 1;
  let boundPort = policy.server.port;
  const wallet: Wallet | null =
    deps.wallet ??
    (policy.cashu === null
      ? null
      : createWallet({
          ledger,
          client: (m) => createMintClient(m),
          random,
          now,
        }));
  const deliverFetch: Fetch = deps.deliverFetch ?? ((u, i) => fetch(u, i));
  const inflight = new Map<string, Promise<StoredResponse>>();
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
      case 'cashu':
        return parseCashu(req.payload, ctx);
    }
  }

  async function prepare(intent: PaymentIntent): Promise<string | null> {
    const p = intent.raw as SignPlan;
    if (p.kind === 'cashu') return prepareCashu(intent);
    if (p.kind === 'x402-svm') {
      const url = policy.rpc[intent.chain];
      if (url === undefined)
        return p.blockhash !== null && oneSolanaCluster
          ? null
          : 'missing_recent_blockhash';
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
    hooks: DecideHooks = { onAllowed: signNow },
  ): StoredResponse {
    const pre = resolveExisting(agentId, req, key, hash, events);
    if (pre.kind === 'done') return pre.result;
    const t = now();
    const recipient = normalizeAddress(intent.recipient);
    const taskError = checkTask(agentId, req.taskId, t);
    // The hook may complete the intent (the Cashu fee), so it runs before the
    // summary that audit lines and approvals record is built.
    const refusal =
      taskError ??
      (hooks.beforeEvaluate === undefined ? null : hooks.beforeEvaluate());
    const summary = intentSummary(intent);
    const intentJson = canonicalJson(summary);
    const base = {
      ts: t,
      agent: agentId,
      idempotencyKey: req.idempotencyKey,
      intent: summary,
      ...(req.taskId === null ? {} : { taskId: req.taskId }),
    };
    if (refusal !== null) {
      events.push({ ...base, event: 'denied', reason: refusal });
      return store(key, hash, denied(refusal));
    }
    const currency = currencyOfChain(intent.chain);
    const snap = ledger.snapshot(
      agentId,
      recipient,
      {
        dayStart: windowStart(policy, t),
        monthStart: monthStart(policy, t),
        velocityStart: velocityStart(policy, t),
        taskId: req.taskId,
      },
      currency,
    );
    const decision = evaluate(policy, intent, snap, {
      approved: pre.approved,
      learned:
        policy.allow.recipients === 'any'
          ? []
          : ledger.learnedRecipientsFor(recipient).map(learnedRule),
    });

    if (decision.kind === 'deny') {
      events.push({
        ...base,
        event: 'denied',
        reason: decision.reason,
        ...(decision.usd === null ? {} : amountField(currency, decision.usd)),
      });
      return store(key, hash, denied(decision.reason));
    }
    const charged = amountField(currency, decision.usd);
    if (policy.mode === 'dry_run') {
      events.push({
        ...base,
        event: 'dry_run',
        reason: decision.kind,
        ...charged,
      });
      return {
        httpStatus: 200,
        body: { status: 'dry_run', decision: decision.kind, ...charged },
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
        context: {
          reason: decision.reason,
          resourceUrl: intent.resourceUrl ?? req.resource?.url ?? null,
        },
      });
      events.push({
        ...base,
        event: 'pending',
        approvalId: id,
        ...charged,
        reason: decision.reason,
      });
      const pendingBody: Record<string, unknown> = {
        status: 'pending',
        reason: decision.reason,
        approvalId: id,
        expiresAt: new Date(expiresAt).toISOString(),
      };
      if (approvalMethod === 'passkey')
        pendingBody['approvalUrl'] = `${approvalOrigin()}/approve/${id}`;
      return store(key, hash, { httpStatus: 202, body: pendingBody });
    }

    return hooks.onAllowed({
      agentId,
      req,
      key,
      hash,
      intent,
      events,
      base,
      decision,
      snap,
      approvalId: pre.approvalId,
      recipient,
      intentJson,
      t,
      currency,
    });
  }

  function signNow(c: AllowedContext): StoredResponse {
    const { intent, decision, events, base } = c;
    const usd = formatUsd(decision.usd);
    let out: SignOutput;
    try {
      out = signer.sign(intent);
    } catch (e) {
      const reason =
        e instanceof NotImplementedError
          ? 'signer_not_implemented'
          : 'signer_error';
      events.push({ ...base, event: 'denied', reason, usd });
      return store(
        c.key,
        c.hash,
        denied(reason, { detail: (e as Error).message }),
      );
    }
    const body = signedBody(intent, out, decision.usd, decision.feeUsd);
    const task = taskRemaining(c);
    if (task !== null) body['task'] = task;
    recordSpend(c);
    const txRef = out.kind === 'evm-tx' ? out.hash : out.signature;
    events.push({
      ...base,
      event: 'signed',
      usd,
      txRef,
      ...(c.approvalId === null ? {} : { approvalId: c.approvalId }),
    });
    return store(c.key, c.hash, { httpStatus: 200, body });
  }

  function taskRemaining(c: AllowedContext): Record<string, unknown> | null {
    const task = c.snap.task;
    if (task === null || c.req.taskId === null || task.budget === null)
      return null;
    const left = task.budget - task.spent - c.decision.usd;
    return c.currency === 'sat'
      ? { id: c.req.taskId, remainingSat: left.toString() }
      : { id: c.req.taskId, remainingUsd: formatUsd(left) };
  }

  function recordSpend(c: AllowedContext): void {
    const d = c.decision;
    ledger.addSpend({
      id: c.key,
      agent: c.agentId,
      recipient: c.recipient,
      intentJson: c.intentJson,
      usd: c.currency === 'usd' ? d.usd : 0n,
      feeUsd: c.currency === 'usd' ? d.feeUsd : 0n,
      sat: c.currency === 'sat' ? d.usd : 0n,
      feeSat: c.currency === 'sat' ? d.feeUsd : 0n,
      taskId: c.req.taskId,
      ts: c.t,
    });
    if (c.approvalId !== null)
      ledger.setApprovalStatus(c.approvalId, 'approved', 'consumed', c.t);
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
      if (!['budgetUsd', 'budgetSat', 'ttlSeconds', 'label'].includes(k))
        return errorResult(400, `unknown field ${k}`);
    }
    // A task has a USD budget, a sat budget, or both; without budgetSat,
    // budgetUsd is required (and parsed for its error message).
    const satIn = input['budgetSat'];
    let budget = 0n;
    let budgetSat: bigint | null = null;
    try {
      if (input['budgetUsd'] !== undefined || satIn === undefined)
        budget = parseUsd(input['budgetUsd'], 'budgetUsd');
      if (satIn !== undefined) budgetSat = parseUint(satIn, 'budgetSat');
    } catch (e) {
      return errorResult(400, (e as Error).message);
    }
    const sat = policy.limits.sat;
    if (budgetSat !== null) {
      if (sat === null)
        return errorResult(400, 'budgetSat: sat limits are off in the policy');
      if (budgetSat <= 0n || budgetSat > sat.perTaskMax)
        return errorResult(
          400,
          `budgetSat must be between 0 and ${sat.perTaskMax}`,
        );
    }
    const ttl = input['ttlSeconds'] ?? 3600;
    if (typeof ttl !== 'number' || !Number.isSafeInteger(ttl) || ttl <= 0)
      return errorResult(400, 'ttlSeconds must be a positive integer');
    const label = input['label'] ?? '';
    if (typeof label !== 'string' || label.length > 200)
      return errorResult(400, 'label must be a string up to 200 chars');
    const limits = policy.limits.perTask;
    if ((budget === 0n && budgetSat === null) || budget > limits.maxUsd)
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
      budgetSat,
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
      ...(budgetSat === null ? {} : { sat: budgetSat.toString() }),
      reason: label,
    });
    return {
      status: 201,
      body: {
        taskId: task.id,
        budgetUsd: formatUsd(budget),
        ...(budgetSat === null ? {} : { budgetSat: budgetSat.toString() }),
        expiresAt: new Date(task.expiresAt).toISOString(),
        label,
      },
    };
  }

  // --- Cashu (NUT-24) --------------------------------------------------------

  // Choose the mint to pay from: the first one the merchant accepts that the
  // policy allows, that holds enough of the unit, is reachable, and can lock
  // to a key when asked. Runs before the ledger transaction (network calls).
  async function prepareCashu(intent: PaymentIntent): Promise<string | null> {
    const plan = intent.raw as CashuPlan;
    if (policy.cashu === null || wallet === null) return 'protocol_not_allowed';
    if (
      plan.lock === null &&
      plan.delivery !== null &&
      new URL(plan.delivery.url).protocol !== 'https:' &&
      !policy.cashu.allowHttp
    )
      return 'cashu_delivery_needs_https';
    const allowed = plan.candidates.filter(
      (m) => findMintRule(policy.cashu, m, plan.unit) !== undefined,
    );
    if (allowed.length === 0) return 'mint_not_allowed';
    let reason = 'insufficient_balance';
    for (const mint of allowed) {
      if (wallet.balance(mint, plan.unit) < plan.amount) continue;
      try {
        const [, info] = await Promise.all([
          wallet.syncKeysets(mint),
          plan.lock === null ? null : wallet.mintInfo(mint),
        ]);
        // A mint that does not enforce NUT-11 treats a locked proof as
        // anyone-can-spend (NUT-10), so the lock would be meaningless.
        if (
          info !== null &&
          (!wallet.supports(info, '10') || !wallet.supports(info, '11'))
        ) {
          reason = 'mint_lacks_p2pk';
          continue;
        }
      } catch (e) {
        reason = e instanceof WalletError ? e.reason : 'mint_unavailable';
        continue;
      }
      intent.asset = mint;
      return null;
    }
    return reason;
  }

  // Phase 1, inside the decide transaction: proof selection fixes the fees
  // (mint input fees on both sides, NUT-02 and NUT-18), which count against
  // the limits like any network fee; an allowed payment reserves its proofs.
  function cashuHooks(w: Wallet, intent: PaymentIntent): DecideHooks {
    const plan = intent.raw as CashuPlan;
    let send: SendPlan | null = null;
    return {
      beforeEvaluate: () => {
        const p = w.planSend(intent.asset, plan.unit, plan.amount);
        if (p instanceof WalletError) return p.reason;
        send = p;
        if (p.fee > 0)
          intent.fee = {
            asset: intent.asset,
            amount: BigInt(p.fee),
            decimals: intent.decimals,
          };
        return null;
      },
      onAllowed: (c) => {
        const opId = `pay_${sha256Hex(c.key).slice(0, 32)}`;
        const meta: CashuPaymentMeta = {
          key: c.key,
          hash: c.hash,
          delivery: plan.delivery,
          recipient: c.recipient,
          total: c.decision.usd.toString(),
          feeTotal: c.decision.feeUsd.toString(),
          base: c.base,
          approvalId: c.approvalId,
          task: taskRemaining(c),
        };
        w.reserveSend(send as SendPlan, opId, plan.lock, { payment: meta });
        recordSpend(c);
        return store(c.key, c.hash, {
          httpStatus: 202,
          body: { status: 'processing', opId },
        });
      },
    };
  }

  // Phase 2 runs once per op at a time, whoever asks (the agent's retry or
  // the sweep).
  function resume(opId: string): Promise<StoredResponse> {
    let p = inflight.get(opId);
    if (p === undefined) {
      p = finishCashu(opId).finally(() => inflight.delete(opId));
      inflight.set(opId, p);
    }
    return p;
  }

  function resumeIfProcessing(r: StoredResponse): Promise<StoredResponse> {
    const opId = r.body['opId'];
    return r.body['status'] === 'processing' && typeof opId === 'string'
      ? resume(opId)
      : Promise.resolve(r);
  }

  async function deliver(
    d: CashuDelivery,
    token: string,
  ): Promise<{
    status: number;
    contentType: string | null;
    body: string;
  } | null> {
    const init: RequestInit = {
      method: d.method,
      headers: { ...d.headers, 'X-Cashu': token },
      redirect: 'manual',
      signal: AbortSignal.timeout(
        (policy.cashu?.deliveryTimeoutSeconds ?? 30) * 1000,
      ),
    };
    if (d.body !== null && d.method !== 'GET' && d.method !== 'HEAD')
      init.body = d.body;
    try {
      const res = await deliverFetch(d.url, init);
      return {
        status: res.status,
        contentType: res.headers.get('content-type'),
        body: (await res.text()).slice(0, 256 * 1024),
      };
    } catch {
      return null;
    }
  }

  // Phase 2 of a Cashu payment: swap at the mint, then hand the locked token
  // to the agent or deliver the unlocked one to the merchant. Safe to run
  // again after a crash: every step resumes from the ledger.
  async function finishCashu(opId: string): Promise<StoredResponse> {
    const w = wallet as Wallet;
    const op = ledger.getOp(opId);
    const m = op?.data['payment'] as CashuPaymentMeta | undefined;
    if (op === null || m === undefined)
      return {
        httpStatus: 500,
        body: { status: 'error', error: 'op_missing' },
      };
    const currency = currencyOfChain(`cashu:${op.unit}`);
    const total = BigInt(m.total);
    const amountTag = amountField(currency, total);
    const refunded = (reason: string): AuditEvent => ({
      ...m.base,
      ts: now(),
      event: 'refunded',
      reason,
      ...amountTag,
    });
    // One transaction for the op state, the stored answer and the audit
    // lines. `refund`: null keeps the spend; otherwise the ecash came back
    // and only `refund` (the mint fees of the round trip) stays counted.
    const settle = (
      result: StoredResponse,
      ev: AuditEvent[],
      refund: bigint | null,
      opState?: string,
    ) =>
      ledger.transaction(() => {
        if (opState !== undefined)
          ledger.putOp({
            ...op,
            state: opState,
            data: { ...op.data, token },
            updated: now(),
          });
        if (refund !== null && refund > 0n)
          ledger.reduceSpendToFee(m.key, currency, refund);
        else if (refund !== null) ledger.removeSpend(m.key);
        store(m.key, m.hash, result);
        for (const e of ev) audit.append(e);
        return result;
      });

    let token = (op.data['token'] as string | null | undefined) ?? null;
    if (op.state === 'swap_pending') {
      const out = await w.runSwap(opId);
      if (out.kind === 'refused')
        return settle(
          denied('mint_refused', { detail: out.detail }),
          [refunded('mint_refused')],
          0n,
        );
      if (out.kind === 'unknown')
        return {
          httpStatus: 202,
          body: {
            status: 'processing',
            opId,
            reason: 'mint_unavailable',
            detail: out.detail,
          },
        };
      token = out.token;
    } else if (op.state === 'released') {
      return settle(denied('mint_refused'), [], 0n);
    } else if (op.state !== 'swapped') {
      return (
        ledger.getIdempotency(m.key)?.result ?? {
          httpStatus: 500,
          body: { status: 'error', error: `op_${op.state}` },
        }
      );
    }
    if (token === null)
      return {
        httpStatus: 500,
        body: { status: 'error', error: 'token_missing' },
      };
    const common = {
      chain: `cashu:${op.unit}`,
      recipient: m.recipient,
      mint: op.mint,
      amount: String(op.data['amount']),
      ...amountField(currency, total, BigInt(m.feeTotal)),
      ...(m.task === null ? {} : { task: m.task }),
    };
    const signedEvent: AuditEvent = {
      ...m.base,
      ts: now(),
      event: 'signed',
      ...amountTag,
      txRef: sha256Hex(token),
      ...(m.approvalId === null ? {} : { approvalId: m.approvalId }),
    };

    if (op.data['lock'] !== null || m.delivery === null)
      return settle(
        {
          httpStatus: 200,
          body: {
            status: 'signed',
            ...common,
            header: { name: 'X-Cashu', value: token },
          },
        },
        [signedEvent],
        null,
        'handed_out',
      );

    const res = await deliver(m.delivery, token);
    if (res !== null && res.status >= 200 && res.status < 300)
      return settle(
        { httpStatus: 200, body: { status: 'paid', ...common, response: res } },
        [signedEvent],
        null,
        'delivered',
      );
    // The merchant did not take it (or did not answer). If the ecash is
    // still unspent, bursar takes it back and the payment never happened.
    const back = await w.reclaim(opId);
    if (back.kind === 'reclaimed') {
      const backUnits = toBudgetUnits(
        currency,
        BigInt(back.amount),
        CASHU_DECIMALS[currency],
      );
      const lost = total > backUnits ? total - backUnits : 0n;
      return settle(
        denied('merchant_rejected', {
          response: res,
          ...(lost > 0n ? { feesKept: amountField(currency, lost) } : {}),
        }),
        [refunded('merchant_rejected')],
        lost,
      );
    }
    return settle(
      {
        httpStatus: 200,
        body: {
          status: 'paid',
          ...common,
          response: res,
          note:
            back.kind === 'spent'
              ? 'the merchant redeemed the ecash but did not answer with success'
              : 'delivery failed and the mint could not say whether the merchant redeemed the ecash',
        },
      },
      [signedEvent],
      null,
      'delivered',
    );
  }

  // Settle Cashu payments whose daemon or mint went away mid-flight.
  async function sweepCashu(olderThanMs = 5 * 60_000): Promise<number> {
    if (wallet === null) return 0;
    let n = 0;
    for (const op of ledger.listOps('swap_pending')) {
      if (op.kind !== 'send' || now() - op.updated < olderThanMs) continue;
      await resume(op.id);
      n++;
    }
    await wallet.sweep(olderThanMs);
    return n;
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
    if (pre.kind === 'done') {
      const r = await resumeIfProcessing(pre.result);
      return { status: r.httpStatus, body: r.body };
    }

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
    const hooks =
      req.protocol === 'cashu' && wallet !== null
        ? cashuHooks(wallet, intent)
        : undefined;
    const result =
      prepError === null
        ? ledger.transaction(() =>
            decideAndSign(agentId, req, key, hash, intent, events, hooks),
          )
        : denyFresh(prepError, {}, { intent: intentSummary(intent) });
    flush(events);
    const out = await resumeIfProcessing(result);
    return { status: out.httpStatus, body: out.body };
  }

  function budget(agentId: string, taskId: string | null = null): HttpResult {
    const t = now();
    let taskBlock: Record<string, unknown> | null = null;
    let taskRow: TaskRow | null = null;
    if (taskId !== null) {
      const task = TASK_ID.test(taskId) ? ledger.getTask(taskId) : null;
      if (task === null || task.agent !== agentId)
        return errorResult(404, 'task_not_found');
      taskRow = task;
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
    const usdBudget = budgetFor(policy, 'usd') as Budget;
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
    const listed = listedRecipients(policy, ledger.listLearnedRecipients());
    const recipients =
      listed === 'any'
        ? [...byRecipient].map(([address, spent]) =>
            row(address, null, spent, recipientDayLimit(usdBudget, null)),
          )
        : listed.map((r) =>
            row(
              r.address,
              r.label,
              byRecipient.get(r.address) ?? 0n,
              recipientDayLimit(usdBudget, r),
            ),
          );
    const v = policy.limits.velocity;
    const satBlock = satBudget(agentId, start, mStart, listed, taskRow);
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
        ...(satBlock === null ? {} : { sat: satBlock }),
      },
    };
  }

  // The same limits for payments in satoshis (Cashu unit "sat"). They are a
  // separate budget: nothing here is converted to or from USD.
  function satBudget(
    agentId: string,
    start: number,
    mStart: number,
    listed: ReturnType<typeof listedRecipients>,
    task: TaskRow | null,
  ): Record<string, unknown> | null {
    const b = budgetFor(policy, 'sat');
    if (b === null) return null;
    const left = (limit: bigint, spent: bigint) =>
      (limit > spent ? limit - spent : 0n).toString();
    const block = (limit: bigint | null, spent: bigint) =>
      limit === null
        ? null
        : {
            limit: limit.toString(),
            spent: spent.toString(),
            remaining: left(limit, spent),
          };
    const day = ledger.daySpent(agentId, start, 'sat');
    const byRecipient = ledger.spentByRecipient(agentId, start, 'sat');
    const row = (
      address: string,
      label: string | null,
      rule: RecipientRule | null,
    ) => {
      const spent = byRecipient.get(address) ?? 0n;
      const limit = recipientDayLimit(b, rule);
      return {
        address,
        label,
        spent: spent.toString(),
        limit: limit?.toString() ?? null,
        remaining: limit === null ? null : left(limit, spent),
      };
    };
    const rows =
      listed === 'any'
        ? [...byRecipient.keys()].map((a) => row(a, null, null))
        : listed
            .filter(
              (r) =>
                r.chains === null ||
                r.chains.includes('cashu:sat') ||
                byRecipient.has(r.address),
            )
            .map((r) => row(r.address, r.label, r));
    return {
      perTx: b.perTx.toString(),
      approvalThreshold: b.approvalThreshold?.toString() ?? null,
      perDay: block(b.perDay, day),
      perMonth: block(b.perMonth, ledger.daySpent(agentId, mStart, 'sat')),
      walletPerDay: block(b.walletPerDay, ledger.walletDaySpent(start, 'sat')),
      task:
        task === null || task.budgetSat === null
          ? null
          : block(task.budgetSat, ledger.taskSpent(task.id, 'sat')),
      recipients: rows,
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
    const onRequest: RequestListener = (req, res) => void handle(req, res);
    const server = createServer(onRequest);
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        boundPort = (server.address() as AddressInfo).port;
        holdLoopbackTwin(server, onRequest).then(
          () => resolve({ server, port: boundPort }),
          reject,
        );
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
    wallet,
    sweepCashu,
  };
}
