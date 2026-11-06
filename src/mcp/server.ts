import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import { computeResourceHash } from '../intent.ts';
import { isRecord, sha256Hex } from '../util.ts';

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export type McpDeps = {
  bursarUrl: string;
  token: string;
  fetch?: Fetch;
  sleep?: (ms: number) => Promise<void>;
  pollMs?: number;
  maxBodyChars?: number;
};

type JsonRpc = {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
};
type ToolResult = {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
};

const PROTOCOL_VERSION = '2025-06-18';
const DEFAULT_WAIT_SECONDS = 0;
const MAX_WAIT_SECONDS = 600;

const TOOLS = [
  {
    name: 'pay',
    description:
      'Fetch a URL that may cost money. If the server answers HTTP 402 (x402, MPP or Cashu X-Cashu), the payment is sent to the local bursar daemon, which checks it against the spending policy the human set and signs it. ' +
      'You never see or hold a key. If bursar denies the payment, do not look for another way to pay; tell the human the reason. ' +
      'If the payment needs human approval you get status pending_approval and an approvalUrl: show the human the URL, wait until they say they approved it, then call pay again with the same arguments.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'http(s) URL of the paid resource',
        },
        method: { type: 'string', default: 'GET' },
        body: { type: 'string', description: 'request body, sent as is' },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
        task_id: {
          type: 'string',
          description:
            'charge the payment to a task budget opened with open_task',
        },
        wait_seconds: {
          type: 'number',
          description: `seconds to keep polling while a human approval is pending (default ${DEFAULT_WAIT_SECONDS}, max ${MAX_WAIT_SECONDS})`,
        },
      },
      required: ['url'],
      additionalProperties: false,
    },
  },
  {
    name: 'budget',
    description:
      'Show how much this agent may still spend: per payment, today, this month, per recipient, and for a task.',
    inputSchema: {
      type: 'object',
      properties: { task_id: { type: 'string' } },
      additionalProperties: false,
    },
  },
  {
    name: 'open_task',
    description:
      'Open a task with its own budget, e.g. "at most $0.50 for this research". Pass the returned task_id to pay.',
    inputSchema: {
      type: 'object',
      properties: {
        budget_usd: {
          type: 'string',
          description: 'decimal dollars, e.g. "0.50"',
        },
        budget_sat: {
          type: 'string',
          description:
            'satoshis for Cashu payments in sat, e.g. "500" (a separate budget, never converted from USD)',
        },
        ttl_seconds: { type: 'number', default: 3600 },
        label: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
];

type PayArgs = {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
  taskId: string | undefined;
  waitSeconds: number;
};

class ToolError extends Error {}

// What a payment cost, in its own currency (Cashu sat payments carry `sat`).
const amountOf = (r: Record<string, unknown>) =>
  r['sat'] === undefined ? { usd: r['usd'] } : { sat: r['sat'] };

function text(value: unknown, isError = false): ToolResult {
  const out: ToolResult = {
    content: [
      {
        type: 'text',
        text:
          typeof value === 'string' ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
  if (isError) out.isError = true;
  return out;
}

function optString(
  args: Record<string, unknown>,
  name: string,
): string | undefined {
  const v = args[name];
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || v.length === 0)
    throw new ToolError(`${name} must be a non-empty string`);
  return v;
}

function parsePayArgs(args: Record<string, unknown>): PayArgs {
  const url = optString(args, 'url');
  if (url === undefined) throw new ToolError('url is required');
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ToolError('url is not a valid URL');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    throw new ToolError('url must be http or https');
  const headers: Record<string, string> = {};
  const rawHeaders = args['headers'];
  if (rawHeaders !== undefined) {
    if (!isRecord(rawHeaders))
      throw new ToolError('headers must be an object of strings');
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (typeof v !== 'string')
        throw new ToolError('headers must be an object of strings');
      headers[k] = v;
    }
  }
  const wait = args['wait_seconds'];
  if (
    wait !== undefined &&
    (typeof wait !== 'number' || !Number.isFinite(wait) || wait < 0)
  )
    throw new ToolError('wait_seconds must be a non-negative number');
  return {
    url,
    method: (optString(args, 'method') ?? 'GET').toUpperCase(),
    body:
      args['body'] === undefined ? undefined : (optString(args, 'body') ?? ''),
    headers,
    taskId: optString(args, 'task_id'),
    waitSeconds: Math.min(wait ?? DEFAULT_WAIT_SECONDS, MAX_WAIT_SECONDS),
  };
}

function paymentRequest(
  res: Response,
  bodyText: string,
  a: PayArgs,
): { protocol: 'x402' | 'mpp' | 'cashu'; payload: Record<string, unknown> } {
  // NUT-24. bursar delivers an unlocked token itself, so it gets the request
  // headers and body to send along with it.
  const cashu = res.headers.get('x-cashu');
  if (cashu && /^creq(a|b1)/i.test(cashu.trim()))
    return {
      protocol: 'cashu',
      payload: {
        paymentRequest: cashu.trim(),
        deliver: {
          headers: a.headers,
          ...(a.body === undefined ? {} : { body: a.body }),
        },
      },
    };
  const required = res.headers.get('payment-required');
  if (required) {
    try {
      return {
        protocol: 'x402',
        payload: {
          paymentRequired: JSON.parse(
            Buffer.from(required, 'base64').toString('utf8'),
          ) as unknown,
        },
      };
    } catch {
      throw new ToolError(
        'the server sent a PAYMENT-REQUIRED header that is not base64 JSON',
      );
    }
  }
  const auth = res.headers.get('www-authenticate');
  if (auth && /payment/i.test(auth))
    return { protocol: 'mpp', payload: { challenge: auth } };
  try {
    const body = JSON.parse(bodyText) as unknown;
    if (isRecord(body) && 'x402Version' in body)
      return { protocol: 'x402', payload: { paymentRequired: body } };
  } catch {
    throw new ToolError(
      'the server answered 402 without a payment request bursar understands',
    );
  }
  throw new ToolError(
    'the server answered 402 without a payment request bursar understands',
  );
}

export function createMcpServer(deps: McpDeps) {
  const doFetch: Fetch = deps.fetch ?? ((url, init) => fetch(url, init));
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pollMs = deps.pollMs ?? 3000;
  const maxBody = deps.maxBodyChars ?? 20_000;
  const pending = new Map<string, Record<string, unknown>>();

  async function bursar(
    path: string,
    init: { method: 'GET' | 'POST'; body?: unknown },
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    let res: Response;
    try {
      const reqInit: RequestInit = {
        method: init.method,
        headers: {
          authorization: `Bearer ${deps.token}`,
          'content-type': 'application/json',
        },
      };
      if (init.body !== undefined) reqInit.body = JSON.stringify(init.body);
      res = await doFetch(`${deps.bursarUrl}${path}`, reqInit);
    } catch (e) {
      throw new ToolError(
        `bursar is not reachable at ${deps.bursarUrl} (${(e as Error).message}); ask the human to start it`,
      );
    }
    const raw = await res.text();
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      throw new ToolError(`bursar returned HTTP ${res.status} without JSON`);
    }
    if (!isRecord(body))
      throw new ToolError(
        `bursar returned HTTP ${res.status} without a JSON object`,
      );
    return { status: res.status, body };
  }

  async function merchant(
    a: PayArgs,
    extra: Record<string, string> = {},
  ): Promise<{ res: Response; text: string }> {
    const init: RequestInit = {
      method: a.method,
      headers: { ...a.headers, ...extra },
      redirect: 'manual',
    };
    if (a.body !== undefined) init.body = a.body;
    let res: Response;
    try {
      res = await doFetch(a.url, init);
    } catch (e) {
      throw new ToolError(
        `request to ${a.url} failed: ${(e as Error).message}`,
      );
    }
    return { res, text: await res.text() };
  }

  function clip(s: string): string {
    return s.length > maxBody
      ? `${s.slice(0, maxBody)}\n… (${s.length - maxBody} more characters)`
      : s;
  }

  async function pay(a: PayArgs): Promise<ToolResult> {
    const bodySha256 = sha256Hex(a.body ?? '');
    const resource = { method: a.method, url: a.url, bodySha256 };
    const resourceHash = computeResourceHash(resource);
    const pendingKey = `${resourceHash}|${a.taskId ?? ''}`;

    let request = pending.get(pendingKey);
    if (request === undefined) {
      const first = await merchant(a);
      if (first.res.status !== 402) {
        return text({
          paid: false,
          status: first.res.status,
          body: clip(first.text),
        });
      }
      const { protocol, payload } = paymentRequest(first.res, first.text, a);
      request = {
        protocol,
        payload,
        idempotencyKey: `mcp-${randomUUID()}`,
        resource,
        resourceHash,
      };
      if (a.taskId !== undefined) request['taskId'] = a.taskId;
    }

    const deadline = Date.now() + a.waitSeconds * 1000;
    let result: Record<string, unknown>;
    for (;;) {
      const out = await bursar('/v1/sign', { method: 'POST', body: request });
      result = out.body;
      if (result['status'] !== 'pending') break;
      if (Date.now() + pollMs > deadline) {
        pending.set(pendingKey, request);
        const fresh = result['reason'] === 'new_recipient';
        return text({
          paid: false,
          status: 'pending_approval',
          reason: result['reason'] ?? 'threshold',
          approvalId: result['approvalId'],
          approvalUrl: result['approvalUrl'],
          expiresAt: result['expiresAt'],
          next: fresh
            ? 'This service is new to bursar, so a human has to allow it once. Show them the approvalUrl; they can allow this payment or always allow the service. Call pay again with the same arguments after they confirm.'
            : 'A human has to approve this payment. Show them the approvalUrl (or tell them to run: bursar approvals), and call pay again with the same arguments after they confirm.',
        });
      }
      await sleep(pollMs);
    }
    pending.delete(pendingKey);

    if (result['status'] === 'denied') {
      return text(
        {
          paid: false,
          status: 'denied',
          reason: result['reason'],
          next: 'Do not retry or pay another way. Tell the human why bursar refused.',
        },
        true,
      );
    }
    if (result['status'] === 'processing') {
      return text({
        paid: false,
        status: 'processing',
        reason: result['reason'] ?? null,
        next: 'bursar has started this payment but the mint did not answer yet. Call pay again with the same arguments in a minute; it will not pay twice.',
      });
    }
    // Cashu without a lock: bursar delivered the token itself and returns the
    // merchant's answer. The agent never holds the ecash.
    if (result['status'] === 'paid') {
      const resp = isRecord(result['response']) ? result['response'] : {};
      const st = typeof resp['status'] === 'number' ? resp['status'] : 0;
      const ok = st >= 200 && st < 300;
      return text(
        {
          paid: ok,
          ...amountOf(result),
          recipient: result['recipient'],
          chain: result['chain'],
          status: st,
          body: clip(typeof resp['body'] === 'string' ? resp['body'] : ''),
          ...(result['note'] === undefined ? {} : { note: result['note'] }),
        },
        !ok,
      );
    }
    if (result['status'] !== 'signed') {
      return text(
        {
          paid: false,
          status: result['status'],
          error: result['error'] ?? result['reason'],
        },
        true,
      );
    }
    const header = result['header'];
    if (
      !isRecord(header) ||
      typeof header['name'] !== 'string' ||
      typeof header['value'] !== 'string'
    ) {
      return text(
        {
          paid: false,
          status: 'signed_without_header',
          note: 'bursar signed, but this protocol has no HTTP header to attach',
        },
        true,
      );
    }
    const second = await merchant(a, { [header['name']]: header['value'] });
    const receipt =
      second.res.headers.get('payment-response') ??
      second.res.headers.get('x-payment-response') ??
      second.res.headers.get('payment-receipt');
    let decodedReceipt: unknown = receipt;
    if (receipt) {
      try {
        decodedReceipt = JSON.parse(
          Buffer.from(receipt, 'base64').toString('utf8'),
        );
      } catch {
        decodedReceipt = receipt;
      }
    }
    return text(
      {
        paid: second.res.ok,
        ...amountOf(result),
        recipient: result['recipient'],
        chain: result['chain'],
        status: second.res.status,
        receipt: decodedReceipt ?? null,
        body: clip(second.text),
      },
      !second.res.ok,
    );
  }

  async function callTool(
    name: unknown,
    rawArgs: unknown,
  ): Promise<ToolResult> {
    const args = isRecord(rawArgs) ? rawArgs : {};
    try {
      if (name === 'pay') return await pay(parsePayArgs(args));
      if (name === 'budget') {
        const task = optString(args, 'task_id');
        const out = await bursar(
          `/v1/budget${task ? `?taskId=${encodeURIComponent(task)}` : ''}`,
          { method: 'GET' },
        );
        return text(out.body, out.status !== 200);
      }
      if (name === 'open_task') {
        const budgetUsd = optString(args, 'budget_usd');
        const budgetSat = optString(args, 'budget_sat');
        if (budgetUsd === undefined && budgetSat === undefined)
          throw new ToolError('budget_usd or budget_sat is required');
        const ttl = args['ttl_seconds'];
        const body: Record<string, unknown> = {
          ttlSeconds: typeof ttl === 'number' ? ttl : 3600,
        };
        if (budgetUsd !== undefined) body['budgetUsd'] = budgetUsd;
        if (budgetSat !== undefined) body['budgetSat'] = budgetSat;
        const label = optString(args, 'label');
        if (label !== undefined) body['label'] = label;
        const out = await bursar('/v1/tasks', { method: 'POST', body });
        return text(out.body, out.status >= 300);
      }
      return text(`unknown tool ${String(name)}`, true);
    } catch (e) {
      if (e instanceof ToolError) return text(e.message, true);
      throw e;
    }
  }

  async function handle(msg: JsonRpc): Promise<Record<string, unknown> | null> {
    const id = msg.id;
    if (id === undefined || id === null) return null;
    const reply = (result: unknown) => ({ jsonrpc: '2.0', id, result });
    switch (msg.method) {
      case 'initialize': {
        const requested = isRecord(msg.params)
          ? msg.params['protocolVersion']
          : undefined;
        return reply({
          protocolVersion:
            typeof requested === 'string' ? requested : PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: 'bursar', version: '0.1.0' },
          instructions:
            "Payments go through the local bursar daemon, which enforces the human's spending policy. Use the pay tool for any URL that answers 402. Never ask for keys or try to pay another way.",
        });
      }
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools: TOOLS });
      case 'tools/call': {
        const p = isRecord(msg.params) ? msg.params : {};
        return reply(await callTool(p['name'], p['arguments']));
      }
      default:
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `method not found: ${String(msg.method)}`,
          },
        };
    }
  }

  return { handle, callTool };
}

// BURSAR_TOKEN_FILE lets setup register the server without putting the token
// on a command line, where other local users can read it. An unreadable file
// throws, so the error names it instead of a generic "set BURSAR_TOKEN".
export function readToken(env: NodeJS.ProcessEnv): string | undefined {
  const file = env['BURSAR_TOKEN_FILE'];
  return (
    env['BURSAR_TOKEN'] ||
    (file ? readFileSync(file, 'utf8').trim() : undefined) ||
    undefined
  );
}

export function runStdio(env: NodeJS.ProcessEnv = process.env): void {
  let token: string | undefined;
  try {
    token = readToken(env);
  } catch (e) {
    process.stderr.write(`bursar-mcp: ${(e as Error).message}\n`);
    process.exit(1);
  }
  if (!token) {
    process.stderr.write(
      "bursar-mcp: set BURSAR_TOKEN (or BURSAR_TOKEN_FILE) to this agent's token\n",
    );
    process.exit(1);
  }
  const server = createMcpServer({
    bursarUrl: env['BURSAR_URL'] ?? 'http://127.0.0.1:8402',
    token,
  });
  const rl = createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (line.trim() === '') return;
    let msg: JsonRpc;
    try {
      msg = JSON.parse(line) as JsonRpc;
    } catch {
      process.stdout.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } })}\n`,
      );
      return;
    }
    void server.handle(msg).then(
      (out) => {
        if (out) process.stdout.write(`${JSON.stringify(out)}\n`);
      },
      (e: unknown) => {
        process.stdout.write(
          `${JSON.stringify({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: (e as Error).message } })}\n`,
        );
      },
    );
  });
}

if (import.meta.main) runStdio();
