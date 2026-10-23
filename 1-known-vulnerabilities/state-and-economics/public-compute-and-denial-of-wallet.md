# Public Compute, Rate-Limit Bypass, ReDoS & Denial-of-Wallet (DoW)

## 1. Attack Transcript

```text
# Rate limit is 5 requests/minute per client. The attacker rotates a header the server trusts.
$ for i in $(seq 1 200); do
    curl -s -o /dev/null -w "%{http_code} " -X POST https://app.example.com/api/generate \
      -H "X-Forwarded-For: 203.0.113.$i" -H 'content-type: application/json' \
      -d "{\"prompt\":\"$(head -c 400000 /dev/urandom | base64 -w0)\"}" &
  done; wait
200 200 200 200 200 ... (200 x 200)
# provider invoice: 200 requests x ~100k input tokens each

# Same endpoint, IPv6: one /64 allocation = 2^64 source addresses, each "a different client"
$ curl --interface 2001:db8:abcd:1::$RANDOM6 ...

# ReDoS: one request pins a CPU core for seconds
$ curl -s -X POST https://app.example.com/api/validate-slug \
    -d '{"slug":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}'      # /^(a+)+$/ on non-matching input
# 12.4 s

# Oversized password into a memory-hard KDF
$ curl -s -X POST https://app.example.com/api/auth/login -d "{\"email\":\"x@y.z\",\"password\":\"$(head -c 10000000 /dev/zero | tr '\0' a)\"}"
```

---

## 2. Spot the Bug

```typescript
const memoryHits = new Map<string, number>();

export async function generatePreview(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const used = memoryHits.get(ip) ?? 0;
  if (used >= 5) {
    return new Response("Rate limit exceeded", { status: 429 });
  }

  const { prompt } = await req.json();
  const completion = await callPaidLlmApi({ prompt });

  memoryHits.set(ip, used + 1);
  return Response.json({ completion });
}
```

```sql
-- Shared rate-limit statement used by the "hardened" version of the handler above
WITH global_gate AS (
  INSERT INTO rate_limit_buckets (bucket_key, window_start, hits)
  VALUES ('__GLOBAL_DAILY_COMPUTE__', $1, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET hits = rate_limit_buckets.hits + 1
  WHERE rate_limit_buckets.hits < $2
  RETURNING hits AS daily_hits
),
actor_gate AS (
  INSERT INTO rate_limit_buckets (bucket_key, window_start, hits)
  VALUES ($3, $4, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET hits = rate_limit_buckets.hits + 1
  WHERE rate_limit_buckets.hits < $5
    AND EXISTS (SELECT 1 FROM global_gate)
  RETURNING hits AS key_hits
)
SELECT a.key_hits, g.daily_hits FROM actor_gate a CROSS JOIN global_gate g;
```

<details>
<summary>Reveal</summary>

1. The handler trusts the first `X-Forwarded-For` entry (client-chosen), keeps counters in per-isolate memory (each isolate has its own `Map`), increments **after** the paid call (100 parallel requests all see `used = 0`), and accepts an unbounded `prompt` with no `max_tokens` ceiling.
2. In the SQL, both CTEs are data-modifying, so **both always execute**. A request rejected by the per-actor limit has *already* incremented the global daily bucket. A single abusive client sending rejected requests burns the global cap and locks out every legitimate user — a self-inflicted denial of service.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` and `I5 — Minimal Blast Radius` (OWASP ASVS `v5.0.0-5.2.1`, `6.1.1`, `6.3.1`).
- **Mechanism:** a **Denial-of-Wallet (DoW)** or resource-exhaustion vulnerability exists when an unauthenticated (or free-tier) caller can trigger an operation whose marginal server cost (LLM tokens, third-party search/fetch API bills, headless-browser rendering, transcoding, Argon2/bcrypt over megabyte strings, catastrophically backtracking regexes, agent tool loops) is orders of magnitude higher than the cost of sending the request.
- **Common Rate-Limit Failure Modes:**
  1. **Trusting spoofable client IP headers** (`X-Forwarded-For` first entry).
  2. **In-memory counters in serverless/edge isolates** — every isolate has its own memory, multiplying the effective limit by the isolate count.
  3. **Post-compute accounting** — checking before a 15-second LLM stream but incrementing after, so 100 concurrent streams start from `0`.
  4. **Keying on a single IPv6 address** — one residential or cloud allocation is a /64 (2^64 addresses), so per-address limits are meaningless.
  5. **Rejected requests that still consume shared budgets** (the CTE above), turning the limiter into a denial-of-service lever.
  6. **Single dimension limits** — IP only. No per-account, per-tenant or per-run budget.

### Where It Hides

- Public "free tools", AI playgrounds, chat widgets, preview endpoints (`/api/generate`, `/api/analyze`, `/api/preview`) calling paid APIs.
- Authentication endpoints (`/login`, `/magic-link`, `/register`) that send paid SMS/e-mail on every POST or pass a 10 MB password into a KDF.
- Upload and webhook endpoints that call `await req.arrayBuffer()` / `await req.json()` before a byte ceiling.
- Agent loops: a tool-calling agent with no cap on iterations, tokens or wall-clock time.
- Any `new RegExp(userInput)` or user-influenced regex (validators, search highlighters, routers, markdown plugins).

---

## 4. Hardened Pattern

### 4.1 Client identity: trusted source only, IPv6 collapsed to /64

```typescript
import net from "node:net";

/**
 * Only trust `cf-connecting-ip` (or your edge's equivalent) if the origin is reachable ONLY through that
 * edge (tunnel, authenticated origin pulls / mTLS, or firewall allowlist). Otherwise any caller can set
 * the header directly. If the origin is reachable some other way, use the socket peer address.
 */
export function getTrustedClientIp(
  req: Request,
  opts: { originLockedToEdge: boolean; socketPeerIp?: string }
): string {
  if (opts.originLockedToEdge) {
    const edgeIp = req.headers.get("cf-connecting-ip")?.trim();
    if (edgeIp && net.isIP(edgeIp)) return edgeIp;
    throw new Error("UNTRUSTED_CLIENT_IP_SOURCE: edge header missing");
  }
  if (opts.socketPeerIp && net.isIP(opts.socketPeerIp)) return opts.socketPeerIp;
  throw new Error("UNTRUSTED_CLIENT_IP_SOURCE");
}

/** IPv4 -> as is. IPv6 -> the /64 prefix (the unit an attacker controls). */
export function rateLimitKeyForIp(rawIp: string): string {
  const ip = rawIp.split("%")[0]; // strip zone id
  if (net.isIPv4(ip)) return `v4:${ip}`;
  if (!net.isIPv6(ip)) throw new Error("INVALID_IP");

  // Expand to 8 groups (handles "::" and an embedded IPv4 tail such as ::ffff:1.2.3.4).
  let tail4: string[] = [];
  let body = ip;
  const lastColon = ip.lastIndexOf(":");
  const maybeV4 = ip.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const [a, b, c, d] = maybeV4.split(".").map(Number);
    tail4 = [((a << 8) | b).toString(16), ((c << 8) | d).toString(16)];
    body = ip.slice(0, lastColon + 1) + tail4.join(":");
  }
  const [head, rest] = body.split("::");
  const headGroups = head ? head.split(":") : [];
  const restGroups = rest === undefined ? [] : rest ? rest.split(":") : [];
  const fill = rest === undefined ? [] : Array(8 - headGroups.length - restGroups.length).fill("0");
  const groups = [...headGroups, ...fill, ...restGroups].map((g) => g.padStart(4, "0"));
  if (groups.length !== 8) throw new Error("INVALID_IP");
  return `v6:${groups.slice(0, 4).join(":")}`;
}
```

### 4.2 Bounded body reads

```typescript
export async function readBoundedJson<T>(req: Request, maxBytes: number): Promise<T> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declared) || declared < 0 || declared > maxBytes) {
    throw new Response(JSON.stringify({ error: "PAYLOAD_TOO_LARGE" }), { status: 413 });
  }
  if (!req.body) {
    throw new Response(JSON.stringify({ error: "EMPTY_BODY" }), { status: 400 });
  }

  // Content-Length can lie (or be absent with chunked encoding): enforce while streaming.
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel();
      throw new Response(JSON.stringify({ error: "PAYLOAD_TOO_LARGE" }), { status: 413 });
    }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
}
```

### 4.3 Atomic rate limit **and** budget with no shared-budget burn on reject

Both counters are consumed in one transaction, actor first. If the actor is over its limit, the transaction aborts before touching the shared bucket; if the global cap is exhausted, the abort rolls back the actor increment too.

```typescript
export interface ComputeLease {
  readonly actorKey: string;
  readonly tenantKey: string;
}

export async function acquireComputeLeaseOrThrow(
  db: SqlExecutor,
  p: {
    actorKey: string;       // rateLimitKeyForIp(...) or a user id
    tenantKey: string;      // `tenant:${id}`
    windowSeconds: number;
    maxPerActor: number;
    maxPerTenant: number;
    globalDailyCap: number;
  }
): Promise<ComputeLease> {
  const nowEpoch = Math.floor(Date.now() / 1000);
  const windowStart = nowEpoch - (nowEpoch % p.windowSeconds);
  const dayStart = nowEpoch - (nowEpoch % 86400);

  // Guarded upsert: a fresh bucket inserts with hits = 1; an existing one increments only while below
  // its ceiling. Zero rows returned => over limit. (maxPerX must be >= 1.)
  const bump = `INSERT INTO rate_limit_buckets AS b (bucket_key, window_start, hits)
                VALUES ($1, $2, 1)
                ON CONFLICT (bucket_key, window_start)
                DO UPDATE SET hits = b.hits + 1 WHERE b.hits < $3
                RETURNING hits`;

  try {
    await db.transaction(async (tx) => {
      // Cheapest-to-hit, most specific limit first; the shared global bucket last.
      if (!(await tx.queryOne(bump, [`actor:${p.actorKey}`, windowStart, p.maxPerActor]))) throw new LimitHit();
      if (!(await tx.queryOne(bump, [p.tenantKey, windowStart, p.maxPerTenant]))) throw new LimitHit();
      if (!(await tx.queryOne(bump, ["__GLOBAL_DAILY_COMPUTE__", dayStart, p.globalDailyCap]))) throw new LimitHit();
    });
  } catch (e) {
    if (e instanceof LimitHit) {
      throw new Response(JSON.stringify({ error: "RATE_LIMIT_OR_BUDGET_EXCEEDED" }), {
        status: 429,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "retry-after": String(p.windowSeconds),
        },
      });
    }
    throw e;
  }
  return { actorKey: p.actorKey, tenantKey: p.tenantKey };
}
class LimitHit extends Error {}
```

Because a rejected request rolls back, floods of rejected requests do not consume anything shared. They do still cost a database round trip, so put a coarse edge rate limit (WAF rule per IP/ASN) *in front of* this precise limiter.

### 4.4 Wrap every expensive sink in a budgeted client

```typescript
export async function budgetedLlmCall(
  lease: ComputeLease,
  scope: TenantScope,
  params: { prompt: string; maxOutputTokens: number },
  limits = { maxInputChars: 32_000, maxOutputTokensCeiling: 1_024 }
) {
  if (params.prompt.length > limits.maxInputChars) throw new Response("PROMPT_TOO_LARGE", { status: 413 });
  const maxOut = Math.min(params.maxOutputTokens, limits.maxOutputTokensCeiling);
  const estInputTokens = Math.ceil(params.prompt.length / 3); // conservative
  const maxCost = costUnits(estInputTokens, maxOut);

  // reserve-max / settle-actual / refund: see race-conditions-and-double-spend.md
  return spendCreditsHardened(scope, maxCost, crypto.randomUUID(), async () => {
    const out = await callPaidLlmApi({ prompt: params.prompt, max_tokens: maxOut });
    return { result: out, actualCost: costUnits(out.usage.inputTokens, out.usage.outputTokens) };
  });
}
```

### 4.5 Agent / loop cost caps

```typescript
export interface RunBudget {
  maxToolCalls: number;     // e.g. 25
  maxTotalTokens: number;   // input + output across the whole run
  maxWallClockMs: number;   // e.g. 120_000
  maxConcurrentRuns: number; // per tenant
}

export class BudgetExceeded extends Error {}

export function chargeStep(b: RunBudget, used: { toolCalls: number; tokens: number; startedAt: number }): void {
  if (used.toolCalls >= b.maxToolCalls) throw new BudgetExceeded("tool_calls");
  if (used.tokens >= b.maxTotalTokens) throw new BudgetExceeded("tokens");
  if (Date.now() - used.startedAt >= b.maxWallClockMs) throw new BudgetExceeded("wall_clock");
}
```

Enforce these in the harness that runs the loop (not in the system prompt). See [`agentic-and-mcp-threats.md`](../injection-and-trust-boundaries/agentic-and-mcp-threats.md).

### 4.6 ReDoS: linear-time engines, length caps, no user-supplied patterns

```typescript
// 1. Bound the input BEFORE any regex touches it.
const MAX_SLUG = 64;
export function isValidSlug(s: unknown): boolean {
  return typeof s === "string" && s.length <= MAX_SLUG && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(s);
}
// The pattern above has no nested quantifier over overlapping alternatives, so it is linear.

// 2. If a pattern must be complex or comes from a user/config, use a linear-time engine (RE2).
import RE2 from "re2";
const re = new RE2("^(?:a+)+$"); // RE2 never backtracks; .test() is O(n)
```

In Rust, the `regex` crate guarantees linear time; `fancy-regex` and PCRE bindings backtrack and need explicit limits (`backtrack_limit`).

### 4.7 Password length before the KDF

Reject passwords over 128–256 UTF-8 **bytes** before Argon2id/scrypt to prevent CPU/memory exhaustion (ASVS `v5.0.0-6.2.8`: never silently truncate shorter passwords). bcrypt truncates at 72 bytes silently; prefer Argon2id, or pre-hash with a keyed hash and bound the input.

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Botnets defeat any per-IP key.** Require an account (with e-mail verification and a per-account budget) for anything that costs real money; for anonymous trial endpoints add proof-of-work or a challenge and a small global anonymous budget.
- **The global cap is itself a DoS lever:** an attacker who can consume the anonymous budget denies the anonymous tier. Separate global budgets per tier (anonymous, free, paid) so paid customers survive.
- **Hot-row contention:** the global bucket serializes every request on one row. Shard it (N rows, random pick, sum on read) and tolerate a small overshoot.
- **Header trust depends on network topology:** `originLockedToEdge: true` is a deployment fact, not a code flag. Verify it by sending the header directly to the origin from outside (it must be unreachable).
- **Estimation error:** `chars / 3` under-counts for some languages and tokenizers. Settle on the provider's reported usage, and keep an output ceiling that bounds the worst case regardless.
- **Window boundaries:** fixed windows allow 2x bursts at the boundary. Use a sliding-window or token-bucket if that matters.
- **Cost sinks that are not LLMs:** e-mail/SMS sends, PDF/screenshot renders, image transforms, and third-party enrichment calls need the same lease.
- **Regex timeouts in single-threaded runtimes** cannot interrupt a running match; only linear engines or a worker with a kill timer help.

---

## 6. How to Discover It Automatically

### A. Static

```yaml
# semgrep
rules:
  - id: spoofable-xff-first-hop
    languages: [typescript, javascript]
    severity: ERROR
    message: x-forwarded-for first entry is client-controlled; use the trusted edge header or socket peer
    pattern-either:
      - pattern: $REQ.headers.get("x-forwarded-for")
      - pattern: $REQ.headers["x-forwarded-for"]
  - id: user-controlled-regex
    languages: [typescript, javascript]
    severity: WARNING
    message: Dynamic RegExp built from non-literal input (ReDoS); use RE2 or a fixed pattern with a length cap
    pattern: new RegExp($X, ...)
    pattern-not: new RegExp("...", ...)
```

```bash
rg -n 'x-forwarded-for' src/
rg -n 'api\.openai\.com|api\.anthropic\.com|api\.deepseek\.com|resend\.com|stripe\.com' src/   # paid sinks: is a lease acquired before the call?
rg -n -C 5 'argon2|bcrypt|scrypt|pbkdf2' src/                                                  # missing max byte length
rg -n 'new RegExp\(|RegExp\(' src/
rg -n '\.(json|text|arrayBuffer|formData)\(\)' src/                                            # body reads without a bound
rg -n 'new Map<string, number>\(\)' src/                                                       # in-isolate rate-limit state
```

### B. Dynamic Attacker Test

1. **Header Spoofing:** against a limit of 5/min, send 10 requests each with a different `X-Forwarded-For: 203.0.113.${i}` → requests 6–10 must return `429`.
2. **IPv6 Rotation:** send 10 requests from 10 distinct addresses inside one /64 (lab with an IPv6 loopback range) → 429 after the fifth.
3. **Parallel Pre-Call Burst:** against a fresh bucket (limit 3), release 15 requests at a barrier ([`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md)). At most 3 reach the upstream mock; at least 12 get `429` before touching it.
4. **Shared-Budget Burn:** with a global cap of 100 and a per-actor limit of 3, one actor sends 500 requests. Afterwards a second actor's first request must still succeed (the global counter must read ≤ 3 from the first actor).
5. **Oversized Payload:** send a 15 MB streaming body with a forged `Content-Length: 100` → `413`, no OOM.
6. **ReDoS probe:** feed `"a" * 40 + "!"` and other pathological strings to every regex-backed validator with a 500 ms deadline.
7. **Agent loop:** an input that instructs the agent to call a tool forever → run terminates at `maxToolCalls` with `BudgetExceeded`.

Include probes 1–2 and 4 in [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Wrap Expensive Sinks in a Budgeted Client:** never call `fetch("https://api.openai.com/…")` or `sendEmail()` from a route handler. Expose `budgetedLlmCall(lease, scope, params)` that requires a pre-acquired `ComputeLease` and enforces `maxInputChars` and `max_tokens`; lint-ban the raw provider SDK imports outside that module.
2. **One client-identity function:** `getTrustedClientIp` + `rateLimitKeyForIp` are the only code allowed to read IP-ish headers (lint `x-forwarded-for`).
3. **Shared limiter state, not isolate memory:** database, Redis with atomic scripts, or one Durable Object per key. Never a module-level `Map`.
4. **Cap Password Input at ≤ 128 UTF-8 Bytes before the KDF (`ASVS v5.0.0-6.2.8`)**, never silently truncating shorter passwords.
5. **Every body read goes through `readBoundedJson`/`readBoundedBytes`**; ban bare `req.json()` with a lint rule.
6. **Regex policy:** literal patterns only plus an input length cap, RE2 for anything else; no `new RegExp(userInput)`.
7. **Run budgets are harness code:** loops carry `RunBudget`, enforced outside the model.
