# Public Compute, Rate-Limit Bypass & Denial-of-Wallet (DoW)

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` and `I5 — Minimal Blast Radius` (OWASP ASVS `v5.0.0-5.2.1`, `6.1.1`, `6.3.1`).
- **Mechanism:** A **Denial-of-Wallet (DoW)** or resource-exhaustion vulnerability occurs when an unauthenticated (or free-tier) caller can trigger an operation whose marginal cost to the server (LLM tokens, third-party search/fetch API bills, headless browser rendering, image/video transcoding, bcrypt/Argon2 hashing of megabyte strings, or catastrophic backtracking regular expressions) is orders of magnitude higher than the cost of sending the HTTP request.
- **Common Rate-Limit Failure Modes:**
  1. **Trusting Spoofable Client IP Headers:** Reading the first entry of `X-Forwarded-For` (`req.headers.get("x-forwarded-for")?.split(",")[0]`), which any attacker can randomize on every request (`X-Forwarded-For: 1.2.3.4`), completely bypassing IP rate limits.
  2. **In-Memory Rate Limiting in Serverless/Edge Isolates:** Storing rate-limit counters in a global JavaScript `Map` inside a serverless function or horizontal container pool where each isolate has its own memory, multiplying the effective limit by the number of isolates.
  3. **Post-Compute Deduction:** Checking the rate limit before an expensive 15-second LLM stream, but only incrementing the counter *after* the stream completes—allowing an attacker to open 100 concurrent streams before the counter increments from `0` to `1`.

---

## 2. Where It Hides

- Public "free tools", AI playgrounds, chat widgets, or preview endpoints (`/api/generate`, `/api/analyze`, `/api/preview`) that invoke OpenAI, Anthropic, DeepSeek, or paid scraper APIs without an atomic pre-call budget cap.
- Authentication endpoints (`/api/auth/login`, `/api/auth/magic-link`, `/api/auth/register`) that send paid SMS/transactional emails on every POST or pass a 10MB password string into `bcrypt` (locking the CPU thread for seconds).
- File upload or webhook endpoints that call `await req.arrayBuffer()` or `await req.json()` before enforcing a hard byte-stream ceiling (`ASVS v5.0.0-5.2.1`).

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Spoofable `X-Forwarded-For` + Post-Call Counter + Unbounded Input)

```typescript
const memoryHits = new Map<string, number>();

// VULNERABLE:
// 1. Trusts client-spoofed `x-forwarded-for` first IP!
// 2. Uses per-isolate in-memory Map that resets across workers/restarts.
// 3. Increments counter AFTER the paid LLM call (vulnerable to parallel burst).
// 4. Accepts unbounded `prompt` length and sets no `max_tokens` ceiling.
export async function generatePreviewVulnerable(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const used = memoryHits.get(ip) ?? 0;
  if (used >= 5) {
    return new Response("Rate limit exceeded", { status: 429 });
  }

  const { prompt } = await req.json();
  const completion = await callPaidLlmApi({ prompt }); // Attacker sends 500KB prompt 200x in parallel!

  memoryHits.set(ip, used + 1);
  return Response.json({ completion });
}
```

### Hardened Pattern (TypeScript — Trusted Edge IP + Atomic Pre-Call Sliding Window + Hard Spend Caps)

```typescript
// 1. Extract client IP ONLY from the trusted edge proxy header set by your infrastructure
//    (e.g., `cf-connecting-ip` on Cloudflare, or the right-most untrusted hop in XFF).
export function getTrustedClientIp(req: Request, isBehindCloudflare: boolean): string {
  if (isBehindCloudflare) {
    const cfIp = req.headers.get("cf-connecting-ip");
    if (cfIp) return cfIp.trim();
  }
  throw new Error("UNTRUSTED_CLIENT_IP_SOURCE");
}

// 2. Enforce a strict streaming byte limit BEFORE buffering JSON into memory (ASVS v5.0.0-5.2.1):
export async function readBoundedJson<T>(req: Request, maxBytes: number): Promise<T> {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (contentLength > maxBytes) {
    throw new Response(JSON.stringify({ error: "PAYLOAD_TOO_LARGE" }), { status: 413 });
  }
  if (!req.body) {
    throw new Response(JSON.stringify({ error: "EMPTY_BODY" }), { status: 400 });
  }

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

  const combined = Buffer.concat(chunks).toString("utf8");
  return JSON.parse(combined) as T;
}

// 3. Atomic Pre-Call Rate-Limit + Global Daily Budget Circuit Breaker in Database:
export async function acquireComputeSlotOrThrow(
  db: SqlExecutor,
  bucketKey: string,
  windowSeconds: number,
  maxHitsPerKey: number,
  globalDailyCapHits: number
): Promise<void> {
  const nowEpoch = Math.floor(Date.now() / 1000);
  const windowStart = nowEpoch - (nowEpoch % windowSeconds);
  const dayStart = nowEpoch - (nowEpoch % 86400);

  // Atomically increments BOTH the per-IP/actor window counter AND the global daily circuit breaker
  // BEFORE any upstream compute or paid API call is made:
  const allowed = await db.queryOne<{ key_hits: number; daily_hits: number }>(
    `WITH global_gate AS (
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
     SELECT a.key_hits, g.daily_hits
       FROM actor_gate a
       CROSS JOIN global_gate g`,
    [dayStart, globalDailyCapHits, bucketKey, windowStart, maxHitsPerKey]
  );

  if (!allowed) {
    throw new Response(JSON.stringify({ error: "RATE_LIMIT_OR_BUDGET_EXCEEDED" }), {
      status: 429,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "retry-after": String(windowSeconds),
      },
    });
  }
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Flag spoofable `x-forwarded-for` `.split(",")[0]` patterns:
rg -n 'x-forwarded-for' src/

# 2. Flag outbound calls to LLM / email / SMS / scraper APIs and verify pre-call atomic rate limits:
rg -n 'api\.openai\.com|api\.anthropic\.com|api\.deepseek\.com|resend\.com|stripe\.com' src/

# 3. Check password hashing calls for missing maximum byte-length bounds (bcrypt 72-byte / DoS trap):
rg -n -C 5 'argon2|bcrypt|scrypt|pbkdf2' src/
```

### B. Dynamic Attacker Test (XFF Spoofing & Parallel Pre-Call Burst)
1. **Header Spoofing Test:** Against a rate-limited endpoint (limit = 5 requests/minute), send 10 sequential requests where each request sets a different `X-Forwarded-For: 203.0.113.${i}` header. Assert that requests 6–10 return `429 Too Many Requests` (proving `X-Forwarded-For` cannot spoof the client identity).
2. **Parallel Pre-Call Burst Test:** Against a fresh rate-limit bucket (limit = 3), fire 15 requests simultaneously at a barrier. Assert that **at most 3** reach the upstream mock handler and **at least 12** are rejected with `429` before touching the upstream dependency.
3. **Oversized Payload Test:** Send a 15MB streaming body with a forged `Content-Length: 100` header. Assert the server cancels the stream and returns `413 Payload Too Large` without OOM-crashing.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Wrap Expensive Sinks in a Budgeted Client:** Do not call `fetch("https://api.openai.com/...")` or `sendEmail()` directly from route handlers. Expose a single `budgetedLlmCall(actorOrIp, params)` wrapper that requires a pre-acquired `ComputeLease` token from `acquireComputeSlotOrThrow` and enforces hard `maxInputChars` and `max_tokens` limits.
2. **Cap Password Input Length at $\le 128$ UTF-8 Bytes (`ASVS v5.0.0-6.2.8`):** Reject passwords longer than 128–256 bytes before passing them to Argon2id/scrypt to prevent CPU exhaustion, while never silently truncating passwords under 64 characters.
