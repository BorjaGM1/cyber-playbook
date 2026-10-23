# Step 4: Concurrency, Single-Packet & Race Attack Harnesses

## 1. Mental Model (Why Sequential Tests Never Catch Double-Spends)

A race condition (Time-of-Check to Time-of-Use, or TOCTOU) only manifests when two or more requests execute their database `SELECT` (or in-memory state check) inside the **critical window** $\Delta t$ before the first request commits its `UPDATE` or `INSERT`.

In a local test environment, $\Delta t$ is often only **0.5 ms to 5 ms**. A standard loop—or even `Promise.all(urls.map(u => fetch(u)))`, where TCP connections, TLS handshakes and DNS lookups happen lazily—delivers requests staggered by 5–25 ms, executing serially and missing the bug.

You need three techniques, each with a different job:
1. **Barrier-Synchronized Last-Byte HTTP/1.1 Bursts and HTTP/2 Single-Packet Bursts (black-box / local server):** pre-establish $N$ warm connections (or $N$ HTTP/2 streams), send everything except the final byte, hold at a barrier, then release the final byte of all $N$ requests together.
2. **Real-Engine Transaction Races (SQL level):** call the *production* repository function from $N$ concurrent connections against the *production database engine*. This isolates the database logic from HTTP noise and is the fastest way to reproduce `READ COMMITTED` anomalies.
3. **Deterministic Thread Permutation with `shuttle` / `loom` (white-box Rust, in-process stores only):** systematically explore interleavings of the **production** concurrent data structure, with a mandatory positive control (a deliberately buggy variant that the test must catch).

---

## 2. Engine Fidelity Rules (Read Before Trusting a "Pass")

A race "pass" on a different configuration than production is not a pass.

| Property | Requirement | What goes wrong otherwise |
|----------|-------------|---------------------------|
| **Database engine and version** | Same as production | SQLite serializes writers and hides every row-lock and `READ COMMITTED` race |
| **Isolation level** | Production default (usually `READ COMMITTED` on PostgreSQL) | `SERIALIZABLE` in the lab turns phantom-read bugs into retries and hides them |
| **Pool size** | **≥ burst size** (`DB_POOL_MAX ≥ N`) | With a pool of 10 and a burst of 25, the pool *serializes* 15 requests and hides the bug |
| **App instances** | **≥ 2**, requests alternated between them | In-process mutexes, in-memory rate limiters and caches only protect one instance |
| **Warm-up** | Open all pool connections and JIT paths first | Cold connection setup staggers arrival by tens of milliseconds |
| **Transport** | HTTP/1.1 last-byte *and* HTTP/2 single-packet when the edge supports it | Some proxies serialize HTTP/1.1 per upstream |

Guard the harness itself:

```javascript
export function assertLabFidelity({ burst, poolMax, instances, engine, prodEngine }) {
  const problems = [];
  if (poolMax < burst) problems.push(`DB pool (${poolMax}) < burst (${burst}): the pool will serialize the race`);
  if (instances < 2) problems.push("only 1 app instance: in-process locks/limiters will mask multi-instance races");
  if (engine !== prodEngine) problems.push(`lab engine ${engine} != production ${prodEngine}`);
  if (problems.length) throw new Error(`RACE_LAB_UNFAITHFUL:\n - ${problems.join("\n - ")}`);
}
```

---

## 3. Target Inventory for Race Attacks

Run the barrier race harness against every endpoint that touches any of these state transitions:

| Target Operation | Setup Before Barrier Burst | Burst ($N = 25$ Simultaneous Requests) | Conservation Invariant to Assert After Burst |
|------------------|----------------------------|----------------------------------------|----------------------------------------------|
| **1. Wallet / Credit Spend** | `balance = 10`, action `cost = 10` | `25 × POST /api/credits/spend { cost: 10 }` | `successes === 1`, `final_balance === 0` (never `< 0`), ledger sum equals balance delta |
| **2. Single-Use Coupon / Gift Card** | Coupon `PROMO50` (`max_uses = 1`) | `25 × POST /api/coupons/redeem { code: "PROMO50" }` | `successes === 1`, `credits_added === 50` |
| **3. Plan Resource / Seat Quota** | Free plan (`max_projects = 2`), currently `1` project | `25 × POST /api/projects { name: "p_i" }` | `successes === 1`, `COUNT(projects) === 2` — **requires the production engine at `READ COMMITTED`** (Section 6) |
| **4. Single-Use Invite / Magic Link** | 1 valid invite token `inv_123` | `25 × POST /api/invites/accept { token: "inv_123" }` | `successes === 1`, `COUNT(org_members) === 1` |
| **5. Idempotency Key Deduplication** | `balance = 100`, `cost = 10` | `25 × POST /api/charge` with **same** `Idempotency-Key: k1` | Side effect runs **once**, `final_balance === 90`, and every duplicate returns the **original** response |
| **6. Webhook Event Replay** | Signed payload `evt_001` | `25 × POST /api/webhooks/stripe` with payload `evt_001` | Side effect runs **once**, `COUNT(processed_events) === 1` |
| **7. Revoke-vs-Use Race** | Active API key `sk_live_A` | `1 × DELETE /api/keys/A` raced with `24 × GET /api/data` | Zero `200 OK` responses that *started* after the revocation committed |
| **8. Refresh-Token Rotation** | One refresh token | `25 × POST /api/auth/refresh` with the same token | Exactly one new token pair; reuse revokes the family |
| **9. Global Budget Gate** | Daily cap `= 100` | `25` requests from a client already over its own limit | Global counter increases only for *admitted* requests (rejected requests must not burn the shared budget) |

---

## 4. Reference Implementation: Barrier-Synchronized Last-Byte HTTP Burst (`race-harness.mjs`)

This standalone Node.js script pre-opens $N$ TCP connections, writes each request **except the final body byte**, waits at a barrier until every socket has flushed, then writes the final byte on all sockets in one synchronous loop. It parses responses properly (including `Transfer-Encoding: chunked`), warms the target first, and can alternate between several app instances.

```javascript
// race-harness.mjs — Last-Byte Barrier Race Harness (HTTP/1.1)
import net from "node:net";

/** Decode a complete HTTP/1.1 response (status line + headers + identity or chunked body). */
export function parseHttpResponse(raw /* Buffer */) {
  const sep = raw.indexOf("\r\n\r\n");
  if (sep < 0) return { status: 0, headers: {}, body: "", complete: false };
  const head = raw.subarray(0, sep).toString("latin1").split("\r\n");
  const status = Number(/^HTTP\/1\.[01]\s+(\d{3})/.exec(head[0])?.[1] ?? 0);
  const headers = {};
  for (const line of head.slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  let body = raw.subarray(sep + 4);
  if ((headers["transfer-encoding"] ?? "").toLowerCase().includes("chunked")) {
    const parts = [];
    let off = 0;
    for (;;) {
      const eol = body.indexOf("\r\n", off);
      if (eol < 0) break;
      const size = parseInt(body.subarray(off, eol).toString("latin1").split(";")[0], 16);
      if (!Number.isFinite(size) || size === 0) break;
      parts.push(body.subarray(eol + 2, eol + 2 + size));
      off = eol + 2 + size + 2;
    }
    body = Buffer.concat(parts);
  } else if (headers["content-length"] !== undefined) {
    body = body.subarray(0, Number(headers["content-length"]));
  }
  return { status, headers, body: body.toString("utf8"), complete: true };
}

/**
 * Fires `bodyPayloads.length` requests with last-byte synchronization.
 * `targets` is a list of {host, port}; sockets are assigned round-robin so multi-instance races are exercised.
 */
export async function fireBarrierSynchronizedBurst({
  targets = [{ host: "127.0.0.1", port: 4100 }],
  path,
  method = "POST",
  headers = {},
  bodyPayloads,              // array of strings; length = concurrency
  barrierMs = 60,
  timeoutMs = 15_000,
}) {
  const sockets = [];
  await Promise.all(
    bodyPayloads.map(
      (bodyStr, idx) =>
        new Promise((resolve, reject) => {
          const { host, port } = targets[idx % targets.length];
          const bodyBuf = Buffer.from(bodyStr, "utf8");
          const prefix = bodyBuf.subarray(0, Math.max(0, bodyBuf.length - 1));
          const last = bodyBuf.subarray(Math.max(0, bodyBuf.length - 1));
          const head = [
            `${method} ${path} HTTP/1.1`,
            `Host: ${host}:${port}`,
            `Content-Type: application/json`,
            `Content-Length: ${bodyBuf.length}`,
            `Connection: close`,
            ...Object.entries(headers).map(([k, v]) => `${k}: ${typeof v === "function" ? v(idx) : v}`),
            "", "",
          ].join("\r\n");
          const sock = net.createConnection({ host, port }, () => {
            sock.setNoDelay(true);
            sock.write(Buffer.concat([Buffer.from(head, "utf8"), prefix]), () => {
              sockets.push({ sock, last, idx });
              resolve();
            });
          });
          sock.once("error", reject);
        })
    )
  );

  await new Promise((r) => setTimeout(r, barrierMs));          // all partial requests parked in server buffers

  const results = sockets.map(
    ({ sock, last, idx }) =>
      new Promise((resolve) => {
        const chunks = [];
        const timer = setTimeout(() => { sock.destroy(); resolve({ idx, status: 0, headers: {}, body: "timeout" }); }, timeoutMs);
        sock.on("data", (c) => chunks.push(c));
        sock.on("close", () => { clearTimeout(timer); resolve({ idx, ...parseHttpResponse(Buffer.concat(chunks)) }); });
        sock.on("error", () => {});                              // 'close' follows
      })
  );
  const t0 = process.hrtime.bigint();
  for (const { sock, last } of sockets) sock.write(last);        // release the barrier
  const released = Number(process.hrtime.bigint() - t0) / 1e6;
  const out = await Promise.all(results);
  return { released_ms: released, responses: out };
}

/** Open and use every pool connection before the burst so connection setup cannot stagger arrival. */
export async function warmUp({ targets, path, headers, count = 40 }) {
  await Promise.all(
    Array.from({ length: count }, (_, i) =>
      fetch(`http://${targets[i % targets.length].host}:${targets[i % targets.length].port}${path}`, { headers }).catch(() => {})
    )
  );
}
```

### HTTP/2 Single-Packet Variant

When the edge speaks HTTP/2, the strongest burst is **many streams in one TCP packet**: it removes network jitter entirely. Send headers and all-but-last-byte on every stream, then `cork()` the socket, end all streams, and `uncork()` so the final DATA frames leave in a single write.

```javascript
import http2 from "node:http2";

export async function fireHttp2SinglePacket({ origin, path, headers, bodyPayloads }) {
  const session = http2.connect(origin);
  await new Promise((r) => session.once("connect", r));
  const streams = bodyPayloads.map((body) => {
    const buf = Buffer.from(body);
    const req = session.request({ ":method": "POST", ":path": path, "content-type": "application/json", ...headers }, { endStream: false });
    req.write(buf.subarray(0, buf.length - 1));
    return { req, last: buf.subarray(buf.length - 1) };
  });
  await new Promise((r) => setTimeout(r, 60));                    // headers + partial bodies delivered
  const results = streams.map(({ req }) => new Promise((resolve) => {
    let status = 0; const chunks = [];
    req.on("response", (h) => { status = Number(h[":status"]); });
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve({ status, body: Buffer.concat(chunks).toString("utf8") }));
  }));
  session.socket.cork();
  for (const { req, last } of streams) req.end(last);
  session.socket.uncork();                                        // one TCP write containing every final frame
  const out = await Promise.all(results);
  session.close();
  return out;
}
```

If your stack cannot be reached over HTTP/2 in the lab, record that in `coverage.json` as a limitation rather than silently falling back.

---

## 5. Reference Implementation: SQL-Level Race Test Against the Production Engine

Fastest and least noisy for `I3`: call the **real** repository function (imported from the application, not re-implemented) from $N$ concurrent connections on the production engine at its default isolation level.

```typescript
// race.sql.test.ts — runs against the lab Postgres (same version/isolation as production)
import { Pool } from "pg";
import { assertLabFidelity } from "./race-harness.mjs";
import { spendCredits } from "../src/server/credits";                 // PRODUCTION function
import { createProjectUnderQuota } from "../src/server/projects";     // PRODUCTION function
import { scopeFor } from "./lab-scopes";

const BURST = 25;
const pool = new Pool({ connectionString: process.env.LAB_DATABASE_URL, max: BURST + 5 });   // pool >= burst

test("credit spend: exactly one success, no negative balance, ledger consistent", async () => {
  assertLabFidelity({ burst: BURST, poolMax: BURST + 5, instances: 1, engine: "postgres", prodEngine: "postgres" });
  const scope = await scopeFor(pool, "tenantB", { balance: 10 });
  const results = await Promise.allSettled(
    Array.from({ length: BURST }, (_, i) => spendCredits(pool, scope, 10, `idem-${i}`))   // 25 DISTINCT keys
  );
  const ok = results.filter((r) => r.status === "fulfilled").length;
  const { rows: [w] } = await pool.query("SELECT balance FROM tenant_wallets WHERE tenant_id = $1", [scope.tenantId]);
  const { rows: [l] } = await pool.query(
    "SELECT COALESCE(SUM(delta),0)::int AS net FROM wallet_ledger WHERE tenant_id = $1 AND status IN ('reserved','committed')", [scope.tenantId]);
  expect(ok).toBe(1);
  expect(w.balance).toBe(0);
  expect(l.net).toBe(-10);              // a phantom 'reserved' row on insufficient funds would make this -250
});

test("plan quota: COUNT-subquery insert must not overshoot at READ COMMITTED", async () => {
  const scope = await scopeFor(pool, "tenantB", { maxProjects: 2, existingProjects: 1 });
  const results = await Promise.allSettled(
    Array.from({ length: BURST }, (_, i) => createProjectUnderQuota(pool, scope, `p_${i}`))
  );
  const { rows: [c] } = await pool.query("SELECT COUNT(*)::int AS n FROM projects WHERE tenant_id = $1", [scope.tenantId]);
  expect(results.filter((r) => r.status === "fulfilled").length).toBe(1);
  expect(c.n).toBe(2);
});
```

The quota test **fails** for the `INSERT … SELECT … WHERE (SELECT COUNT(*) …) < max` pattern on PostgreSQL at `READ COMMITTED` (two transactions both read the count before either commits) and **passes** for the counter-row pattern (`UPDATE plan_usage SET projects = projects + 1 WHERE tenant_id = $1 AND projects < $2 RETURNING projects` in the same transaction as the insert). The corrected patterns are in [`../1-known-vulnerabilities/state-and-economics/race-conditions-and-double-spend.md`](../1-known-vulnerabilities/state-and-economics/race-conditions-and-double-spend.md). Run the identical test on SQLite and observe it pass for the vulnerable pattern—that is the engine-fidelity trap in action.

### Multi-Instance Race

Run two (or more) app processes against the same database and alternate burst sockets between their ports (`targets` in `fireBarrierSynchronizedBurst`). Any control that lives in process memory—mutexes, per-isolate rate-limit maps, in-memory idempotency caches, single-flight de-duplication—passes a one-instance burst and fails here.

---

## 6. Deterministic Thread Permutation in Rust (`shuttle`) — For In-Process Stores Only

[`shuttle`](https://github.com/awslabs/shuttle) is for concurrent Rust data structures **that live inside the process** (in-memory ledgers, connection pools, PTY multiplexers, rate-limiter state). It does **not** test SQL behavior, and a test that locks a `Mutex<i64>` it defined itself proves nothing about your code. The pattern below tests the **production type** through a synchronization facade, and ships a positive control:

```rust
// src/sync.rs — facade so production code and shuttle tests share one implementation
#[cfg(feature = "shuttle")]
pub use shuttle::sync::{Arc, Mutex};
#[cfg(not(feature = "shuttle"))]
pub use std::sync::{Arc, Mutex};

// src/credit_store.rs — PRODUCTION type
use crate::sync::Mutex;
use std::collections::HashMap;

#[derive(Default)]
pub struct CreditStore { balances: Mutex<HashMap<String, i64>> }

impl CreditStore {
    pub fn with_balance(tenant: &str, n: i64) -> Self {
        let s = Self::default();
        s.balances.lock().unwrap().insert(tenant.to_owned(), n);
        s
    }
    /// Correct: check and decrement under ONE lock acquisition.
    pub fn try_spend(&self, tenant: &str, cost: i64) -> bool {
        let mut g = self.balances.lock().unwrap();
        match g.get_mut(tenant) {
            Some(b) if *b >= cost => { *b -= cost; true }
            _ => false,
        }
    }
    pub fn balance(&self, tenant: &str) -> i64 { *self.balances.lock().unwrap().get(tenant).unwrap_or(&0) }

    /// Positive control only: check-then-act with two lock acquisitions (the TOCTOU shape).
    #[cfg(test)]
    pub fn try_spend_buggy(&self, tenant: &str, cost: i64) -> bool {
        let ok = self.balance(tenant) >= cost;           // lock 1
        if ok { *self.balances.lock().unwrap().get_mut(tenant).unwrap() -= cost; }   // lock 2
        ok
    }
}

#[cfg(all(test, feature = "shuttle"))]
mod concurrency_tests {
    use super::*;
    use crate::sync::Arc;
    use shuttle::{check_random, thread};

    fn run(spend: fn(&CreditStore, &str, i64) -> bool) -> (usize, i64) {
        let store = Arc::new(CreditStore::with_balance("t", 10));
        let handles: Vec<_> = (0..5).map(|_| {
            let s = Arc::clone(&store);
            thread::spawn(move || spend(&s, "t", 10))
        }).collect();
        let wins = handles.into_iter().map(|h| h.join().unwrap()).filter(|&ok| ok).count();
        (wins, store.balance("t"))
    }

    #[test]
    fn production_try_spend_never_double_spends() {
        check_random(|| { let (wins, bal) = run(CreditStore::try_spend); assert_eq!(wins, 1); assert_eq!(bal, 0); }, 500);
    }

    #[test]
    #[should_panic] // POSITIVE CONTROL: shuttle MUST find the interleaving in the buggy variant
    fn buggy_variant_is_caught_by_the_harness() {
        check_random(|| { let (wins, bal) = run(CreditStore::try_spend_buggy); assert_eq!(wins, 1); assert!(bal >= 0); }, 500);
    }
}
```

Run with `cargo test --features shuttle`. If the `#[should_panic]` control does not fail, your shuttle harness cannot see the race and the first test's "pass" is meaningless.

---

## 7. Interpreting Results

- **Pass criteria are conservation statements**, not response codes: successes count, final balance, row counts and the ledger sum. A response of `200` for all 25 with a correct final state would still be a bug in a different direction (duplicate side effects); check side effects through mock-egress as in [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md).
- **A flaky pass is not a pass.** Repeat the burst 20 times with fresh state; a probabilistic race must be shown absent over many trials, or the endpoint must be rewritten to a single atomic statement.
- **Every confirmed race becomes a permanent regression test** and a guard-mutation target ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md), O9).
