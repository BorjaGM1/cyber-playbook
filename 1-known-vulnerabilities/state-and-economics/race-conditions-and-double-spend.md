# Race Conditions, TOCTOU & Atomic Double-Spend Prevention

## 1. Attack Transcript

A tenant holds exactly one unit of credit (`balance = 10`, `cost = 10`). The attacker opens 25 warm connections and releases them in the same millisecond (see [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md)):

```text
$ node race-harness.mjs --path /api/credits/spend --body '{"cost":10}' --n 25 \
      --header 'Cookie: __Host-session=<tenant B session>' \
      --header 'Idempotency-Key: k-{i}'
sent 25 requests, barrier released, arrival jitter 0.4 ms
status histogram: 200 x 19, 402 x 6
upstream LLM calls billed: 19
final balance: -180

$ node race-harness.mjs --path /api/projects --body '{"name":"p{i}"}' --n 25   # plan limit = 2, owns 1
status histogram: 201 x 7, 402 x 18
projects after burst: 8
```

Sequential tests (`for i in 1..25; do curl ...; done`) show `1 x 200, 24 x 402` and a green CI run. Only the burst reveals the bug.

---

## 2. Spot the Bug

Two handlers. Both pass every sequential unit test. Find the race in each before reading on.

```typescript
export async function spendCredits(tenantId: string, cost: number) {
  const row = await db.queryOne<{ balance: number }>(
    "SELECT balance FROM tenant_wallets WHERE tenant_id = $1",
    [tenantId]
  );

  if (!row || row.balance < cost) {
    throw new Error("INSUFFICIENT_CREDITS");
  }

  const paidResult = await callExpensiveUpstreamApi();

  await db.execute(
    "UPDATE tenant_wallets SET balance = $1 WHERE tenant_id = $2",
    [row.balance - cost, tenantId]
  );

  return paidResult;
}
```

```sql
-- Plan quota ("atomic" because it is a single statement):
INSERT INTO projects (id, tenant_id, name)
SELECT $1, $2, $3
WHERE (
    SELECT COUNT(*)
    FROM projects p
    WHERE p.tenant_id = $2
      AND p.archived_at IS NULL
) < $4
RETURNING id, tenant_id, name;
```

<details>
<summary>Reveal</summary>

1. `spendCredits` is a read-modify-write: every concurrent caller reads `balance = 10`, all pass the check, all call the paid upstream, and the last write wins (`SET balance = $1` is an absolute value computed in application memory).
2. The quota statement is **a single statement but not atomic under PostgreSQL `READ COMMITTED`.** The `COUNT(*)` subquery reads a snapshot and takes no lock. Two concurrent transactions both see `count = 1`, both satisfy `1 < 2`, and both insert. A single `INSERT … SELECT … WHERE (count) < max` is only safe if something serializes the callers (a locked row, an advisory lock, or `SERIALIZABLE` with retry). The earlier revision of this note presented that statement as hardened; it was not.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` (conservation of balances, credits, quotas, single-use coupons, and idempotency keys).
- **Mechanism:** Time-of-Check to Time-of-Use (TOCTOU) occurs when an application handles a state-changing request in two separate steps:
  1. **Check:** read the current state (`SELECT balance …`, `SELECT used_at …`, `SELECT COUNT(*) …`).
  2. **Use:** decide in TypeScript/Rust (`if (balance >= cost)`), perform an external action (call an LLM, issue a payout, grant a seat), then write the new state.

  When 20+ requests arrive within the same 1–5 ms window (HTTP/2 single-packet multiplexing or barrier-synchronized sockets), all of them execute the check before the first one writes. All pass.
- **Why Happy-Path Tests Miss It:** Standard tests `await` requests one by one. Even `Promise.all()` over cold connections staggers arrivals by 10–30 ms across TCP handshakes. A SQLite lab hides the bug entirely because SQLite serializes writers; the race lab must run the **production engine, isolation level, pool size and instance count** (a connection pool smaller than the burst serializes the burst and hides the bug).
- **A subtle PostgreSQL fact:** a data-modifying CTE (`WITH x AS (INSERT …)`) is executed exactly once and **always to completion, whether or not the primary query reads its output.** A "conditional" `UPDATE … FROM cte` cannot cancel the CTE's `INSERT`. Patterns that rely on the outer statement to veto an inner write leave phantom rows.

### Where It Hides

- **AI Credit / Token / Wallet Deductions:** checking remaining credits before a streaming LLM call and deducting after it finishes, or computing `SET balance = <js value>`.
- **Single-Use Promo Codes, Gift Cards, Referral Links:** `if (!coupon.redeemed_by)` then insert a redemption row without a `UNIQUE` constraint or atomic `UPDATE … WHERE redeemed_at IS NULL`.
- **Plan Quota / Seat Limits:** `const count = await countProjects(orgId); if (count < 3) await insertProject(...)`.
- **Invitation & Password-Reset Token Consumption:** replaying one single-use token in parallel to mint several sessions or duplicate memberships.
- **Webhook / Checkout Fulfillment:** concurrent deliveries of the same event (see [`workflow-step-skipping-and-webhooks.md`](workflow-step-skipping-and-webhooks.md)).
- **Refresh-token rotation and revocation:** reuse detection that checks then marks, letting two parallel refreshes both succeed.

---

## 4. Hardened Pattern

### 4.1 Reserve → Settle → Refund with a real transaction

Rules: (a) the balance `UPDATE` is the gate, and the ledger row exists **only if** the debit succeeded; (b) a replayed idempotency key returns the **stored original result**, not an error; (c) the debit is reserved **before** the upstream call at the *maximum* possible cost, then settled to actual cost; (d) stuck reservations are reaped.

```typescript
interface SpendOutcome {
  readonly kind: "reserved" | "replay";
  readonly reservationId: string;
  readonly storedResult?: unknown; // present on replay of a committed spend
}

export async function reserveCredits(
  scope: TenantScope,
  maxCost: number,
  idempotencyKey: string
): Promise<SpendOutcome> {
  if (!Number.isSafeInteger(maxCost) || maxCost <= 0 || maxCost > 1_000_000) {
    throw new Error("INVALID_COST_MUST_BE_POSITIVE_INTEGER");
  }

  return db.transaction(async (tx) => {
    // 1. Claim the idempotency key. The UNIQUE (tenant_id, idempotency_key) index makes
    //    concurrent callers with the same key queue on this row.
    const claimed = await tx.queryOne<{ id: string }>(
      `INSERT INTO wallet_ledger (id, tenant_id, idempotency_key, delta, status, created_at)
       VALUES ($1, $2, $3, $4, 'reserved', CURRENT_TIMESTAMP)
       ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
       RETURNING id`,
      [crypto.randomUUID(), scope.tenantId, idempotencyKey, -maxCost]
    );

    if (!claimed) {
      // Replay: return what the first request produced (never a second debit, never a bare error).
      const prior = await tx.queryOne<{ id: string; status: string; result_json: unknown }>(
        `SELECT id, status, result_json FROM wallet_ledger
          WHERE tenant_id = $1 AND idempotency_key = $2`,
        [scope.tenantId, idempotencyKey]
      );
      if (!prior) throw new Error("LEDGER_INCONSISTENT");
      return { kind: "replay", reservationId: prior.id, storedResult: prior.result_json };
    }

    // 2. The balance UPDATE is the gate. The row lock serializes concurrent spenders, and under
    //    READ COMMITTED the WHERE clause is re-evaluated after the lock is acquired.
    const debited = await tx.queryOne<{ balance: number }>(
      `UPDATE tenant_wallets
          SET balance = balance - $2, updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = $1 AND balance >= $2
        RETURNING balance`,
      [scope.tenantId, maxCost]
    );

    if (!debited) {
      // Throwing rolls the transaction back, which also removes the ledger row claimed in step 1.
      throw new Error("INSUFFICIENT_CREDITS");
    }
    return { kind: "reserved", reservationId: claimed.id };
  });
}

export async function settleCredits(
  scope: TenantScope,
  reservationId: string,
  maxCost: number,
  actualCost: number,
  result: unknown
): Promise<void> {
  if (!Number.isSafeInteger(actualCost) || actualCost < 0 || actualCost > maxCost) {
    throw new Error("INVALID_ACTUAL_COST");
  }
  await db.transaction(async (tx) => {
    const settled = await tx.queryOne<{ id: string }>(
      `UPDATE wallet_ledger
          SET status = 'committed', delta = -$3, result_json = $4
        WHERE id = $1 AND tenant_id = $2 AND status = 'reserved'
        RETURNING id`,
      [reservationId, scope.tenantId, actualCost, JSON.stringify(result)]
    );
    if (!settled) return; // already settled/refunded: settling twice must be a no-op
    // Give back the unused part of the reservation (streaming LLM: reserved max_tokens, used fewer).
    if (actualCost < maxCost) {
      await tx.execute(
        `UPDATE tenant_wallets SET balance = balance + $2 WHERE tenant_id = $1`,
        [scope.tenantId, maxCost - actualCost]
      );
    }
  });
}

export async function spendCreditsHardened(
  scope: TenantScope,
  maxCost: number,
  idempotencyKey: string,
  runUpstream: () => Promise<{ result: unknown; actualCost: number }>
) {
  const outcome = await reserveCredits(scope, maxCost, idempotencyKey);
  if (outcome.kind === "replay") return outcome.storedResult;

  try {
    const { result, actualCost } = await runUpstream();
    await settleCredits(scope, outcome.reservationId, maxCost, actualCost, result);
    return result;
  } catch (err) {
    await refundReservation(scope.tenantId, outcome.reservationId);
    throw err;
  }
}

// Compensating refund. Takes the amount from the LEDGER row, never from application memory, and only
// fires once because of the `status = 'reserved'` guard. The reaper below reuses it.
export async function refundReservation(tenantId: string, reservationId: string): Promise<void> {
  await db.execute(
    `WITH refunded AS (
       UPDATE wallet_ledger
          SET status = 'refunded'
        WHERE id = $1 AND tenant_id = $2 AND status = 'reserved'
        RETURNING -delta AS amount
     )
     UPDATE tenant_wallets w
        SET balance = w.balance + r.amount
       FROM refunded r
      WHERE w.tenant_id = $2`,
    [reservationId, tenantId]
  );
}
```

Reaper (cron / scheduled worker; a process that crashes between reserve and settle would otherwise strand credits forever):

```sql
-- Run every minute. Pick the timeout above the maximum upstream duration.
SELECT id, tenant_id
  FROM wallet_ledger
 WHERE status = 'reserved'
   AND created_at < CURRENT_TIMESTAMP - INTERVAL '15 minutes'
 LIMIT 500;
-- then call refundReservation(tenant_id, id) for each row (the status guard makes it safe to race with a late settle).
```

Schema backstops:

```sql
ALTER TABLE tenant_wallets ADD CONSTRAINT wallet_non_negative CHECK (balance >= 0);
CREATE UNIQUE INDEX wallet_ledger_idem ON wallet_ledger (tenant_id, idempotency_key);
```

> The earlier revision used a single statement `WITH dedup AS (INSERT … ON CONFLICT DO NOTHING RETURNING id) UPDATE tenant_wallets … FROM dedup WHERE balance >= $4`. Because the CTE's `INSERT` always executes, an insufficient balance left a phantom `reserved` ledger row and burned the idempotency key, and a duplicate key returned a bare error instead of the original result. The transaction above fixes both.

### 4.2 Plan quotas: serialize on a counter row (not on `COUNT(*)`)

```sql
-- tenant_quotas(tenant_id PK, projects_used int NOT NULL, projects_max int NOT NULL, CHECK (projects_used >= 0))
-- Inside ONE transaction with the INSERT. The row lock on tenant_quotas serializes concurrent creators;
-- under READ COMMITTED the WHERE is re-checked after the lock is acquired, so exactly `max` succeed.
UPDATE tenant_quotas
   SET projects_used = projects_used + 1
 WHERE tenant_id = $1
   AND projects_used < projects_max
RETURNING projects_used;
-- 0 rows  => quota exhausted: abort (402/409), nothing was written.
-- 1 row   => INSERT INTO projects (...) in the same transaction; COMMIT.
-- On project delete/archive: UPDATE tenant_quotas SET projects_used = projects_used - 1 ... in the same transaction.
```

Alternatives when a counter column is impractical:

```sql
-- (a) Advisory lock: serialize all creators for this tenant for the duration of the transaction.
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));
-- then: INSERT ... SELECT ... WHERE (SELECT COUNT(*) ...) < $max   -- now safe, callers are serialized

-- (b) SERIALIZABLE (and retry on SQLSTATE 40001):
BEGIN ISOLATION LEVEL SERIALIZABLE; -- count, insert, COMMIT; retry the whole transaction on serialization failure
```

### 4.3 Single-use coupons and invites: consume with a guarded `UPDATE`

```sql
UPDATE coupons
   SET redeemed_count = redeemed_count + 1
 WHERE code_hash = $1 AND redeemed_count < max_uses AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
RETURNING id, credit_amount;
-- plus: CREATE UNIQUE INDEX one_redemption_per_tenant ON coupon_redemptions (coupon_id, tenant_id);

UPDATE invites
   SET used_at = CURRENT_TIMESTAMP
 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
RETURNING id, tenant_id, role;
```

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Cost unknown until the end (streaming LLM):** reserving `maxCost` can starve a tenant that runs many concurrent streams. Cap concurrent reservations per tenant and make the reserved amount a function of the request's `max_tokens` and input size (see [`public-compute-and-denial-of-wallet.md`](public-compute-and-denial-of-wallet.md)).
- **Cross-system effects:** if `runUpstream` succeeds but the process dies before `settleCredits`, the reaper refunds a call that was actually delivered (free usage) — or never refunds if the reaper window is long. Log upstream request IDs in the ledger and reconcile with the provider's usage report.
- **Counters drift:** `projects_used` can disagree with `COUNT(*)` after manual SQL or a missed decrement. Run a nightly reconciliation job and alert on drift.
- **Multiple databases/regions:** row locks do not span replicas or regions. If the wallet lives in a eventually-consistent store (KV), a single-key compare-and-swap with versioning, or a single-writer actor (Durable Object per tenant), is required.
- **Hot rows:** a global counter updated by thousands of requests per second serializes on one row. Shard the counter (N sub-rows, sum on read) and accept a small overshoot bound.
- **Isolation assumptions:** guarded `UPDATE`s rely on `READ COMMITTED` re-evaluation or stricter. Under `REPEATABLE READ` the second updater gets a serialization failure and must be retried, not treated as "insufficient credits".
- **Revoke-vs-use:** a request that began before revocation commits can still complete. Define the SLO (for example, "no request *starting* after the revocation commit succeeds") and test it as written.

---

## 6. How to Discover It Automatically

### A. Static (Semgrep-style rule + ripgrep)

```yaml
# semgrep: absolute-value balance writes computed in application memory
rules:
  - id: absolute-balance-write
    languages: [typescript, javascript]
    severity: ERROR
    message: Write balances as relative atomic deltas (SET balance = balance - $1 WHERE balance >= $1)
    patterns:
      - pattern-regex: '(?is)SET\s+(balance|credits|quota|used_count)\s*=\s*(\$\d+|\?|:\w+)\s'
```

```bash
# Non-atomic absolute writes:
rg -n -i 'SET\s+(balance|credits|quota|used_count)\s*=\s*(\$\d|\?|:\w)' src/

# Coupon/invite redemption that separates SELECT and UPDATE:
rg -n -C 8 'redeemed_at|used_at|remaining_uses' src/

# Count-then-insert quota checks:
rg -n -U -i 'SELECT\s+COUNT\(\*\)[^;]*;[\s\S]{0,400}INSERT\s+INTO' src/
rg -n -i 'INSERT\s+INTO[^;]*SELECT[^;]*WHERE\s*\(\s*SELECT\s+COUNT' src/ migrations/

# Data-modifying CTEs whose outer statement is expected to veto the write:
rg -n -U -i 'WITH\s+\w+\s+AS\s*\(\s*INSERT' src/
```

### B. Dynamic Attacker Test (Barrier-Synchronized Race Burst)

Follow [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md) on the **production database engine** with a pool at least as large as the burst:

1. Seed `Tenant B` with `balance = 10` (exactly one action of `cost = 10`), one single-use coupon `SAVE10`, a plan quota `max_projects = 2` with one project already created.
2. Release 25 simultaneous requests against `POST /api/credits/spend` (once with 25 distinct idempotency keys, once with 25 identical ones), `POST /api/coupons/redeem`, and `POST /api/projects`.
3. **Pass criteria:** exactly 1 `200`; 24 × `409`/`402`/`422` (or, for identical idempotency keys, 25 responses carrying the same stored result and one debit); `wallet.balance === 0` (never negative); `COUNT(redeemed_coupons) === 1`; `COUNT(projects) === 2`; zero phantom `reserved` ledger rows after the burst; upstream mock called exactly once.
4. Run the query-log and DB-diff checks from [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md) to confirm no other table changed.

---

## 7. How to Eliminate the Bug Class by Construction

1. **Ban Absolute-Value Balance Writes:** never write `SET balance = $1`. Only relative deltas guarded by `WHERE balance >= $1`, paired with `CHECK (balance >= 0)`.
2. **One module owns money:** route every wallet, quota and coupon mutation through a ledger module that exposes only `reserve / settle / refund`. Lint-ban direct writes to `tenant_wallets`, `tenant_quotas` and `coupons` elsewhere (see [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md) for how the scoped builder keeps these tables behind one module).
3. **Positive-integer input schemas:** `z.number().int().positive().max(1_000_000)` so `cost: -500` cannot turn a debit into a credit and `NaN`/`Infinity`/floats are rejected at parse time.
4. **`UNIQUE` constraints for idempotency and single use:** `UNIQUE (tenant_id, idempotency_key)` and `UNIQUE (coupon_id, tenant_id)` make concurrent inserts physically conflict at the index level.
5. **Quota counters, not counts:** enforce limits with a guarded counter `UPDATE`, an advisory lock, or `SERIALIZABLE` + retry. Never with an unlocked `COUNT(*)`.
6. **Run the burst test in CI** against the real engine for every endpoint that touches money, quota, tokens or single-use secrets.
