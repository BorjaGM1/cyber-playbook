# Race Conditions, TOCTOU & Atomic Double-Spend Prevention

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` (Conservation of balances, credits, quotas, single-use coupons, and idempotency keys).
- **Mechanism:** Time-of-Check to Time-of-Use (TOCTOU) occurs when an application handles a state-changing request in two separate database steps:
  1. **Check (`SELECT`):** Read the current state (`SELECT balance FROM wallets WHERE tenant_id = $1` or `SELECT used_at FROM coupons WHERE code = $1` or `SELECT COUNT(*) FROM projects WHERE tenant_id = $1`).
  2. **Use (`UPDATE` / `INSERT`):** Check the condition in TypeScript/Rust (`if (balance >= cost)`), perform an external action (e.g., call an LLM, issue a payout, grant a seat), and then write the new state (`UPDATE wallets SET balance = $1`).
  When an attacker sends 20 parallel requests synchronized to arrive within the same 1–5 millisecond window (using HTTP/2 single-packet multiplexing or barrier-synchronized sockets), all 20 requests execute the `SELECT` before the first request executes the `UPDATE`. All 20 pass the `if (balance >= cost)` check, spending a balance of 1 credit 20 times.
- **Why Happy-Path Tests Miss It:** Standard unit and integration tests `await` requests one by one. Even a naive `Promise.all()` over slow client connections often staggers requests by 10–30ms across TCP handshakes, missing narrow race windows unless a barrier-synchronized harness is used.

---

## 2. Where It Hides

- **AI Credit / Token / Wallet Deductions:** Checking remaining credits before firing a streaming LLM call and deducting credits only after the stream finishes (or via `SET balance = currentBalance - cost` computed in JS memory).
- **Single-Use Promo Codes, Gift Cards, and Referral Links:** Checking `if (!coupon.redeemed_by)` and inserting a redemption row without a `UNIQUE` constraint or atomic `UPDATE ... WHERE redeemed_at IS NULL`.
- **Plan Quota / Seat Limits:** Free-tier accounts limited to `MAX_PROJECTS = 3` running `const count = await countProjects(orgId); if (count < 3) await insertProject(...)`.
- **Invitation & Password-Reset Token Consumption:** Replaying a single-use invite token 10 times in parallel to mint 10 sessions or duplicate membership records.
- **Webhook / Checkout Fulfillments:** Processing concurrent webhook deliveries (`checkout.session.completed`) for the same event ID without an atomic idempotency insert first.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Read-Modify-Write TOCTOU Double-Spend)

```typescript
// VULNERABLE: Classic read-modify-write race condition.
// 20 concurrent requests with `cost = 10` against `balance = 10` will ALL read `balance = 10`,
// ALL pass `row.balance < cost`, and overwrite `balance = 0` while executing the paid action 20 times!
export async function spendCreditsVulnerable(tenantId: string, cost: number) {
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

### Hardened Pattern 1: Single-Statement Atomic Compare-and-Swap (Reserve Before Side-Effect)

Always **reserve/deduct atomically in a single `UPDATE ... WHERE` statement before calling any external API**, and refund via a compensating ledger entry if the upstream call fails:

```typescript
export async function spendCreditsHardened(
  scope: TenantScope,
  cost: number,
  idempotencyKey: string
) {
  if (!Number.isInteger(cost) || cost <= 0) {
    throw new Error("INVALID_COST_MUST_BE_POSITIVE_INTEGER");
  }

  // 1. Atomic reservation + idempotency guard inside a single transaction/CTE:
  //    - Inserts idempotency key (fails or returns nothing on duplicate).
  //    - Atomically decrements `balance = balance - $2` ONLY IF `balance >= $2`.
  //    - In PostgreSQL or SQLite, the row lock on `UPDATE` serializes concurrent callers!
  const reserved = await db.queryOne<{ new_balance: number; reservation_id: string }>(
    `WITH dedup AS (
       INSERT INTO wallet_ledger (id, tenant_id, idempotency_key, delta, status)
       VALUES ($1, $2, $3, -$4, 'reserved')
       ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
       RETURNING id
     )
     UPDATE tenant_wallets w
        SET balance = w.balance - $4,
            updated_at = CURRENT_TIMESTAMP
       FROM dedup
      WHERE w.tenant_id = $2
        AND w.balance >= $4
     RETURNING w.balance AS new_balance, dedup.id AS reservation_id`,
    [crypto.randomUUID(), scope.tenantId, idempotencyKey, cost]
  );

  if (!reserved) {
    throw new Error("INSUFFICIENT_CREDITS_OR_DUPLICATE_REQUEST");
  }

  try {
    const result = await callExpensiveUpstreamApi();
    await db.execute(
      "UPDATE wallet_ledger SET status = 'committed' WHERE id = $1 AND tenant_id = $2",
      [reserved.reservation_id, scope.tenantId]
    );
    return result;
  } catch (err) {
    // 2. Compensating atomic refund if the upstream side-effect failed:
    await db.execute(
      `WITH refund_state AS (
         UPDATE wallet_ledger
            SET status = 'refunded'
          WHERE id = $1 AND tenant_id = $2 AND status = 'reserved'
         RETURNING id
       )
       UPDATE tenant_wallets
          SET balance = balance + $3
         FROM refund_state
        WHERE tenant_id = $2`,
      [reserved.reservation_id, scope.tenantId, cost]
    );
    throw err;
  }
}
```

### Hardened Pattern 2: Enforcing Plan Quotas Atomically (`INSERT ... SELECT ... WHERE COUNT < MAX`)

```sql
-- Atomically insert a new project ONLY IF the tenant currently has fewer than `max_projects` ($4).
-- Also add a CHECK constraint on wallets (`CHECK (balance >= 0)`) as a database-level backstop.
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

---

## 4. How to Discover It Automatically

### A. Static Code Search
Look for any function that performs a `SELECT` on a balance, count, quota, or token table followed by an `UPDATE` or `INSERT` in the same handler:

```bash
# Find non-atomic `SET balance = $` (setting an absolute value computed in app memory instead of `balance - $`):
rg -n -i 'SET\s+(balance|credits|quota|used_count)\s*=\s*\$' src/

# Find coupon/invite redemption checks that separate SELECT and UPDATE:
rg -n -C 8 'redeemed_at|used_at|remaining_uses' src/
```

### B. Dynamic Attacker Test (Barrier-Synchronized Race Burst)
Follow [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md):
1. Seed `Tenant B` with `balance = 10` credits (enough for **exactly 1** action of `cost = 10`), 1 single-use coupon (`SAVE10`), and a plan quota of `max_projects = 2` (with 1 project already created).
2. Open 25 concurrent connections to the local server, hold all 25 at an in-process barrier until sockets are warm, and release all 25 simultaneously against:
   - `POST /api/credits/spend` (`cost: 10`, with 25 distinct idempotency keys, and again with 25 identical idempotency keys).
   - `POST /api/coupons/redeem` (`code: "SAVE10"`).
   - `POST /api/projects` (creating a new project against `max_projects = 2`).
3. **Pass Criteria:**
   - Exactly **1** request returns `200 OK` and **24** requests return `409`/`402`/`422`.
   - Post-burst database state satisfies `wallet.balance === 0` (never negative), `COUNT(redeemed_coupons) === 1`, and `COUNT(projects) === 2`.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Ban Absolute-Value Balance Writes:** Never write `SET balance = $1`. Always write relative atomic deltas (`SET balance = balance - $1 WHERE balance >= $1`) paired with a table constraint `CHECK (balance >= 0)`.
2. **Require Positive Integer Validation on All Monetary/Credit Inputs:** Reject `NaN`, `Infinity`, floats, `0`, and negative numbers at schema parse time (`z.number().int().positive().max(1_000_000)`) so an attacker cannot pass `cost: -500` to turn a debit into a credit (`balance - (-500)`).
3. **Database-Level `UNIQUE` Constraints for Idempotency & Single-Use Tokens:** Enforce `UNIQUE (tenant_id, idempotency_key)` and `UNIQUE (coupon_id, tenant_id)` in schema migrations so even under `READ COMMITTED` isolation, concurrent inserts physically conflict at the index level.
