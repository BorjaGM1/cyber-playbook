# Workflow Step Skipping, Webhook Replay & Mass Assignment

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` and `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-2.3.1`, `15.3.1`).
- **Mechanism:** Three closely related state-transition flaws allow attackers to corrupt business logic without touching authentication:
  1. **Multi-Step Workflow Skipping (`v5.0.0-2.3.1`):** A multi-screen flow (`Step 1: Create Order` $\to$ `Step 2: Payment Verification` $\to$ `Step 3: Provision Resource`) enforces step sequence in the frontend UI, but the Step 3 backend endpoint (`POST /api/orders/:id/provision`) only checks `order.tenant_id === actor.tenantId` without asserting `order.status === 'paid'`.
  2. **Webhook Forgery, Timestamp Drift & Replay:** Payment or lifecycle webhooks (`/api/webhooks/stripe`, `/api/webhooks/github`) either verify HMAC over `JSON.stringify(req.body)` (instead of raw request bytes), skip timestamp tolerance checks (allowing replay of old captured payloads), or fail to record `event.id` in a unique table before applying state changes.
  3. **Mass Assignment & Response Over-Fetching (`v5.0.0-15.3.1`):** Passing `req.body` directly into an ORM `.update(req.body)` (allowing a user to set `role: "owner"`, `plan: "enterprise"`, or `is_verified: true`) or returning `SELECT * FROM users` directly in JSON responses (leaking password hashes, internal flags, or billing IDs).

---

## 2. Where It Hides

- Onboarding, checkout, domain-verification, or payout flows split across multiple `POST`/`PATCH` endpoints where each step updates a column on the same row.
- Generic `PATCH /api/users/:id` or `PATCH /api/orgs/:id` handlers that spread parsed JSON fields into an SQL/ORM update builder (`db.update(users).set(body)`).
- Webhook handlers that parse JSON middleware first (`await req.json()`) and then re-serialize to verify signatures, or return `200 OK` and process events without deduplicating `event_id`.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Step Skipping + Mass Assignment + Replayable Webhook)

```typescript
// VULNERABLE 1: Mass assignment allows caller to overwrite `plan`, `credits`, or `status`!
export async function updateOrgVulnerable(orgId: string, req: Request) {
  const body = await req.json(); // Attacker sends: { "name": "Acme", "plan": "enterprise", "credits": 999999 }
  await db.update(orgsTable).set(body).where(eq(orgsTable.id, orgId));
}

// VULNERABLE 2: Provision endpoint checks tenant ownership, but forgets to require `status = 'paid'`!
export async function provisionOrderVulnerable(scope: TenantScope, orderId: string) {
  const order = await db.queryOne(
    "SELECT id, status FROM orders WHERE id = $1 AND tenant_id = $2",
    [orderId, scope.tenantId]
  );
  if (!order) return new Response("Not Found", { status: 404 });
  // Missing check: if (order.status !== 'paid')! Attacker jumps straight from 'draft' to 'provisioned'!
  await db.execute("UPDATE orders SET status = 'provisioned' WHERE id = $1", [orderId]);
}
```

### Hardened Pattern (TypeScript — Explicit State-Transition Guard + Raw-Body Webhook Deduplication + Strict Projection)

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

// 1. Strict input schema (eliminates Mass Assignment) + explicit column projection (eliminates Over-Fetching):
const UpdateOrgInputSchema = z
  .object({
    name: z.string().trim().min(1).max(80),
    billingEmail: z.string().email().max(254),
  })
  .strict(); // Rejects unknown keys like `plan`, `role`, `credits`!

export async function updateOrgHardened(scope: TenantScope, rawBody: unknown) {
  if (scope.role !== "owner") {
    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  }
  const input = UpdateOrgInputSchema.parse(rawBody);

  // Explicit column list in both SET and RETURNING (ASVS v5.0.0-15.3.1):
  return db.queryOne<{ id: string; name: string; billing_email: string }>(
    `UPDATE orgs
        SET name = $1,
            billing_email = $2,
            updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
     RETURNING id, name, billing_email`,
    [input.name, input.billingEmail, scope.tenantId]
  );
}

// 2. Atomic State-Machine Transition (`paid` -> `provisioned` ONLY):
export async function provisionOrderHardened(scope: TenantScope, orderId: string) {
  // Atomic CAS transition: only transitions if current status is EXACTLY 'paid'.
  // Prevents both step-skipping ('draft' -> 'provisioned') and double-provisioning ('provisioned' -> 'provisioned').
  const transitioned = await db.queryOne<{ id: string }>(
    `UPDATE orders
        SET status = 'provisioned',
            provisioned_at = CURRENT_TIMESTAMP
      WHERE id = $1
        AND tenant_id = $2
        AND status = 'paid'
     RETURNING id`,
    [orderId, scope.tenantId]
  );

  if (!transitioned) {
    return new Response(JSON.stringify({ error: "INVALID_STATE_TRANSITION_OR_NOT_FOUND" }), {
      status: 409,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  return new Response(JSON.stringify({ ok: true, orderId: transitioned.id }), { status: 200 });
}

// 3. Hardened Webhook Verifier (Raw Bytes + Timestamp Window + Atomic Event ID Deduplication):
export async function handlePaymentWebhookHardened(req: Request, webhookSecret: string) {
  const sigHeader = req.headers.get("x-webhook-signature");
  const timestampHeader = req.headers.get("x-webhook-timestamp");
  if (!sigHeader || !timestampHeader) {
    return new Response("Missing signature headers", { status: 400 });
  }

  // Enforce 5-minute replay tolerance window:
  const tsSeconds = Number(timestampHeader);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(tsSeconds) || Math.abs(nowSeconds - tsSeconds) > 300) {
    return new Response("Webhook timestamp outside 300s window", { status: 400 });
  }

  // Read RAW request bytes (never JSON.stringify(await req.json()))
  const rawBytes = Buffer.from(await req.arrayBuffer());
  const signedPayload = Buffer.concat([Buffer.from(`${tsSeconds}.`, "utf8"), rawBytes]);
  const expectedHex = createHmac("sha256", webhookSecret).update(signedPayload).digest("hex");

  const a = Buffer.from(sigHeader, "utf8");
  const b = Buffer.from(expectedHex, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return new Response("Invalid webhook signature", { status: 401 });
  }

  const event = JSON.parse(rawBytes.toString("utf8")) as {
    id: string;
    type: string;
    data: { orderId: string; tenantId: string };
  };

  // Atomic deduplication + state transition in one statement:
  await db.execute(
    `WITH recorded AS (
       INSERT INTO processed_webhook_events (event_id, event_type, received_at)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING event_id
     )
     UPDATE orders
        SET status = 'paid',
            paid_at = CURRENT_TIMESTAMP
       FROM recorded
      WHERE orders.id = $3
        AND orders.tenant_id = $4
        AND orders.status = 'pending_payment'`,
    [event.id, event.type, event.data.orderId, event.data.tenantId]
  );

  return new Response(JSON.stringify({ received: true }), { status: 200 });
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Find ORM `.set(` or `Object.assign` calls that pass a whole request body object:
rg -n '\.set\(\s*(body|data|input|req\.body)\s*\)|Object\.assign\(' src/

# 2. Find `SELECT *` queries that may over-fetch internal columns into API responses:
rg -n -i 'SELECT\s+\*\s+FROM' src/

# 3. Inspect webhook handlers for raw-body signature verification and event_id deduplication:
rg -n -C 12 'webhook' src/
```

### B. Dynamic Attacker Test (Out-of-Order Transition, Mass Assignment & Webhook Replay)
1. **Step-Skipping Test:** Create an entity in its initial state (`status = 'draft'` or `pending_verification`). Immediately call every downstream endpoint (`/provision`, `/publish`, `/withdraw`, `/complete`) skipping the intermediate verification/payment step. Assert `409 Conflict` / `403`.
2. **Mass-Assignment Probe:** On every `POST`, `PUT`, and `PATCH` endpoint, inject extra privileged keys into the JSON body: `"role": "owner"`, `"isAdmin": true`, `"plan": "enterprise"`, `"balance": 999999`, `"emailVerified": true`, `"tenantId": "<victim_tenant_id>"`. Assert that either the request is rejected (`400` strict schema) or the privileged columns remain unchanged in the database.
3. **Webhook Replay & Stale Timestamp Test:**
   - Send a valid signed webhook with `timestamp = now - 600s` $\to$ Assert `400`.
   - Send a valid signed webhook with `event.id = "evt_test_1"` twice in parallel $\to$ Assert the side effect (e.g., credit top-up or order fulfillment) happens **exactly once**.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Encode Valid State Transitions in SQL `WHERE status = $expected_prior_status`:** Never write `UPDATE orders SET status = $1 WHERE id = $2`. Always require the prior state in the `WHERE` clause and check `rowCount === 1`.
2. **Use `.strict()` on All Input Schemas and Explicit `RETURNING` DTOs:** Ban `SELECT *` and unvalidated body spreads via lint rules.
