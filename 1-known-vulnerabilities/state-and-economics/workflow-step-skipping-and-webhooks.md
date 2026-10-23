# Workflow Step Skipping, Webhook Replay & Mass Assignment

## 1. Attack Transcript

Three independent probes against one billing/onboarding surface:

```text
# (a) Step skipping — create an order, never pay, call the last step directly
$ curl -s -X POST https://app.example.com/api/orders -H "Cookie: $B" -d '{"sku":"pro-annual"}'
{"id":"ord_91","status":"draft"}
$ curl -s -X POST https://app.example.com/api/orders/ord_91/provision -H "Cookie: $B"
{"ok":true,"orderId":"ord_91"}                      # provisioned without payment

# (b) Mass assignment — extra keys ride along on a legitimate PATCH
$ curl -s -X PATCH https://app.example.com/api/orgs/org_b -H "Cookie: $B" \
       -d '{"name":"Acme","plan":"enterprise","credits":999999}'
{"id":"org_b","name":"Acme","plan":"enterprise","credits":999999,"stripeCustomerId":"cus_..."}

# (c) Webhook: replay and the wrong event type
$ curl -s -X POST https://app.example.com/api/webhooks/payments \
       -H "x-webhook-timestamp: 1790000000" -H "x-webhook-signature: <captured valid sig>" \
       --data-binary @captured_payment_failed.json
{"received":true}                                   # a payment.failed event marked the order paid
```

All three pass happy-path tests: the UI never offers "Provision" before "Pay", never sends `plan`, and Stripe-style test fixtures only send success events once.

---

## 2. Spot the Bug

```typescript
export async function updateOrg(orgId: string, req: Request) {
  const body = await req.json();
  await db.update(orgsTable).set(body).where(eq(orgsTable.id, orgId));
}

export async function provisionOrder(scope: TenantScope, orderId: string) {
  const order = await db.queryOne(
    "SELECT id, status FROM orders WHERE id = $1 AND tenant_id = $2",
    [orderId, scope.tenantId]
  );
  if (!order) return new Response("Not Found", { status: 404 });
  await db.execute("UPDATE orders SET status = 'provisioned' WHERE id = $1", [orderId]);
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}
```

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

export async function handlePaymentWebhook(req: Request, webhookSecret: string) {
  const sigHeader = req.headers.get("x-webhook-signature");
  const timestampHeader = req.headers.get("x-webhook-timestamp");
  if (!sigHeader || !timestampHeader) {
    return new Response("Missing signature headers", { status: 400 });
  }
  const tsSeconds = Number(timestampHeader);
  if (!Number.isInteger(tsSeconds) || Math.abs(Date.now() / 1000 - tsSeconds) > 300) {
    return new Response("Webhook timestamp outside 300s window", { status: 400 });
  }

  const rawBytes = Buffer.from(await req.arrayBuffer());
  const expectedHex = createHmac("sha256", webhookSecret)
    .update(Buffer.concat([Buffer.from(`${tsSeconds}.`), rawBytes]))
    .digest("hex");
  const a = Buffer.from(sigHeader);
  const b = Buffer.from(expectedHex);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return new Response("Invalid webhook signature", { status: 401 });
  }

  const event = JSON.parse(rawBytes.toString("utf8")) as {
    id: string;
    type: string;
    data: { orderId: string; tenantId: string };
  };

  await db.execute(
    `WITH recorded AS (
       INSERT INTO processed_webhook_events (event_id, event_type, received_at)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING event_id
     )
     UPDATE orders
        SET status = 'paid', paid_at = CURRENT_TIMESTAMP
       FROM recorded
      WHERE orders.id = $3
        AND orders.tenant_id = $4
        AND orders.status = 'pending_payment'`,
    [event.id, event.type, event.data.orderId, event.data.tenantId]
  );
  return new Response(JSON.stringify({ received: true }), { status: 200 });
}
```

<details>
<summary>Reveal</summary>

1. `updateOrg` spreads the request body into the ORM update: `plan`, `credits`, `role`, `stripeCustomerId` are all writable.
2. `provisionOrder` checks ownership but never requires `status = 'paid'`, and updates without a prior-state guard (so it also double-provisions).
3. The webhook handler has four distinct flaws even though the signature check is correct:
   - **`event.type` is never checked** — a signed `payment.failed` (or any other) event with an `orderId` marks the order paid.
   - **The event ID is burned unconditionally** — the data-modifying CTE always inserts into `processed_webhook_events`, even when the `UPDATE` matches nothing (event arrived before the order reached `pending_payment`). The provider's retry is then deduplicated forever and the payment is lost.
   - **Amount and currency are never compared** to the server-side order total.
   - **Tenant and order are taken from the payload** instead of being derived server-side from a provider reference stored at checkout creation.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I3 — State-Machine & Economic Conservation` and `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-2.3.1`, `15.3.1`).
- **Mechanism:** three closely related state-transition flaws let attackers corrupt business logic without touching authentication:
  1. **Multi-Step Workflow Skipping (`v5.0.0-2.3.1`):** the sequence (`Create Order` → `Payment Verification` → `Provision`) is enforced by the frontend, but the Step-3 endpoint only checks tenant ownership, not `order.status = 'paid'`.
  2. **Webhook Forgery, Drift, Replay and Misrouting:** HMAC computed over `JSON.stringify(req.body)` instead of raw bytes; no timestamp tolerance; event IDs recorded before the transition succeeds; unchecked event types; unchecked amounts.
  3. **Mass Assignment & Response Over-Fetching (`v5.0.0-15.3.1`):** `.update(req.body)` lets a user set `role: "owner"`, `plan: "enterprise"`, `is_verified: true`; returning `SELECT *` leaks password hashes, internal flags, billing IDs.

### Where It Hides

- Onboarding, checkout, domain-verification or payout flows split across several `POST`/`PATCH` endpoints where each step updates a column on the same row.
- Generic `PATCH /api/users/:id` / `PATCH /api/orgs/:id` handlers that spread parsed JSON into an update builder, including nested relation writes (`connect`, `create`).
- Webhook handlers that parse JSON middleware first and re-serialize to verify signatures, or return `200` before the side effect is durable.
- Out-of-order delivery: providers do not guarantee ordering, so `payment.succeeded` can arrive before your `checkout.created` handler has committed.

---

## 4. Hardened Pattern

### 4.1 Strict input schema + explicit projection (kills mass assignment and over-fetching)

```typescript
import { z } from "zod";

const UpdateOrgInputSchema = z
  .object({
    name: z.string().trim().min(1).max(80),
    billingEmail: z.string().email().max(254),
  })
  .strict(); // unknown keys such as `plan`, `role`, `credits`, or nested `connect` are rejected

export async function updateOrgHardened(scope: TenantScope, rawBody: unknown) {
  if (scope.role !== "owner") {
    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  }
  const input = UpdateOrgInputSchema.parse(rawBody);

  const row = await db.queryOne<{ id: string; name: string; billing_email: string }>(
    `UPDATE orgs
        SET name = $1, billing_email = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
     RETURNING id, name, billing_email`,
    [input.name, input.billingEmail, scope.tenantId]
  );
  return row
    ? Response.json(row)
    : new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
}
```

### 4.2 Atomic state-machine transition (`paid` → `provisioned` only)

```typescript
export async function provisionOrderHardened(scope: TenantScope, orderId: string) {
  const transitioned = await db.queryOne<{ id: string }>(
    `UPDATE orders
        SET status = 'provisioned', provisioned_at = CURRENT_TIMESTAMP
      WHERE id = $1 AND tenant_id = $2 AND status = 'paid'
     RETURNING id`,
    [orderId, scope.tenantId]
  );

  if (!transitioned) {
    // Not found, wrong tenant, not yet paid, already provisioned: same shape for the caller.
    return new Response(JSON.stringify({ error: "INVALID_STATE_TRANSITION_OR_NOT_FOUND" }), {
      status: 409,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  return Response.json({ ok: true, orderId: transitioned.id });
}
```

### 4.3 Webhook: raw bytes, rotating secrets, type allowlist, server-side lookup, state machine for events

Event rows have a state: `received` → `applied` (or `rejected`). An event is only marked `applied` in the same transaction as the transition it caused. An event that cannot be applied *yet* returns a non-2xx so the provider retries.

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

// Only events we act on. Everything else is acknowledged and ignored (no state change).
const HANDLED_EVENT_TYPES = new Set(["payment.succeeded"]);

function verifySignature(
  rawBytes: Buffer,
  tsSeconds: number,
  header: string,
  secrets: readonly string[] // current + previous secret during rotation
): boolean {
  // Header may carry several signatures: "v1=abc,v1=def" (rotation on the provider side).
  const provided = header
    .split(",")
    .map((p) => p.trim().replace(/^v1=/, ""))
    .filter((p) => /^[0-9a-f]{64}$/.test(p));
  if (provided.length === 0 || provided.length > 4) return false;

  const signedPayload = Buffer.concat([Buffer.from(`${tsSeconds}.`, "utf8"), rawBytes]);
  let ok = false;
  for (const secret of secrets) {
    const expected = createHmac("sha256", secret).update(signedPayload).digest();
    for (const p of provided) {
      const candidate = Buffer.from(p, "hex");
      // Evaluate every comparison; do not short-circuit on the first match.
      if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) ok = true;
    }
  }
  return ok;
}

export async function handlePaymentWebhookHardened(
  req: Request,
  secrets: readonly string[],
  system: SystemScope // audited unscoped handle: a webhook has no end-user actor (see ../../strategy/scoped-db.md)
) {
  const sigHeader = req.headers.get("x-webhook-signature");
  const tsSeconds = Number(req.headers.get("x-webhook-timestamp"));
  if (!sigHeader || !Number.isInteger(tsSeconds)) return new Response("Bad request", { status: 400 });
  if (Math.abs(Math.floor(Date.now() / 1000) - tsSeconds) > 300) {
    return new Response("Webhook timestamp outside 300s window", { status: 400 });
  }

  // RAW bytes, bounded. Never JSON.stringify(await req.json()).
  const rawBytes = await readBoundedBytes(req, 256 * 1024);
  if (!verifySignature(rawBytes, tsSeconds, sigHeader, secrets)) {
    return new Response("Invalid webhook signature", { status: 401 });
  }

  const event = WebhookEventSchema.parse(JSON.parse(rawBytes.toString("utf8")));
  // WebhookEventSchema: { id: string, type: string, data: { checkoutId: string, amountCents: int, currency: string } }

  if (!HANDLED_EVENT_TYPES.has(event.type)) {
    return Response.json({ received: true, ignored: true });
  }

  return system.transaction(async (tx) => {
    // 1. Take the per-event row lock. A concurrent duplicate delivery blocks here until we commit,
    //    then observes state = 'applied'.
    const row = await tx.queryOne<{ state: "received" | "applied" | "rejected" }>(
      `INSERT INTO processed_webhook_events (event_id, event_type, state, attempts, received_at)
       VALUES ($1, $2, 'received', 1, CURRENT_TIMESTAMP)
       ON CONFLICT (event_id) DO UPDATE
         SET attempts = processed_webhook_events.attempts + 1
       RETURNING state`,
      [event.id, event.type]
    );
    if (row && row.state !== "received") {
      return Response.json({ received: true, duplicate: true });
    }

    // 2. Tenant and order are derived SERVER-SIDE from the provider reference stored when the
    //    checkout was created. Amount and currency must equal the server-side order total.
    const paid = await tx.queryOne<{ id: string }>(
      `UPDATE orders
          SET status = 'paid', paid_at = CURRENT_TIMESTAMP
        WHERE provider_checkout_id = $1
          AND status = 'pending_payment'
          AND total_cents = $2
          AND currency = $3
        RETURNING id`,
      [event.data.checkoutId, event.data.amountCents, event.data.currency]
    );

    if (paid) {
      await tx.execute(
        `UPDATE processed_webhook_events SET state = 'applied' WHERE event_id = $1`,
        [event.id]
      );
      return Response.json({ received: true });
    }

    // 3. Not applied. Work out why, because the right response differs.
    const order = await tx.queryOne<{ status: string; total_cents: number; currency: string }>(
      `SELECT status, total_cents, currency FROM orders WHERE provider_checkout_id = $1`,
      [event.data.checkoutId]
    );

    if (order?.status === "paid" || order?.status === "provisioned") {
      // Same payment delivered under a different event id: converge idempotently.
      await tx.execute(`UPDATE processed_webhook_events SET state = 'applied' WHERE event_id = $1`, [event.id]);
      return Response.json({ received: true, duplicate: true });
    }
    if (order && (order.total_cents !== event.data.amountCents || order.currency !== event.data.currency)) {
      await tx.execute(`UPDATE processed_webhook_events SET state = 'rejected' WHERE event_id = $1`, [event.id]);
      await raiseSecurityAlert("webhook_amount_mismatch", { eventId: event.id });
      return Response.json({ received: true, rejected: true }); // stop retries; a human investigates
    }

    // Order unknown or not yet in pending_payment (out-of-order delivery): leave the event in
    // 'received' and answer non-2xx so the provider retries after our own flow has caught up.
    return new Response(JSON.stringify({ error: "ORDER_NOT_READY" }), {
      status: 409,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  });
}
```

Note that the 409 path commits the `attempts` increment but leaves `state = 'received'` — the event is never burned.

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Retry storms and poison events:** an event that can never apply (order deleted) will be retried by the provider until it gives up. Cap `attempts`, move to `rejected` after N, and alert.
- **Timestamp window vs. retries:** providers re-sign on retry (new timestamp) but a *replayed capture* keeps the old timestamp and fails the window; make sure your window is not larger than the provider's retry policy requires.
- **Secret rotation:** during rotation both secrets must verify; remove the old one on a schedule. Never log the signature or the secret.
- **State machine completeness:** `pending_payment → paid` is guarded, but what about `paid → refunded`, `paid → disputed`, `provisioned → canceled`? Every edge needs the same `WHERE status = <prior>` guard and a table of legal edges in code and in a property test (see [`../../2-discovery-and-attacker-methods/stateful-property-and-fuzzing-harnesses.md`](../../2-discovery-and-attacker-methods/stateful-property-and-fuzzing-harnesses.md)).
- **Business-logic economics:** price or quantity coming from the client, refund greater than paid, partial-refund loops, coupon stacking, trial abuse through email aliases (`a+1@`, dots), proration. These are invariants on money; assert `SUM(refunds) <= SUM(payments)` in the ledger.
- **Fulfilment is a side effect too:** provisioning after `paid` must itself be idempotent (the `status = 'paid'` guard) and survive a crash between commit and the side effect (outbox pattern; see [`../authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../authorization-and-tenancy/async-jobs-and-scope-propagation.md)).
- **Mass assignment via nesting:** `.strict()` on the top level does not help if a nested object is `z.any()` or `z.record()`.

---

## 6. How to Discover It Automatically

### A. Static

```yaml
# semgrep
rules:
  - id: orm-update-with-request-body
    languages: [typescript, javascript]
    severity: ERROR
    message: Do not pass a request body object directly to an ORM write; parse with a .strict() schema first
    pattern-either:
      - pattern: $DB.update($T).set($BODY)
      - pattern: $DB.$M.update({ ..., data: $BODY, ... })
      - pattern: $DB.$M.create({ data: $BODY })
      - pattern: Object.assign($ROW, $BODY)
    # Triage matches: a hit is a finding unless $BODY is the output of a .strict() schema parse.
```

```bash
rg -n '\.set\(\s*(body|data|input|req\.body)\s*\)|Object\.assign\(' src/
rg -n -i 'SELECT\s+\*\s+FROM' src/
rg -n -C 12 'webhook' src/
# Webhook handlers that never branch on event type or never compare amounts:
rg -n -L 'event\.type|evt\.type' $(rg -l -i 'webhook' src/)
# Unconditional status writes (no prior-state guard):
rg -n -i "SET\s+status\s*=\s*'[a-z_]+'\s+WHERE\s+id\s*=\s*\\$\d+\s*[\"'\`;)]" src/
```

### B. Dynamic Attacker Test

1. **Step-Skipping:** create each entity in its initial state (`draft`, `pending_verification`), then call every downstream endpoint (`/provision`, `/publish`, `/withdraw`, `/complete`) out of order. Expect `409`/`404`.
2. **Mass-Assignment Probe:** on every `POST`/`PUT`/`PATCH`, inject `"role":"owner"`, `"isAdmin":true`, `"plan":"enterprise"`, `"balance":999999`, `"emailVerified":true`, `"tenantId":"<victim>"`, and nested `{"project":{"connect":{"id":"<victim>"}}}`. Expect `400` or unchanged columns (verified by the DB-diff oracle).
3. **Webhook matrix** (all against the local lab with a known test secret):
   - timestamp `now - 600s` → `400`;
   - valid signature, event type `payment.failed` with a real `orderId` → order unchanged;
   - valid `payment.succeeded` sent *before* the order reaches `pending_payment` → non-2xx, then re-sent after → applied exactly once;
   - same `event.id` twice in parallel (barrier burst) → side effect exactly once;
   - amount off by one cent → `rejected`, order unchanged, alert fired;
   - signature header with two `v1=` values (one stale secret) → accepted only if one verifies.
4. Fold these into the sweep in [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md); the concurrent-duplicate case uses [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Encode transitions in SQL:** never write `UPDATE orders SET status = $1 WHERE id = $2`. Always include the prior state in `WHERE` and check `rowCount === 1`. Keep one table of legal edges and generate the guards from it.
2. **`.strict()` input schemas and explicit `RETURNING` DTOs:** ban unvalidated body spreads and `SELECT *` with lint rules.
3. **Event handlers are state machines:** `received → applied | rejected`; an event is only `applied` in the transaction of the change it caused; unknown types are acknowledged and ignored; a not-yet-applicable event gets a non-2xx.
4. **Server-side references only:** webhook payloads are signals; the order, tenant and expected amount come from rows you wrote at checkout creation.
5. **Webhook secrets live in a list** (current + previous) so rotation never requires downtime.
