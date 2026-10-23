# Async Jobs, Queues & Scope Propagation (Confused-Deputy Workers)

## 1. Attack Transcript

Tenant B's owner asks the product to export a project. They pass Tenant A's project UUID. The HTTP handler only checks that the caller is *authenticated*, enqueues `{ projectId }`, and returns `202`. The worker, which has a service database handle, does the rest.

```bash
$ curl -s -X POST -H "Cookie: __Host-session=$B" -H 'content-type: application/json' \
    -d '{"projectId":"a3d9b1c2-0000-4000-8000-00000000b002","format":"csv"}' \
    https://app.example.com/api/exports
{"jobId":"e41f…","status":"queued"}                                   # 202, no authorization failure anywhere

$ sleep 5; curl -s -H "Cookie: __Host-session=$B" https://app.example.com/api/exports/e41f…/download
id,title,description
7f1c…,"Quarterly acquisition target flag{CANARY_TENANT_A}",…          # Tenant A's data, delivered to B
```

Variant (revoke-vs-run race): `Guest G` is removed at `t0`; an export enqueued at `t0 - 1s` runs at `t0 + 30s` using the *old* envelope, and writes the project's private files to a bucket G can download.

## 2. Spot the Bug

```typescript
// src/app/api/exports/route.ts
export async function POST(req: Request) {
  const session = await verifySession(req);
  const { projectId, format } = await req.json();
  const jobId = crypto.randomUUID();
  await queue.send({ jobId, userId: session.sub, projectId, format });
  return Response.json({ jobId, status: "queued" }, { status: 202 });
}

// src/jobs/export-worker.ts
export async function handleExport(msg: { jobId: string; userId: string; projectId: string; format: string }) {
  const rows = await serviceDb.query("SELECT * FROM issues WHERE project_id = $1", [msg.projectId]);
  const url = await putBlob(`exports/${msg.jobId}.${msg.format}`, toCsv(rows));
  await serviceDb.execute("UPDATE export_jobs SET status = 'done', url = $2 WHERE id = $1", [msg.jobId, url]);
}

// src/jobs/nightly.ts (cron)
export async function nightly(env: Env) {
  for (const t of await serviceDb.query("SELECT id FROM tenants")) {
    await recomputeStats(serviceDb, t.id);
  }
}
```

<details>
<summary>Reveal the bugs</summary>

1. The enqueue route performs **authentication but not authorization** of `projectId`.
2. The worker runs with an unscoped service handle, so the *worker* becomes the confused deputy: it has more authority than the requester and applies none of the requester's limits.
3. The message carries `userId`, not a verifiable scope; nothing can be re-checked at execution time (membership may have been revoked meanwhile).
4. The output location is keyed by `jobId` only and `serviceDb.execute("UPDATE export_jobs … WHERE id = $1")` has no tenant binding.
5. `nightly` iterates all tenants with a raw service handle; one mistake in `recomputeStats` is cross-tenant by default.

</details>

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (and `I5` for the service handle's blast radius). OWASP ASVS `v5.0.0-8.2.2`, `8.3.1`, `7.4.2`.
- **Mechanism:** A `TenantScope` is an in-memory capability bound to one request. When work crosses a process boundary (queue, cron, workflow engine, Durable Object, `waitUntil`, webhook retry, outbox table), the capability does not travel; only IDs do. The worker then (a) uses a broader credential than the requester, or (b) rebuilds authority from a client-controlled field in the payload. Either way the check that existed on the front door is absent on the back door.
- **Why happy-path tests pass:** tests enqueue a job as the owner of the same project and assert the output. Authorization failures would only appear if the test enqueued a foreign ID, revoked the user between enqueue and execution, or replayed a captured message.

### Where It Hides

- Export, import, report, email-digest, AI-summary, thumbnail and webhook-delivery workers.
- Cron/scheduled handlers (`scheduled`, `node-cron`, Kubernetes CronJobs) that loop over all tenants with a service handle.
- Workflow engines (durable steps) and sagas: step N runs hours after the authorization at step 1.
- **Durable Objects / actors:** a stub obtained from a *client-supplied* ID (`env.ROOM.idFromName(req.query.room)`) is an IDOR; `alarm()` and `webSocketMessage()` run with no request context.
- `waitUntil(...)` / fire-and-forget closures that capture a module-global instead of the request's scope (see [`cache-and-derived-data.md`](cache-and-derived-data.md)).
- Inbound webhook receivers that enqueue events and resolve the tenant from a payload field instead of the verified endpoint's stored mapping.
- Dead-letter queues, retries and outbox tables that retain sensitive payloads and are replayed by operators with broader credentials.

## 4. Hardened Pattern

Rule: **a job runs with the requester's scope, rebuilt and re-validated at execution time, or with an explicit, audited `SystemScope`. Never with an ambient service handle.** The scope travels as a signed, purpose-bound, short-lived envelope.

### 4.1 Signed scope envelope (enqueue side)

```typescript
// src/auth/job-envelope.ts   (lint: importable only from src/auth/** and src/jobs/runner.ts)
import { createHmac, timingSafeEqual } from "node:crypto";

export interface JobEnvelope {
  readonly v: 1;
  readonly jobType: string;            // binds the envelope to ONE job kind
  readonly jobId: string;              // single-use, unique
  readonly tenantId: string;
  readonly actorId: string;
  readonly kind: "member" | "guest";
  readonly projectGrants: readonly string[];   // snapshot for diagnostics; authority is re-derived live (4.2)
  readonly payloadSha256: string;      // binds the payload so it cannot be swapped
  readonly iat: number;
  readonly exp: number;                // short: queue delay budget (e.g. 15 min), not hours
}

const PURPOSE = "job_scope:v1";

export function mintJobEnvelope(scope: TenantScope, jobType: string, payloadJson: string, ttlSec = 900): string {
  const now = Math.floor(Date.now() / 1000);
  const env: JobEnvelope = {
    v: 1, jobType, jobId: crypto.randomUUID(),
    tenantId: scope.tenantId, actorId: scope.actorId,
    kind: scope.kind,
    projectGrants: scope.kind === "guest" ? [...scope.allowedProjectIds].sort() : [],
    payloadSha256: sha256Hex(payloadJson),
    iat: now, exp: now + ttlSec,
  };
  const body = Buffer.from(JSON.stringify(env)).toString("base64url");
  const mac = createHmac("sha256", process.env.JOB_ENVELOPE_SECRET!).update(`${PURPOSE}.${body}`).digest("base64url");
  return `${body}.${mac}`;
}
```

The queue client exposes **only** `enqueue(scope, jobType, payload)` which calls `mintJobEnvelope`; there is no `queue.send(rawMessage)` in request code. Use a different secret from session cookies and keep the purpose prefix (see [`../auth-and-sessions/cookie-purpose-confusion-and-oidc.md`](../auth-and-sessions/cookie-purpose-confusion-and-oidc.md)).

### 4.2 Worker side: verify, then rebuild scope from live data

```typescript
// src/jobs/runner.ts
export function defineJob<S extends z.ZodTypeAny>(def: {
  type: string;
  schema: S;                                                    // .strict(), no tenant ids in payload
  run: (db: ScopedDb, payload: z.infer<S>, ctx: { jobId: string }) => Promise<void>;
}) { registry.set(def.type, def); }

export async function dispatch(msg: { envelope: string; payload: string }) {
  const env = verifyJobEnvelope(msg.envelope);                  // MAC, purpose, exp, v
  if (!env) throw new PoisonMessage("bad_envelope");            // dead-letter without echoing payload
  if (env.payloadSha256 !== sha256Hex(msg.payload)) throw new PoisonMessage("payload_swapped");

  const def = registry.get(env.jobType);
  if (!def) throw new PoisonMessage("unknown_job_type");        // envelope for type X cannot run handler Y

  // Single use (replay protection): unique insert; duplicate delivery or replay -> no-op.
  const first = await jobLedger.tryInsert({ jobId: env.jobId, tenantId: env.tenantId });
  if (!first) return;

  // Authority is RE-DERIVED from the database now. The envelope proves who asked and for which tenant;
  // it does not prove they are still allowed.
  const live = await loadLiveMembership(env.actorId, env.tenantId);   // revoked_at IS NULL, user not disabled
  if (!live) { await jobLedger.markDenied(env.jobId, "membership_revoked"); return; }
  const scope = scopeForJob(live, env);                               // guest: grants INTERSECTED with the envelope snapshot
  const db = ScopedDb.forScope(scope);

  const payload = def.schema.parse(JSON.parse(msg.payload));          // ids inside payload are still untrusted
  await def.run(db, payload, { jobId: env.jobId });                   // every query goes through ScopedDb
}
```

`scopeForJob` mints through the same single mint site as HTTP requests (`src/auth`), and for guests uses `liveGrants ∩ envelope.projectGrants` so a later *grant* cannot widen an already-queued job and a later *revoke* narrows it.

### 4.3 The job body

```typescript
defineJob({
  type: "project_export",
  schema: z.object({ projectId: z.string().uuid(), format: z.enum(["csv", "json"]) }).strict(),
  run: async (db, { projectId, format }, { jobId }) => {
    const project = await db.select("projects").where("projects.id", "=", projectId).executeTakeFirst();
    if (!project) { await recordJobResult(db, jobId, "not_found"); return; }      // foreign ID => same outcome as missing
    const issues = await db.select("issues").where("issues.project_id", "=", projectId).execute();
    const key = `tenants/${db.scope.tenantId}/exports/${jobId}.${format}`;       // tenant-prefixed, UUID-only key
    await putBlob(key, serialize(issues, format));
    await recordJobResult(db, jobId, "done", key);
  },
});
```

Download of the result re-authorizes the *downloader* through `ScopedDb` (the job result row is a tenant table owned by the requester), not by possession of the URL.

### 4.4 Cron, system work, tenants

```typescript
// Cross-tenant maintenance is explicit, allowlisted and audited (see scoped-db.md, SystemScope).
await withSystemScope("retention-sweeper", "Nightly purge of soft-deleted rows older than retention window", async (sys) => {
  for (const tenantId of await sys.listTenantIds()) {
    const db = await sys.forTenant(tenantId, "retention purge");    // per-tenant ScopedDb; audited per access
    await purgeExpired(db);
  }
});
```

### 4.5 Durable Objects / actors

- Derive the object ID from the **verified scope** (`env.TENANT_DO.idFromName(scope.tenantId)`), never from a request parameter.
- The Worker → DO call carries the signed envelope; the DO verifies it, because anything that can reach the DO's `fetch` can call it.
- `alarm()` and queue consumers have no request: persist `tenantId` (and the job's envelope hash) in DO storage at creation and rebuild a scope from live data when the alarm fires.
- A DO keyed by tenant still shares memory across that tenant's users: do not store per-user data in module/class fields without a user key.

## 5. Residual Edge Cases

- **Expiry vs. long jobs.** `exp` bounds *start* latency. Long workflows must re-validate live membership at each durable step (re-run `loadLiveMembership`) rather than extend the envelope.
- **Retries and replays.** The ledger insert makes redelivery idempotent; a retry after partial side effects must be written as an idempotent upsert keyed by `(tenantId, jobId, step)`.
- **Scheduled recurring jobs owned by a user** (weekly digest) must be tied to the membership row: revoking the user deletes or pauses the schedule in the same transaction.
- **Result artifacts** (files, emails, webhook calls) are outputs to new audiences. Email to arbitrary addresses is an egress channel; webhook URLs go through the SSRF-safe fetcher ([`../injection-and-trust-boundaries/ssrf-file-uploads-and-path-traversal.md`](../injection-and-trust-boundaries/ssrf-file-uploads-and-path-traversal.md)).
- **Dead-letter queues and logs** contain payloads and envelopes; restrict access, redact, and set short retention.
- **Envelope secret rotation.** Support `kid` with two active secrets, and keep `exp` short enough that rotation does not strand healthy jobs.
- **Agent/MCP-triggered jobs** must carry the *human requester's* scope, not the agent's ambient service identity ([`../injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../injection-and-trust-boundaries/agentic-and-mcp-threats.md)).
- **Cost.** Per-tenant concurrency and spend caps apply to jobs too ([`../state-and-economics/public-compute-and-denial-of-wallet.md`](../state-and-economics/public-compute-and-denial-of-wallet.md)).

## 6. How to Discover It Automatically

### A. Static
```bash
# Workers/handlers that import a raw or service database handle
rg -n 'serviceDb|globalDb|rawDb|from ".*/db/raw"' src/jobs src/workers src/cron

# Direct queue sends outside the scoped client
rg -n '\bqueue\.send\(|\.sendBatch\(|env\.[A-Z_]+_QUEUE\.send' src/ | rg -v 'src/auth/'

# Stubs obtained from request-controlled names
rg -n 'idFromName\(\s*(req|request|params|url|searchParams|body)' src/
```

```yaml
# rules/job-handler-without-scopeddb.yml (Semgrep)
rules:
  - id: job-run-must-take-scopeddb
    languages: [typescript]
    severity: ERROR
    message: Jobs must be declared with defineJob so run() receives a ScopedDb.
    patterns:
      - pattern: export async function $HANDLER($MSG, ...) { ... }
      - metavariable-regex: { metavariable: $HANDLER, regex: "^handle[A-Z].*" }
    paths: { include: ["src/jobs/**", "src/workers/**"] }
```

### B. Dynamic (run inside the lab; workers must be started under the same query-log hook as the API)
1. **Foreign-ID enqueue.** As Tenant B, enqueue every job type with Tenant A's identifiers in every ID field (path, body, nested). Assert the job result is indistinguishable from a missing ID and that no canary is in any artifact, email-mock capture or webhook-mock capture.
2. **Revoke between enqueue and run.** Pause the worker, enqueue as `Guest G` or a member, revoke them, resume. Assert the job is denied and no artifact is produced.
3. **Envelope tampering matrix.** Flip a MAC byte; swap `tenantId`; swap `jobType`; replay a captured message twice; change the payload after signing; use an expired envelope. Each must be rejected without side effects.
4. **Cross-job-type use.** Take a valid envelope for job X and submit it with job Y's payload.
5. **Cron isolation.** Run the scheduled handlers with two tenants seeded; assert each statement is tenant-bound (query-log oracle) and the `system_scope_audit` rows exist.
6. **DO/actor probes.** Request stubs by guessed/foreign names; assert `404`.
7. Run the **query-log tenant-predicate oracle** on worker traffic ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md#7-the-deterministic-sql-query-log-tenant-predicate-oracle), [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)). Cross-surface parity for job outputs is part of [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md).

## 7. How to Eliminate the Bug Class by Construction

1. **No ambient service handle in job code.** `defineJob` is the only way to register a handler; its `run` signature takes a `ScopedDb`, so a job that wants raw access must be declared with `defineSystemJob` (allowlisted caller, reason, audit row).
2. **One enqueue API** that requires a `TenantScope` and mints the envelope; ban raw `queue.send` outside `src/auth/` by lint.
3. **Re-derive authority live at execution time**; treat the envelope as identity and intent, not as a standing grant.
4. **Tenant-prefixed, UUID-only output keys** and result rows in tenant tables, with downloads authorized through `ScopedDb`.
5. **Import boundary:** `SystemScope` and the raw handle are importable from `src/jobs/system/**` only ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
