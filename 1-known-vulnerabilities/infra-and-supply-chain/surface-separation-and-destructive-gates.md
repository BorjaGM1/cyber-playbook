# Surface Separation (Human UI vs. Machine API) & Destructive Operation Gates

> **Invariant:** `I5 — Minimal Blast Radius & Fail-Closed Boot`.
> Related: [`../auth-and-sessions/api-key-lifecycle-and-privilege-escalation.md`](../auth-and-sessions/api-key-lifecycle-and-privilege-escalation.md) · [`dev-bypasses-and-boot-assertions.md`](dev-bypasses-and-boot-assertions.md) · [`../../baselines/pre-deploy-security-pipeline.md`](../../baselines/pre-deploy-security-pipeline.md) · [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)

---

## 1. Attack Transcript

The dispatcher blocks Bearer keys on human-only routes by checking the `Authorization` header prefix. The authenticator, elsewhere, is more lenient.

```http
POST /api/keys HTTP/1.1
Host: api.example.com
Authorization: bearer sk_live_<leaked key>

HTTP/1.1 201 Created
{"id":"key_9f","secret":"sk_live_c2b1...e07"}
```

```http
POST /api/keys HTTP/1.1
Host: api.example.com
X-API-Key: sk_live_<leaked key>

HTTP/1.1 201 Created
```

Second transcript, destructive migration slipped past a keyword scan:

```sql
-- migrations/0042_cleanup.sql
DROP/**/TABLE audit_events;
DO $$ BEGIN EXECUTE 'DR' || 'OP TABLE sessions'; END $$;
DELETE FROM invoices;
```

The deploy pipeline applies it, because the gate looked for the literal `DROP TABLE` and the env var `ALLOW_DESTRUCTIVE_MIGRATION` had been set by the same agent that wrote the migration.

---

## 2. Spot the Bug

Find three ways a leaked machine key reaches `POST /api/keys`, and three ways a destructive migration passes.

```typescript
export async function dispatchBySurface(
  req: Request,
  deploymentSurface: "human_ui" | "machine_api",
  route: RouteRegistration,
  ctx: ExecutionContext
): Promise<Response> {
  if (deploymentSurface === "machine_api" && route.surface === "human_ui_only") {
    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  }
  if (route.surface === "human_ui_only" && req.headers.get("authorization")?.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "FORBIDDEN_SURFACE" }), { status: 403 });
  }
  return route.handler(req, ctx);
}

const DESTRUCTIVE_SQL_REGEX =
  /\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE\s+TABLE?|DELETE\s+FROM|ALTER\s+TABLE\s+\S+\s+DROP)\b/i;

export function verifyMigrationsBeforeApply(filesOnDisk, appliedRecords, env) {
  const pending = filesOnDisk.slice(appliedRecords.length);
  for (const mig of pending) {
    const match = DESTRUCTIVE_SQL_REGEX.exec(mig.sql);
    if (match && env.ALLOW_DESTRUCTIVE_MIGRATION !== mig.filename) {
      throw new Error(`DESTRUCTIVE_MIGRATION_BLOCKED: ${mig.filename}`);
    }
  }
}
```

---

## 3. Invariant Violated & Mechanism

When one router mounts human administrative endpoints, machine endpoints and maintenance hooks on the same domain and privilege tier, one failure compromises everything:

1. **Collapsed surfaces.** A machine API (`Bearer` keys) that mounts the same routes as the human dashboard (edge Zero-Trust + browser session) lets a leaked key reach `POST /api/keys`, `DELETE /api/workspace`, billing mutations.
2. **Gate/authenticator mismatch.** This is the OpenSSH 10.5 pattern ([`../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md), Pass 2): the gate inspects one representation (header prefix, case-sensitive `Bearer `), the authenticator parses another (`bearer`, `X-API-Key`, a cookie plus a key). Any credential the authenticator accepts but the gate does not recognise slips through. Case: HTTP auth schemes are case-insensitive; credentials arrive in several headers; a request can carry both a session cookie and a key.
3. **Unchecked destructive SQL and schema drift.** A regex over raw text is defeated by comments (`DROP/**/TABLE`), whitespace, procedural blocks (`DO $$ ... EXECUTE ...`), and statements that destroy data without a `DROP` (`ALTER COLUMN ... TYPE`, `UPDATE`/`DELETE` without `WHERE`). Mutating an already-applied migration makes staging and production diverge from what tests verified.
4. **The break-glass lives where the agent lives.** An environment variable the pipeline reads is writable by whatever writes the pipeline. A control the actor being restrained can flip is not a control.

Why happy-path tests pass: they call routes with the intended credential type only, and migrations in tests are the ones the author wrote.

Where it hides: `app.use("/api", apiRouter)` serving browsers and CLIs alike; deploy scripts (`"deploy": "migrate && deploy"`); `/api/admin/impersonate`, `/api/admin/sql`, `/api/internal/recompute` on the public router.

---

## 4. Hardened Pattern

### 4.1 One credential resolver feeds both the gate and the handler

The gate must decide on the **resolved credential tier**, produced by the same function that authenticates. There is no second parser.

```typescript
export type CredentialTier = "anonymous" | "human_session" | "machine_key";

export interface ResolvedCredential {
  readonly tier: CredentialTier;
  readonly actor?: unknown; // HumanActor | MachineActor, produced by the verifier
}

const BEARER = /^bearer\s+(\S+)$/i; // scheme is case-insensitive

export async function resolveCredential(
  req: Request,
  deps: {
    verifyHumanSession(req: Request): Promise<unknown | null>;
    verifyMachineKey(rawKey: string): Promise<unknown | null>;
  }
): Promise<ResolvedCredential | Response> {
  const authz = req.headers.get("authorization");
  const bearerMatch = authz ? BEARER.exec(authz.trim()) : null;
  const apiKeyHeader = req.headers.get("x-api-key");
  const hasCookie = (req.headers.get("cookie") ?? "").length > 0;

  const machineCandidates = [bearerMatch?.[1], apiKeyHeader?.trim()].filter(
    (v): v is string => typeof v === "string" && v.length > 0
  );
  if (authz && !bearerMatch) return badRequest("UNSUPPORTED_AUTH_SCHEME");

  // Ambiguity is rejected, never resolved by precedence.
  if (machineCandidates.length > 1 || (machineCandidates.length === 1 && hasCookie && (await deps.verifyHumanSession(req)))) {
    return badRequest("AMBIGUOUS_CREDENTIALS");
  }

  if (machineCandidates.length === 1) {
    const actor = await deps.verifyMachineKey(machineCandidates[0]);
    return actor ? { tier: "machine_key", actor } : unauthorized();
  }
  const human = await deps.verifyHumanSession(req);
  return human ? { tier: "human_session", actor: human } : { tier: "anonymous" };
}

function badRequest(code: string) {
  return new Response(JSON.stringify({ error: code }), { status: 400, headers: { "content-type": "application/json; charset=utf-8" } });
}
function unauthorized() {
  return new Response(JSON.stringify({ error: "UNAUTHORIZED" }), { status: 401, headers: { "content-type": "application/json; charset=utf-8" } });
}
```

```typescript
export type SurfaceKind = "human_ui_only" | "machine_api_allowed";

export interface RouteRegistration {
  readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly path: string;
  readonly surface: SurfaceKind; // required: forces an explicit decision per route
  readonly handler: (req: Request, ctx: ExecutionContext, cred: ResolvedCredential) => Promise<Response>;
}

export async function dispatchBySurface(
  req: Request,
  deploymentSurface: "human_ui" | "machine_api",
  route: RouteRegistration,
  ctx: ExecutionContext,
  deps: Parameters<typeof resolveCredential>[1]
): Promise<Response> {
  // On the machine deployment, human-only routes do not exist.
  if (deploymentSurface === "machine_api" && route.surface === "human_ui_only") {
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  const cred = await resolveCredential(req, deps);
  if (cred instanceof Response) return cred;

  if (route.surface === "human_ui_only" && cred.tier !== "human_session") {
    // Same body as a missing route so the surface is not enumerable by a key holder.
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  return route.handler(req, ctx, cred);
}
```

### 4.2 Append-only, checksummed, normalized migration gate

```typescript
import crypto from "node:crypto";

export interface MigrationFile { readonly filename: string; readonly sql: string }
export interface AppliedMigration { readonly filename: string; readonly sha256: string }

// Strip SQL comments (including inline block comments used to split keywords) and collapse whitespace.
// Over-flags by design.
export function normalizeSql(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toUpperCase();
}

const ALWAYS_REVIEW: ReadonlyArray<[string, RegExp]> = [
  ["DROP TABLE/COLUMN/SCHEMA/POLICY/CONSTRAINT/INDEX", /\bDROP (TABLE|COLUMN|SCHEMA|POLICY|CONSTRAINT|INDEX|TRIGGER|VIEW|DATABASE)\b/],
  ["TRUNCATE", /\bTRUNCATE\b/],
  ["ALTER COLUMN TYPE / SET DATA TYPE", /\bALTER COLUMN\b[^;]*\b(TYPE|SET DATA TYPE)\b/],
  ["ALTER TABLE ... DROP", /\bALTER TABLE\b[^;]*\bDROP\b/],
  ["RENAME", /\bRENAME (TO|COLUMN)\b/],
  ["procedural/dynamic SQL", /\bDO\b\s*(\$|')|\bEXECUTE\b/],
  ["DISABLE ROW SECURITY / TRIGGER", /\bDISABLE (ROW LEVEL SECURITY|TRIGGER)\b/],
];

/** Statement-level check: UPDATE/DELETE without a WHERE clause. */
function unboundedDml(normalized: string): string[] {
  return normalized
    .split(";")
    .map((s) => s.trim())
    .filter((s) => /^(UPDATE|DELETE FROM)\b/.test(s) && !/\bWHERE\b/.test(s));
}

export function classifyMigration(sql: string): string[] {
  const n = normalizeSql(sql);
  const hits = ALWAYS_REVIEW.filter(([, re]) => re.test(n)).map(([label]) => label);
  if (unboundedDml(n).length > 0) hits.push("UPDATE/DELETE without WHERE");
  // Plain data deletes with a WHERE still need review when they target tables, so flag DELETE FROM generally.
  if (/\bDELETE FROM\b/.test(n) && !hits.includes("UPDATE/DELETE without WHERE")) hits.push("DELETE FROM");
  return hits;
}

/**
 * Break-glass is a human-signed approval ARTIFACT bound to the migration's exact bytes,
 * NOT an environment variable. Verification keys come from a location the pipeline's
 * agent cannot write (protected branch + required human review, or CI-managed secret store).
 */
export interface MigrationApproval {
  readonly filename: string;
  readonly sha256: string;      // of the migration file contents
  readonly approver: string;    // key id in the trusted approver set
  readonly expiresAt: string;   // ISO-8601, short-lived
  readonly signatureB64: string;
}

function approvalMessage(a: Omit<MigrationApproval, "signatureB64">): Buffer {
  return Buffer.from(`migration-approval:v1\n${a.filename}\n${a.sha256}\n${a.approver}\n${a.expiresAt}`, "utf8");
}

export function isValidApproval(
  mig: MigrationFile,
  approval: MigrationApproval | undefined,
  trustedApprovers: ReadonlyMap<string, crypto.KeyObject>, // Ed25519 public keys
  now: Date = new Date()
): boolean {
  if (!approval) return false;
  const digest = crypto.createHash("sha256").update(mig.sql, "utf8").digest("hex");
  if (approval.filename !== mig.filename || approval.sha256 !== digest) return false;
  const key = trustedApprovers.get(approval.approver);
  if (!key) return false;
  const exp = Date.parse(approval.expiresAt);
  if (!Number.isFinite(exp) || exp <= now.getTime() || exp - now.getTime() > 7 * 86_400_000) return false;
  return crypto.verify(null, approvalMessage(approval), key, Buffer.from(approval.signatureB64, "base64"));
}

export function verifyMigrationsBeforeApply(
  filesOnDisk: ReadonlyArray<MigrationFile>,
  appliedRecords: ReadonlyArray<AppliedMigration>,
  approvals: ReadonlyMap<string, MigrationApproval>,
  trustedApprovers: ReadonlyMap<string, crypto.KeyObject>
): void {
  // 1. Applied history is an immutable prefix of the on-disk list: no edits, reorders, or inserts before the tail.
  for (let i = 0; i < appliedRecords.length; i++) {
    const applied = appliedRecords[i];
    const onDisk = filesOnDisk[i];
    if (!onDisk || onDisk.filename !== applied.filename) {
      throw new Error(`MIGRATION_HISTORY_TAMPERED: expected ${applied.filename} at index ${i}, found ${onDisk?.filename ?? "NONE"}`);
    }
    const diskHash = crypto.createHash("sha256").update(onDisk.sql, "utf8").digest("hex");
    if (diskHash !== applied.sha256) {
      throw new Error(`MIGRATION_CHECKSUM_MISMATCH: ${applied.filename} was modified after deployment`);
    }
  }
  // 2. Pending migrations: classify; anything flagged needs a valid signed approval for these exact bytes.
  for (const mig of filesOnDisk.slice(appliedRecords.length)) {
    const reasons = classifyMigration(mig.sql);
    if (reasons.length > 0 && !isValidApproval(mig, approvals.get(mig.filename), trustedApprovers)) {
      throw new Error(`DESTRUCTIVE_MIGRATION_BLOCKED: ${mig.filename} (${reasons.join("; ")}) requires a valid signed human approval`);
    }
  }
}
```

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **Regexes are a tripwire, not a parser.** Nested comments, dollar-quoted strings containing `;`, and `EXECUTE` of constructed strings can still evade statement splitting; that is why procedural SQL (`DO`, `EXECUTE`) is *always* flagged. Prefer parsing with a real SQL parser (e.g. `pg_query`) in CI and diffing the resulting statement list.
- **Approvals expire and bind to bytes,** but a human can sign carelessly. Show the approver the classified reasons and the normalized statements, not just the filename.
- **Where the trusted keys live matters more than the signature scheme.** If the pipeline's agent can edit the file that lists trusted approvers, the gate is theatre. Keep it in a protected-branch, CODEOWNERS-reviewed path or the CI secret store.
- **Online-safe migrations still lock.** `CREATE INDEX` without `CONCURRENTLY`, `ALTER TABLE ... ADD COLUMN ... DEFAULT` on old engines, and long backfills are availability hazards the destructive gate does not classify.
- **The surface split protects routes, not data.** A machine deployment that shares the database with the human deployment still shares the blast radius of a SQL bug; give it a role without `DDL` and without access to tables it never needs.
- **Both-credentials requests** are rejected as ambiguous; legitimate browser-based tools that send a cookie *and* a key will fail, which is the intended trade.

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. List all route registrations and the auth middleware / surface they use:
rg -n '\.(get|post|put|patch|delete)\s*\(' src/

# 2. Destructive operations in migrations:
rg -n -i '\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE|DELETE\s+FROM|ALTER\s+COLUMN)\b' migrations/

# 3. Any second place that parses credentials (should be exactly one):
rg -n -i 'x-api-key|authorization|bearer' src/ | rg -v 'resolveCredential'
```

```yaml
rules:
  - id: route-without-surface
    languages: [typescript]
    severity: ERROR
    message: Every route registration must declare surface.
    patterns:
      - pattern: registerRoute({ ... })
      - pattern-not: registerRoute({ ..., surface: $S, ... })
```

### B. Dynamic
1. **Machine surface enumeration:** with a machine key, in every header form (`Authorization: Bearer`, `bearer`, `BEARER`, `X-API-Key`, plus key-and-cookie together, plus `?api_key=`), call each admin route (`POST /api/keys`, `DELETE /api/keys/:id`, `DELETE /api/orgs/:id`, `POST /api/billing/portal`). Assert `404/403/400/401`, never `2xx`.
2. **Migration tamper tests:** mutate one character of an applied migration, expect `MIGRATION_CHECKSUM_MISMATCH`; insert a new file that sorts before the last applied one, expect `MIGRATION_HISTORY_TAMPERED`.
3. **Evasion corpus:** feed `DROP/**/TABLE`, `drop\ttable`, `DO $$ BEGIN EXECUTE 'DR'||'OP TABLE x'; END $$`, `ALTER TABLE t ALTER COLUMN c TYPE int`, `UPDATE t SET x=1`, `DELETE FROM t`. All must classify as flagged and fail without an approval.
4. **Approval forgery:** an approval for another file's hash, an expired approval, an approval signed by an untrusted key, and an env var `ALLOW_DESTRUCTIVE_MIGRATION=...`: all rejected.

These two checks are part of the no-LLM sweep: [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Mandatory `surface` on every route registration** so every new route forces a decision.
2. **One credential parser.** Gate and handler consume the same `ResolvedCredential`; nothing else reads `Authorization`/`X-API-Key`.
3. **Physical separation where possible:** the machine deployment does not link the human-only modules at all.
4. **Run `verifyMigrationsBeforeApply` in CI on every PR** (fail if an applied migration differs from `main`), and again at deploy time against the real applied-history table.
5. **Break-glass is a signed artifact, not a variable,** bound to the migration's bytes and expiring in days.
