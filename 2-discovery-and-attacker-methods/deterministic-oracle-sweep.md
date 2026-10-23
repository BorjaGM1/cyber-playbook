# Step 1.5: No-LLM Deterministic Oracle Sweep (Run Before Any LLM Hunting)

## 1. Mental Model (Spend Tokens Only on What Code Cannot Decide)

Most of the "boring" 80% of authorization, tenancy, token and state-machine bugs are decidable by a script that needs zero judgment: send a fixed set of mutated requests as fixed actors and compare observed behavior to the authorization matrix. An LLM re-deriving that by reading handlers is slower, costlier, and less reliable. The sweep therefore runs **first, over 100% of the mapped surface, for near-zero tokens**, and produces two outputs:

1. **Findings** — deterministic PoVs (canary hit, DB-diff, tenant-predicate violation, conservation breach) that go straight to the patch pipeline ([`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md)).
2. **The Residual List** — `(route, invariant)` pairs the sweep *cannot* decide (business-logic intent, multi-step chains, oracle-less classes, routes where an oracle was blind per the guard-mutation self-test). Only the residual is handed to LLM micro-agents ([`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md)). This is what resolves the tension between "check 100% of entry points" and "agents have a finite budget".

**Inputs (all required — the sweep refuses to run without them):**

| Input | Produced by | Why it is a gate |
|-------|-------------|------------------|
| `SECURITY_SURFACE_MAP.json` | [`surface-and-sink-mapping.md`](surface-and-sink-mapping.md) | The universe of routes, actors, tables, sinks |
| `authz-matrix.yaml` | Human-confirmed (ASVS `v5.0.0-8.1.1`) | Expected status per `(actor, route)` |
| `intended-exposures.yaml` | Human-confirmed | Allowlist of by-design cross-actor visibility (public share links, org directory); prevents false positives |
| Running lab | [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md) | Seeded actors, canaries, per-run DB clone |

---

## 2. The Nine Oracles

| # | Oracle | Invariant | Decides |
|---|--------|-----------|---------|
| **O1** | Token / header mutation matrix | `I1` | Forged, mismatched, expired, wrong-purpose credentials never authenticate |
| **O2** | ID-substitution matrix + indistinguishability | `I2` | Cross-tenant / guest / revoked callers get responses identical to a random UUID |
| **O3** | Side-door parity (`ReferencedIDs ⊆ PrimaryIDs`) | `I2` | Search, history, export, aggregates, MCP never show more than primary CRUD |
| **O4** | Mass-assignment and step-skip probes | `I3` | Privileged body keys ignored/rejected; downstream endpoints enforce prior state |
| **O5** | Same-engine race bursts | `I3` | Conservation under concurrency ([`concurrency-and-race-attack-harnesses.md`](concurrency-and-race-attack-harnesses.md)) |
| **O6** | **SQL query-log tenant-predicate oracle** | `I2` | Every statement run while serving Tenant B on a tenant table binds Tenant B's id |
| **O7** | Schema-introspection `ScopedDb` test | `I2` | No tenant table is reachable outside [`ScopedDb`](../strategy/scoped-db.md) |
| **O8** | SSRF battery | `I4` | Every URL-accepting parameter blocks loopback, metadata, RFC1918, redirects, rebinding |
| **O9** | **Guard-mutation self-test** | all | The oracles above actually fail when a guard is removed (oracle power) |

### O1 — Token / Header Mutation Matrix (`I1`)

For every route whose `authz-matrix.yaml` row requires authentication, replay one known-good request with each mutation. **All must return `401`** (never `200`, never a data-bearing `4xx`):

| Case | Mutation |
|------|----------|
| `M1` | No credential |
| `M2` | Plain identity header only (`Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, `X-User-Id`) with victim email |
| `M3` | `alg: none` JWT, empty signature |
| `M4` | Wrong `aud` (validly signed) |
| `M5` | Wrong `iss` (validly signed) |
| `M6` | `exp` in the past (−120 s) |
| `M7` | `nbf` in the future (+3600 s) |
| `M8` | Flip the final signature byte |
| `M9` | HS256 token signed with the RS256 public key (key confusion) |
| `M10` | Signed purpose token for another purpose (`pending_mfa` replayed as `session`), and every `Set-Cookie` from every login-start flow replayed as the session cookie |
| `M11` | Revoked key / session / removed member |
| `M12` | `Authorization: bearer …` (lowercase), `Bearer` in `X-API-Key`, and the same credential in a query string, against `human_ui_only` routes ([`../1-known-vulnerabilities/infra-and-supply-chain/surface-separation-and-destructive-gates.md`](../1-known-vulnerabilities/infra-and-supply-chain/surface-separation-and-destructive-gates.md)) |

### O2 — ID-Substitution Matrix with Indistinguishability (`I2`)

For every route containing an ID in path, query, or body (including foreign-key body fields such as `projectId`, `parentId`, `attachmentId`), and for every unauthorized actor class (`Stranger B`, `Guest G` on a forbidden project, `Revoked R`), send the request twice — once with the private ID, once with a freshly generated random UUID — and compare **four** dimensions, not only status:

1. **Status code.**
2. **Headers** (allowlisted: `content-type`, `cache-control`, `www-authenticate`, `vary`, `set-cookie` *names*, security headers).
3. **Body:** structural shape fingerprint, plus normalized text equality after replacing the requested ID with a placeholder.
4. **Timing:** interleaved samples; a median ratio above `1.5×` *and* an absolute gap above `5 ms` is reported as an advisory (`TIMING_SUSPECT`) and goes to the residual list rather than failing the build (timing is noisy; it needs a human or a micro-agent).

The reference implementation is `compareUnauthorized()` in [`differential-and-side-door-oracles.md`](differential-and-side-door-oracles.md).
For mutating routes the oracle also re-reads Tenant A's state (O-integrity, [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md)) after the request; any DB diff is `CRITICAL`.

### O3 — Side-Door Parity (`I2`)

Implemented in [`differential-and-side-door-oracles.md`](differential-and-side-door-oracles.md) as a real set computation: for each actor and entity kind, `(ReferencedIDs(S) ∩ SeededUniverse) \ PrimaryIDs \ IntendedExposures` must be empty for every secondary surface `S`. Counts and aggregates are checked by the count-canary scan.

### O4 — Mass-Assignment and Step-Skip Probes (`I3`)

- **Mass assignment:** on every `POST`/`PUT`/`PATCH`, inject `role`, `isAdmin`, `plan`, `balance`, `emailVerified`, `tenantId`, `ownerId`, `status`, `deletedAt`, `createdBy`, `__proto__`, nested `{ "connect": … }` relation operators. Pass: `400`, or a DB diff proving the privileged columns are unchanged.
- **Step skipping:** from the surface map's state-machine hints (`status`/`state` columns), create an entity in its initial state and call every downstream mutating route (`/provision`, `/publish`, `/complete`, `/withdraw`). Pass: `409`/`404`, and the status column unchanged.

### O5 — Same-Engine Race Bursts (`I3`)

Run the barrier harness against the seven targets in the race note, on the **production database engine, default isolation level, pool size ≥ burst, and ≥2 app instances**. A SQLite lab *will* hide `READ COMMITTED` quota and ledger races.

### O6 — SQL Query-Log Tenant-Predicate Oracle (`I2`)

**Idea:** instead of asking an LLM to read every query, record the SQL the application actually executes while serving each lab request as Tenant B, then check each statement against the schema. A statement that touches a tenant-owned table without binding Tenant B's id is a deterministic finding — even if the response happened to be empty, so it catches latent IDORs that the canary oracles miss.

Mechanism: a lab-only driver hook (enabled by `LAB_QUERY_LOG=1`, refused by the boot assertion in production) wraps the executor and writes JSONL with the request-id attribution. The analyzer runs in the oracle process.

```typescript
// lab/query-log.ts — lab-only hook (refuses to load unless APP_ENV=test|development)
import { AsyncLocalStorage } from "node:async_hooks";
import { appendFileSync } from "node:fs";

export interface RequestAttribution { requestId: string; actor: string; route: string }
export const attribution = new AsyncLocalStorage<RequestAttribution>();

export interface SqlExecutor {
  query<T = unknown>(text: string, values?: readonly unknown[]): Promise<T[]>;
}

export function withQueryLog(inner: SqlExecutor, logPath: string): SqlExecutor {
  if (!["test", "development"].includes(process.env.APP_ENV ?? "")) {
    throw new Error("QUERY_LOG_FORBIDDEN_OUTSIDE_LAB");
  }
  return {
    async query<T>(text: string, values: readonly unknown[] = []) {
      const ctx = attribution.getStore();
      appendFileSync(
        logPath,
        JSON.stringify({ t: Date.now(), ...ctx, text, values }) + "\n"
      );
      return inner.query<T>(text, values);
    },
  };
}

// Lab-only middleware: the harness sets x-lab-request-id / x-lab-actor via the credential proxy.
export function labAttributionMiddleware(req: Request, next: () => Promise<Response>) {
  const requestId = req.headers.get("x-lab-request-id");
  if (!requestId) return next();
  const ctx: RequestAttribution = {
    requestId,
    actor: req.headers.get("x-lab-actor") ?? "unknown",
    route: `${req.method} ${new URL(req.url).pathname}`,
  };
  return attribution.run(ctx, next);
}
```

```typescript
// oracle/query-log-oracle.ts — runs in the oracle process, never in the attacker sandbox
import { readFileSync } from "node:fs";

export interface TenantSchema {
  /** table -> tenant column name, from catalog introspection (O7) */
  tenantTables: Readonly<Record<string, string>>;
}
export interface ActorTenants { [actor: string]: string } // actor -> that actor's own tenant id
export interface Violation {
  kind: "NO_TENANT_BOUND" | "FOREIGN_TENANT_BOUND" | "TENANT_COLUMN_NOT_REFERENCED";
  actor: string; route: string; table: string; text: string;
}

const TABLE_REF = (t: string) =>
  new RegExp(`\\b(?:from|join|update|into|delete\\s+from)\\s+(?:"?public"?\\.)?"?${t}"?\\b`, "i");

export function analyzeQueryLog(
  logPath: string,
  schema: TenantSchema,
  actorTenant: ActorTenants,
  allTenantIds: ReadonlySet<string>,
  /** statements run under a SystemScope are allowed and must carry this SQL comment tag */
  systemTag = "/*system-scope*/"
): Violation[] {
  const violations: Violation[] = [];
  const lines = readFileSync(logPath, "utf8").split("\n").filter(Boolean);

  for (const line of lines) {
    const row = JSON.parse(line) as {
      actor?: string; route?: string; text: string; values: unknown[];
    };
    if (!row.actor || !(row.actor in actorTenant)) continue;      // only attributed attacker traffic
    if (row.text.includes(systemTag)) continue;                    // audited SystemScope statements
    const own = actorTenant[row.actor];
    const bound = new Set(row.values.filter((v): v is string => typeof v === "string"));

    for (const [table, column] of Object.entries(schema.tenantTables)) {
      if (!TABLE_REF(table).test(row.text)) continue;
      const base = { actor: row.actor, route: row.route ?? "?", table, text: row.text };

      if (!new RegExp(`\\b${column}\\b`, "i").test(row.text)) {
        violations.push({ kind: "TENANT_COLUMN_NOT_REFERENCED", ...base });
      }
      if (!bound.has(own)) violations.push({ kind: "NO_TENANT_BOUND", ...base });
      for (const v of bound) {
        if (v !== own && allTenantIds.has(v)) {
          violations.push({ kind: "FOREIGN_TENANT_BOUND", ...base });
        }
      }
    }
  }
  return violations;
}
```

Limits (state them in every report): the text/param heuristic can be fooled by a query that references the tenant column in an unrelated way. For high-assurance runs parse statements with a real parser (`libpg-query` for Postgres) and require that the tenant column appears in a top-level `AND`-conjunct of the `WHERE`/`ON` clause of **each** tenant-table range variable. Any hit is a deterministic lead: a micro-agent only has to produce the request that makes the missing predicate matter.

### O7 — Schema-Introspection CI Test (`I2`)

The "forgotten new table" failure is closed without the database enforcing anything: a CI test introspects the catalog, derives the set of tenant tables, and fails if any is reachable outside `ScopedDb`. The full test is in [`../strategy/scoped-db.md`](../strategy/scoped-db.md); the sweep re-runs it against the lab database so the table list used by O6 is derived, never hand-maintained.

### O8 — SSRF Battery (`I4`)

For every parameter classified as a URL sink in the surface map, submit each target and assert the lab's `hits` log stays empty:

| Target | Lab fixture |
|--------|-------------|
| `http://127.0.0.1:{p}/`, `http://localhost:{p}/`, `http://[::1]:{p}/`, `http://[::ffff:127.0.0.1]:{p}/`, `http://2130706433:{p}/`, `http://0x7f000001:{p}/` | Loopback listener |
| `http://169.254.169.254/latest/meta-data/` | Metadata mock bound to the link-local address in the app's network namespace |
| `http://10.77.0.10/` | RFC1918 internal service |
| `https://redirector.lab.test/to?target=<each of the above>` | Redirect-hop server (302 chain, up to 3 hops) |
| `http://rebind.lab.test/` | Rebinding resolver: first answer a "public" address, second answer `127.0.0.1` (TTL 0) |
| `http://user:pw@host/`, non-default ports, `file:`, `gopher:` schemes | Scheme/port/credential guard |

Fixtures: [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md). Also run a **positive control**: with the guard deliberately disabled (O9), the battery must hit the listener.

### O9 — Guard-Mutation Self-Test (Oracle Power)

**Problem:** `INVARIANT_HELD` and "zero findings" are only meaningful if the oracle *could have* failed. Mutation testing restricted to security guards measures exactly that.

**Procedure:**
1. Enumerate guard sites from the surface map and with mutation operators (below).
2. For each site, in an **isolated copy of the repo** (never the working tree), apply one mutation, rebuild, restore the lab snapshot, run the sweep.
3. If the sweep exits non-zero, the mutant is **killed** (oracle has power here). If it exits zero, the mutant **survived**: the oracle is blind at this guard. Add the `(route, invariant)` to the residual list with reason `ORACLE_BLIND`, and write a new oracle probe or hand it to a micro-agent.
4. **Positive control per oracle:** each oracle ships a tiny fixture app (`selftest/`) with a known-bad route; the oracle must flag it. A sweep whose self-tests fail is invalid.

```typescript
// oracle/guard-mutation.ts — runs on the host orchestrator, not in the attacker sandbox
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

export interface MutationOperator {
  id: string;
  fileGlob: RegExp;       // which source files to mutate
  pattern: RegExp;        // must use /g
  replace: string | ((m: string) => string);
  describe: string;
}

export const DEFAULT_OPERATORS: MutationOperator[] = [
  { id: "drop-tenant-and", fileGlob: /\.(ts|rs|sql)$/, describe: "delete `AND x.tenant_id = $n`",
    pattern: /\s+AND\s+[\w.]*tenant_id\s*=\s*\$\d+/gi, replace: "" },
  { id: "can-access-true", fileGlob: /\.ts$/, describe: "scope.canAccessProject(...) -> true",
    pattern: /scope\.canAccessProject\([^)]*\)/g, replace: "true" },
  { id: "drop-status-guard", fileGlob: /\.(ts|sql)$/, describe: "delete `AND status = 'x'` transition guard",
    pattern: /\s+AND\s+status\s*=\s*'[a-z_]+'/gi, replace: "" },
  { id: "skip-require-human", fileGlob: /\.ts$/, describe: "requireHuman*(...) -> identity",
    pattern: /requireHuman\w*\(([^)]*)\)/g, replace: (m) => m.replace(/requireHuman\w*\(([^)]*)\)/, "($1)") },
  { id: "aud-check-off", fileGlob: /\.ts$/, describe: "remove jwtVerify audience pin",
    pattern: /\baudience:\s*[^,\n]+,?/g, replace: "" },
];

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".git" || name === "target") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

export interface MutantResult { operator: string; file: string; index: number; killed: boolean }

export function runGuardMutation(opts: {
  repoDir: string;
  operators?: MutationOperator[];
  /** shell command: rebuild + restore snapshot + run the sweep; exit code != 0 means sweep failed (mutant killed) */
  sweepCommand: string;
  maxMutants?: number;
}): MutantResult[] {
  const results: MutantResult[] = [];
  const operators = opts.operators ?? DEFAULT_OPERATORS;
  let budget = opts.maxMutants ?? 200;

  for (const file of walk(opts.repoDir)) {
    for (const op of operators) {
      if (!op.fileGlob.test(file)) continue;
      const original = readFileSync(file, "utf8");
      const matches = [...original.matchAll(op.pattern)];
      for (let i = 0; i < matches.length && budget > 0; i++, budget--) {
        const workdir = mkdtempSync(join(tmpdir(), "guard-mut-"));
        try {
          cpSync(opts.repoDir, workdir, { recursive: true });
          const target = join(workdir, file.slice(opts.repoDir.length));
          const m = matches[i];
          const replacement = typeof op.replace === "function" ? op.replace(m[0]) : op.replace;
          const mutated = original.slice(0, m.index!) + replacement + original.slice(m.index! + m[0].length);
          writeFileSync(target, mutated);
          const r = spawnSync("sh", ["-c", opts.sweepCommand], {
            cwd: workdir, stdio: "ignore", timeout: 15 * 60_000,
          });
          results.push({ operator: op.id, file, index: i, killed: r.status !== 0 });
        } finally {
          rmSync(workdir, { recursive: true, force: true });
        }
      }
    }
  }
  return results;
}

export const survivors = (r: MutantResult[]) => r.filter((x) => !x.killed);
```

Equivalent mutants (e.g., a redundant tenant predicate) will survive; triage each survivor once and annotate `equivalent: true` with a reason. Coverage target: the **kill ratio over tenant/authorization guards**, reported next to `coverage.json`.

---

## 3. Sweep Output: The Residual List

```json
{
  "sweepVersion": 1,
  "oraclesRun": ["O1","O2","O3","O4","O5","O6","O7","O8","O9"],
  "oracleSelfTests": { "passed": 9, "failed": 0 },
  "findings": [
    { "id": "F-001", "oracle": "O6", "invariant": "I2",
      "route": "PATCH /api/issues/:id", "evidence": "queryLog:FOREIGN_TENANT_BOUND",
      "pov": "pov/F-001.mjs", "replayedByHarness": true }
  ],
  "residual": [
    { "route": "POST /api/exports", "invariant": "I2", "reason": "ORACLE_BLIND", "mutantsSurvived": 2 },
    { "route": "POST /api/projects/:id/transfer", "invariant": "I3", "reason": "NEEDS_MULTI_STEP_CHAIN" },
    { "route": "GET /api/preview", "invariant": "I4", "reason": "TIMING_SUSPECT" }
  ],
  "mutationKillRatio": { "tenantGuards": 0.94, "authGuards": 0.88 }
}
```

**Residual reasons** (the only reasons a route reaches an LLM agent): `ORACLE_BLIND` (mutant survived), `NEEDS_MULTI_STEP_CHAIN`, `NO_ORACLE_FOR_CLASS` (e.g., business logic, prompt-injection routing), `TIMING_SUSPECT`, `INTENT_AMBIGUOUS` (the authz matrix has no row), and `ROAMER` (cross-cutting helpers).

**Exit codes:** `0` = no findings and all self-tests passed; `1` = findings; `2` = invalid sweep (a self-test failed or a required input is missing). A sweep that exits `2` must never be reported as clean.

---

## 4. What the Sweep Deliberately Does Not Do

It does not judge intent. It cannot decide whether a public share link is a bug, whether a discount stacking rule is exploitable, or whether an agent tool-routing policy is sound. Those either come from `intended-exposures.yaml` (human decision, written once) or go to the residual list. Everything the sweep *can* decide, it decides without a model, with a replayable PoV.
