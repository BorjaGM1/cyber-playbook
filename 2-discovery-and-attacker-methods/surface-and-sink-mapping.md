# Step 0: Deterministic Surface, Actor, Sink, Config & Capability Mapping (Variant Analysis)

## 1. Mental Model (Why Mapping Always Comes Before Attacking)

When a human or AI agent tries to "audit a repo" by reading files in random order, two things go wrong:
1. **Attention drift:** The reviewer carefully inspects the first 5 routes in `src/routes/`, gets tired (or fills the context window), and skims the remaining 35 routes—missing the one legacy export endpoint on line 410 that forgot a tenant check.
2. **Low discovery rate on unguided search:** As shown in BountyBench ([arXiv:2505.15216](https://arxiv.org/abs/2505.15216)), open-ended repository scanning catches only **12.5%** of vulnerabilities, whereas evaluating a specific sink or entry point catches **67.5%** (canonical write-up: [`../observations/LOG.md`](../observations/LOG.md) entry 8).

**Surface and Sink Mapping** converts an unknown codebase into a finite, deterministic set of **Entry Points**, **Actors**, **Data Stores**, **Sensitive Sinks**, **Configuration Flags** and a **Capability Graph** before a single static check or dynamic attack is launched. It also emits `AUTH_DIGEST.md`, the compact "how identity and scoping work here" summary that becomes the stable cached prefix of every later agent ([`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md)).

**Two sources, always diffed.** Static grep misses what frameworks register dynamically; runtime enumeration misses code paths that are only mounted under some config. Build the map from **both** and treat every disagreement as a lead (Section 4).

---

## 2. The Six Tables Every Agent Must Extract First

Generate a structured `SECURITY_SURFACE_MAP.json` containing these inventories.

### Table A: Actor & Credential Hierarchy
List every distinct caller state supported by the application:
1. `Anonymous` (no credentials).
2. `PendingAuth` (holds a temporary cookie/token such as `pending_mfa`, `oauth_state`, or magic-link token).
3. `TenantB_Stranger` (fully authenticated owner/member of a separate organization `Org B`).
4. `TenantA_Guest` (authenticated guest in `Org A` restricted to `Project 1`, forbidden from `Project 2` and workspace admin routes).
5. `TenantA_Member` (standard member in `Org A`, forbidden from owner-only billing/deletion routes).
6. `TenantA_MachineKey` (programmatic `Bearer sk_...` API key in `Org A`, forbidden from human-only key-minting and role-escalation routes).
7. `TenantA_Revoked` (holds a recently revoked session cookie, revoked API key, or removed member account in `Org A`).
8. `TenantA_Owner` (full administrative owner of `Org A`).

### Table B: Complete Entry-Point Matrix
Every way untrusted bytes can enter the application. Each row: method, URL pattern, `file:line`, **middleware actually applied (from the runtime dump)**, credential tiers allowed (`cookie`, `bearer`, `webhook_hmac`, `public`), input schema validator, rate-limit gate, `surface` tag (`human_ui_only` / `machine_api_allowed`).
- **HTTP Routes & Server Actions:** every route handler export; every function in a `"use server"` module is a public endpoint.
- **Secondary / Side-Door Read Surfaces:** global search, autocomplete, activity feeds, issue/entity history, CSV/PDF exports, dashboard count/sum aggregates, GraphQL/batch resolvers.
- **Agent / MCP / WebSocket / PTY Surfaces:** every registered MCP tool, WebSocket message handler, CLI command, or PTY frame decoder.
- **Webhook & Callback Receivers:** billing webhooks, OAuth/OIDC callbacks, third-party inbound queues.
- **Non-HTTP Entry Points (frequently missed):** queue consumers, cron/`scheduled` handlers, inbound `email` handlers, Durable Object `fetch`/`alarm`/`webSocketMessage`, `WorkerEntrypoint` RPC methods, background job processors. These run with ambient service identity ([`../1-known-vulnerabilities/authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../1-known-vulnerabilities/authorization-and-tenancy/async-jobs-and-scope-propagation.md)).

### Table C: Data Ownership & Foreign-Key Graph
For every database table (PostgreSQL, SQLite, D1) and storage bucket (S3, R2, local disk), search index and cache namespace:
- Table/Bucket/Index name.
- Primary tenant-isolation column (`tenant_id`, `org_id`, `workspace_id`, `owner_id`) — **derived from catalog introspection, not hand-maintained** (see the schema-introspection test in [`../strategy/scoped-db.md`](../strategy/scoped-db.md)).
- Secondary capability column, if any (`project_id`, `team_id`, `visibility`), soft-delete column (`deleted_at`).
- Every outbound foreign key (`project_id`, `parent_id`, `attachment_id`, `assignee_id`) that must be validated to belong to the **same** `tenant_id` on `INSERT` and `UPDATE`.
- Derived/denormalized copies (FTS index, vector store namespace, cache keys, materialized aggregates): they need the same scope columns ([`../1-known-vulnerabilities/authorization-and-tenancy/cache-and-derived-data.md`](../1-known-vulnerabilities/authorization-and-tenancy/cache-and-derived-data.md)).

### Table D: Sensitive Sinks (Where `I3`, `I4`, and `I5` Fail)
- **Database Queries:** raw SQL execution, dynamic `ORDER BY`/`WHERE` builders, ORM `where` objects built from request JSON, any access to a table without the scoped handle.
- **Economic / Quota Mutations:** anything touching balances, credits, subscriptions, coupons, seat counts, rate-limit counters.
- **Outbound Network Calls (SSRF / Cost Sinks):** every `fetch`, `axios`, `reqwest`, email sender, paid LLM/API call, webhook delivery, headless-browser/PDF render (`puppeteer`, `playwright`, `wkhtmltopdf`).
- **Filesystem / Object Storage:** every `fs.*`, `path.join`, `bucket.get`, `bucket.put`, presigned URL generator, archive extraction.
- **Interpreter / Process Sinks:** `child_process`, `Command::new`, PTY writes (`\x1b[200~`), `eval`, `new Function`, `vm.*`, dynamic `import()`/`require(userInput)`, `new RegExp(userInput)`, `yaml.load` (unsafe loader), template engines, markdown renderers, `dangerouslySetInnerHTML`, raw HTML responses.
- **Untrusted Deserialization:** `JSON.parse` of data from webhooks, queues, caches or storage (second-order input), `unserialize`/pickle-style loaders.
- **Redirects and Reflection:** `Response.redirect`, `redirect()`, `Location` headers built from query/body (`next=`, `returnTo=`), `Host`/`X-Forwarded-Host` used to build absolute URLs (reset-link poisoning).
- **Durable Object / Actor Stubs:** `env.OBJECT.get(id)` where `id` derives from request input.
- **Identity Resolution:** every place a tenant or actor is derived (`X-Org-Id` header, "active org" cookie, subdomain, path param) — client-selected tenants must be membership-checked.

### Table E: Security Configuration & Flag Graph
Security behavior depends on settings. For each security-relevant environment variable, config key and feature flag:

| Field | Meaning |
|-------|---------|
| `name`, `default`, `type` | Identity of the flag |
| `readSites[]` | `file:line` of every read |
| `guards[]` | Which security control(s) the flag enables, weakens or bypasses (auth mode, proxy trust, CORS origins, rate limiting, mTLS, IP/hostname allowlists, cookie flags, webhook verification) |
| `dependsOn[]` | Other flags a guard's *condition* reads (e.g., a hostname deny-list that depends on `reverse_dns`) |
| `bootAsserted` | Whether `assertSafeBootConfig()` constrains it |

The pairwise-interaction audit ([`attack-surface-and-config-interaction-audit.md`](attack-surface-and-config-interaction-audit.md), Pass 3) runs only over pairs where one flag appears in another guard's `dependsOn`, not over the full cross product.

### Table F: Capability Graph (Input to Stateful Tests and Chain Agents)
A directed list of every mutating route that changes **who can see or do what**. Each edge:

```json
{ "operationId": "moveIssue", "method": "PATCH", "route": "/api/issues/:id/move",
  "effect": "move_parent", "entity": "issue",
  "params": { "id": "IssueId", "projectId": "ProjectId" },
  "readsPermissionFrom": ["project_guests", "org_members"],
  "writesPermissionTo": ["issues.project_id"],
  "affectsSurfaces": ["GET /api/issues/:id", "GET /api/search", "GET /api/issues/:id/history", "GET /api/export"] }
```

`effect` ∈ `grant_membership`, `revoke_membership`, `change_role`, `move_parent`, `change_visibility`, `delete`, `restore`, `transfer_owner`, `create`, `rotate_credential`. This graph is what lets [`stateful-property-and-fuzzing-harnesses.md`](stateful-property-and-fuzzing-harnesses.md) auto-generate its command alphabet and lets a chain agent propose "grant → create → move → revoke → export" sequences deliberately.

---

## 3. Execution Protocol: Runtime Enumeration First, Static Second

### 3.1 Runtime Route Dumps (authoritative for "what is mounted")

| Framework | How to enumerate what the running app actually serves |
|-----------|--------------------------------------------------------|
| **Next.js (App/Pages Router)** | After `next build`: `.next/routes-manifest.json` (static/dynamic/data routes and redirects), `.next/server/app-paths-manifest.json`, `.next/server/pages-manifest.json`, `.next/server/middleware-manifest.json` (**middleware matchers**), `.next/server/server-reference-manifest.json` (**Server Action IDs**). |
| **Express / Connect** | Walk `app._router.stack` (Express 4) or `app.router.stack` (Express 5), recursing into `layer.handle.stack` for routers; record `layer.route.path`, methods, and the **order** of non-route middleware layers (auth placement). |
| **Hono** | `app.routes` (array of `{ method, path, handler }`); `showRoutes(app)` from `hono/dev` prints it. Recurse into `app.route()` mounts. |
| **Axum / Actix (Rust)** | There is no stable runtime listing. Register every route through one helper or macro that records `(method, path, layer_tags)` into a registry that a `cargo test` dumps (`fn all_routes() -> Vec<RouteDecl>`). Record which `.layer(...)` wraps each `.route(...)`/`.nest(...)`—layer **order** decides what runs first. Fallback: differential probing of candidate paths for `404` vs `405` vs `401`. |
| **Cloudflare Workers / Durable Objects** | Inspect the bundle (`wrangler deploy --dry-run --outdir dist`) and enumerate exported handlers: `fetch`, `scheduled`, `queue`, `email`, `tail`; classes `extends DurableObject` (`fetch`, `alarm`, `webSocketMessage`, `webSocketClose`); `extends WorkerEntrypoint` RPC methods; bindings in `wrangler.toml` (`services`, `queues`, `r2_buckets`, `d1_databases`). |
| **OpenAPI / tRPC / GraphQL** | Export the schema (`openapi.json`, `appRouter._def.procedures`, introspection in the lab only). Treat the *schema* as a claim to be diffed against what is mounted. |

### 3.2 Static Extraction (authoritative for "what code exists")

```bash
# 1. HTTP routes: file-based and call-based
fd 'route\.(ts|js|tsx)$' src/ app/
fd -e ts -e tsx -g 'middleware.*' .
rg -n 'export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b' src/ app/
rg -n '\b(app|router)\.(get|post|put|patch|delete|all|use)\s*\(' src/
rg -n '\.route\s*\(\s*"[^"]+"|\.nest\s*\(|\.layer\s*\(' src/

# 2. Server Actions, MCP tools, WebSocket/RPC/queue/cron/email/DO handlers
rg -n '"use server"|server\.tool\(|registerTool\(|on\(["\x27]message|webSocketMessage|\balarm\s*\(|async\s+(queue|scheduled|email)\s*\(' src/
rg -n 'extends\s+(DurableObject|WorkerEntrypoint)' src/

# 3. Tables, foreign keys, and tenant columns
rg -n -i 'CREATE\s+TABLE|ALTER\s+TABLE|sqliteTable|pgTable' src/ migrations/ drizzle/ prisma/

# 4. Sinks
rg -n '\b(fetch|exec|spawn|Command::new|writeFile|readFile|getSignedUrl|createHmac|jwtVerify)\b' src/
rg -n '\b(redirect|Response\.redirect|new RegExp|import\(|require\(|vm\.|yaml\.load|puppeteer|playwright|marked|markdown-it|sendMail|resend|\.get\(\s*env\.\w+\.idFrom)' src/
rg -n 'JSON\.parse\(' src/ | rg -v 'JSON\.parse\(\s*"'

# 5. Config reads (feeds Table E)
rg -n 'process\.env\.|env\.[A-Z_]{3,}|std::env::var|Deno\.env' src/
```

### 3.3 Capability-Graph Extraction
Take every mutating route from Table B and classify its effect by the tables/columns it writes (Table C): writes to a membership/role table → `grant_membership`/`revoke_membership`/`change_role`; writes to a parent FK column (`project_id`, `team_id`, `parent_id`) → `move_parent`; writes to a visibility/`deleted_at` column → `change_visibility`/`delete`/`restore`. Use the query-log hook ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md), O6) to confirm the written columns empirically rather than trusting grep.

---

## 4. Static-vs-Runtime Diff (The Highest-Yield Check in Step 0)

```javascript
// surface-diff.mjs — every disagreement is a lead
import { readFileSync } from "node:fs";
const norm = (r) => `${r.method.toUpperCase()} ${r.path.replace(/\[(\.\.\.)?(\w+)\]|:(\w+)|\{(\w+)\}/g, ":p").replace(/\/+$/, "") || "/"}`;
const runtime = new Set(JSON.parse(readFileSync("runtime-routes.json", "utf8")).map(norm));
const staticR = new Set(JSON.parse(readFileSync("static-routes.json", "utf8")).map(norm));
const openapi = new Set(JSON.parse(readFileSync("openapi-routes.json", "utf8")).map(norm));

const report = {
  mountedButNotInCode:   [...runtime].filter((r) => !staticR.has(r)),   // dynamic registration, plugins, generated routes
  inCodeButNotMounted:   [...staticR].filter((r) => !runtime.has(r)),   // dead code OR config-gated routes (Pass 1 ASR leads)
  mountedButNotDocumented: [...runtime].filter((r) => !openapi.has(r)), // shadow / legacy / debug endpoints
  documentedButNotMounted: [...openapi].filter((r) => !runtime.has(r)),
};
console.log(JSON.stringify(report, null, 2));
```

Each bucket is a lead: *mounted-but-not-in-code* means routes the reviewer cannot see by reading; *in-code-but-not-mounted* routes may mount under another configuration (a Table E dependency); *mounted-but-not-documented* routes are frequently debug, legacy or forgotten.

---

## 5. Output: `SECURITY_SURFACE_MAP.json` and `AUTH_DIGEST.md`

`SECURITY_SURFACE_MAP.json` has top-level keys `actors`, `entryPoints`, `tables`, `sinks`, `config`, `capabilityGraph`, `diff`, and `scanManifest` (tree hash, tool versions). Entry points are the unit of coverage accounting in `coverage.json`.

`AUTH_DIGEST.md` (≤ 150 lines; written once, reused by every agent as part of the cached prefix) contains:
1. **Credential kinds** and their verifiers (`file:line`): session cookie, API key, edge JWT, webhook HMAC; token purposes and cookie names.
2. **Actor construction:** the single module that produces an authenticated actor, and what a handler receives.
3. **Scope type:** how tenant/project scope is represented (`TenantScope`/`ScopedDb`), where it is constructed, and which modules still import the raw database handle (a direct list—each is a finding candidate).
4. **Middleware order** per surface (what runs before parsing and before authentication).
5. **Revocation mechanism** and its documented latency SLO.
6. **Unscoped escape hatches:** every `SystemScope`/service-role use and who calls it.
7. **Known intended exposures** (copied from `intended-exposures.yaml`).

A micro-agent that begins with this digest does not spend its 12-step budget re-deriving how authentication works.

---

## 6. Variant Analysis: Turning One Bug into Zero Remaining Variants

Whenever you find a vulnerability (or review a case from [`../1-known-vulnerabilities/`](../1-known-vulnerabilities/README.md)), **never stop after fixing the single line where you noticed it**:
1. Write a deterministic search pattern (AST rule via `ast-grep` / Semgrep or regex via `rg`) that matches the structural shape of the vulnerable sink across the entire map.
2. Inspect **every match** in the tables. If `DELETE /api/comments/:id` forgot to join `issues.project_id` for guest authorization, inspect every other child table in Table C (`attachments`, `reactions`, `issue_labels`, `subtasks`, `history`) for the same missing join.
3. Turn the pattern into a permanent CI check ([`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md)) and, where possible, a type-level restriction so the variant is unrepresentable.
4. Add the pattern as a **guard-mutation operator** ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md), O9) so the oracle suite is shown to catch its removal.
