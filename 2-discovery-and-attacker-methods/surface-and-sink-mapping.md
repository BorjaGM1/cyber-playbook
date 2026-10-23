# Step 0: Deterministic Surface, Actor & Sink Mapping (Variant Analysis)

## 1. Mental Model (Why Mapping Always Comes Before Attacking)

When a human or AI agent tries to "audit a repo" by reading files in random order, two things go wrong:
1. **Attention drift:** The reviewer carefully inspects the first 5 routes in `src/routes/`, gets tired (or fills the context window), and skims the remaining 35 routes—missing the one legacy export endpoint on line 410 that forgot a tenant check.
2. **Low discovery rate on unguided search:** As shown in BountyBench ([arXiv:2505.15216](https://arxiv.org/abs/2505.15216)), open-ended repository scanning catches only **12.5%** of vulnerabilities, whereas evaluating a specific sink or entry point catches **67.5%**.

**Surface and Sink Mapping** converts an unknown codebase into a finite, deterministic matrix of **Entry Points**, **Actors**, **Data Stores**, and **Sensitive Sinks** before a single static check or dynamic attack is launched.

---

## 2. The Four Tables Every Agent Must Extract First

Before auditing code or launching the attacker harness, generate a structured `SECURITY_SURFACE_MAP.json` (or markdown table) containing these four inventories:

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
Every way untrusted bytes can enter the application:
- **HTTP Routes & Server Actions:** Method, URL pattern, file:line, auth middleware applied, credential tiers allowed (`cookie`, `bearer`, `webhook_hmac`, `public`), input schema validator, and rate-limit gate.
- **Secondary / Side-Door Read Surfaces:** Global search (`/api/search`), autocomplete, activity feeds, issue/entity history, CSV/PDF exports, dashboard count/sum aggregates, GraphQL/batch resolvers.
- **Agent / MCP / WebSocket / PTY Surfaces:** Every registered MCP tool (`server.tool(...)`), WebSocket message handler, CLI command, or PTY frame decoder.
- **Webhook & Callback Receivers:** Stripe/billing webhooks, OAuth/OIDC callbacks, third-party inbound queues.

### Table C: Data Ownership & Foreign-Key Graph
For every database table (PostgreSQL, SQLite, D1) and storage bucket (S3, R2, local disk):
- Table/Bucket name.
- Primary tenant-isolation column (`tenant_id`, `org_id`, `workspace_id`, `owner_id`).
- Secondary capability column, if any (`project_id`, `team_id`, `visibility`).
- Every outbound foreign key (`project_id`, `parent_id`, `attachment_id`, `assignee_id`) that must be validated to belong to the **same** `tenant_id` on `INSERT` and `UPDATE`.

### Table D: Sensitive Sinks (Where `I3`, `I4`, and `I5` Fail)
- **Database Queries:** Any raw SQL execution, dynamic `ORDER BY`/`WHERE` builder, or unscoped table access.
- **Economic / Quota Mutations:** Any query touching balances, credits, subscriptions, coupons, seat counts, or rate-limit counters.
- **Outbound Network Calls (SSRF / Cost Sinks):** Every `fetch`, `axios`, `reqwest`, email sender, or paid LLM API call.
- **Filesystem / Object Storage Reads & Writes:** Every `fs.*`, `path.join`, `bucket.get`, `bucket.put`, or presigned URL generator.
- **Interpreter / Process Sinks:** Every `child_process`, `Command::new`, PTY write (`\x1b[200~`), `eval`, `dangerouslySetInnerHTML`, or raw HTML response.

---

## 3. Execution Protocol: Automated Surface Extraction Commands

An agent starting a security review should run this deterministic extraction pass first:

```bash
# 1. Extract all HTTP routes (Next.js App Router, Express/Hono/Fastify, Axum/Actix, Cloudflare Workers):
fd 'route\.(ts|js|tsx)$' src/
rg -n '\b(app|router)\.(get|post|put|patch|delete|all|use)\s*\(' src/
rg -n '\.route\s*\(\s*"[^"]+"' src/

# 2. Extract all MCP tools, Server Actions, and WebSocket / RPC handlers:
rg -n '"use server"|server\.tool\(|registerTool\(|on\(["\x27]message' src/

# 3. Extract all database tables and foreign keys from migrations/schema:
rg -n -i 'CREATE\s+TABLE|ALTER\s+TABLE|sqliteTable|pgTable' src/ migrations/ drizzle/ prisma/

# 4. Extract all sensitive sinks (SQL, fetch, storage, process, crypto, env):
rg -n '\b(fetch|exec|spawn|Command::new|writeFile|readFile|getSignedUrl|createHmac|jwtVerify)\b' src/
```

---

## 4. Variant Analysis: Turning One Bug into Zero Remaining Variants

Whenever you find a vulnerability (or review a case from [`../1-known-vulnerabilities/`](../1-known-vulnerabilities/README.md)), **never stop after fixing the single line where you noticed it**:
1. Write a deterministic search pattern (AST rule via `ast-grep` / Semgrep or regex via `rg`) that matches the structural shape of the vulnerable sink across the entire `SECURITY_SURFACE_MAP`.
2. Inspect **every match** in the table. For example, if `DELETE /api/comments/:id` forgot to join `issues.project_id` for guest authorization, immediately inspect every other child table in Table C (`attachments`, `reactions`, `issue_labels`, `subtasks`, `history`) for the exact same missing join.
3. Turn the search pattern into a permanent CI check in [`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md) so the variant can never regress.
