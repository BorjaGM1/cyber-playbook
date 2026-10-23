# Cross-Tenant IDOR/BOLA & Why Explicit Scoping Beats Database RLS

## 1. Attack Transcript

Tenant B's owner holds a valid session. They know (or enumerated) two UUIDs that belong to Tenant A: an issue `7f1c…` and a project `a3d9…`.

```bash
# 1. Existence oracle: same caller, an existing foreign issue vs. a random UUID
$ curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: __Host-session=$B" https://app.example.com/api/issues/7f1c2d4e-0000-4000-8000-00000000a001
403
$ curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: __Host-session=$B" https://app.example.com/api/issues/11111111-2222-4333-8444-555555555555
404
# 403 vs 404: the attacker now has a perfect "does this UUID exist in some other tenant" oracle.

# 2. Foreign-key attach: B edits its OWN issue but re-parents it into A's project
$ curl -s -X PATCH -H "Cookie: __Host-session=$B" -H 'content-type: application/json' \
    -d '{"title":"hello","projectId":"a3d9b1c2-0000-4000-8000-00000000b002"}' \
    https://app.example.com/api/issues/9e8b0000-0000-4000-8000-00000000c003
200 OK
# B's issue now lives in A's project; anything A's members do with "all issues in this project"
# (exports, webhooks, notifications, AI summaries) now processes attacker-controlled content,
# and B's issue is returned by A's project queries.

# 3. Client-selected tenant: the server believes a header
$ curl -s -H "Cookie: __Host-session=$B" -H "X-Org-Id: <tenant A uuid>" https://app.example.com/api/issues
[{"id":"7f1c…","title":"Quarterly acquisition target flag{CANARY_TENANT_A}"}, …]
```

## 2. Spot the Bug

Three handlers from the same codebase. Each one looks reasonable. Find the cross-tenant hole in each before reading on.

```typescript
export async function updateIssue(req: Request, issueId: string, actor: { tenantId: string }) {
  const body = await req.json();

  const issue = await globalDb.queryOne("SELECT id, tenant_id FROM issues WHERE id = $1", [issueId]);
  if (!issue) {
    return new Response("Not found", { status: 404 });
  }
  if (issue.tenant_id !== actor.tenantId) {
    return new Response("Forbidden", { status: 403 });
  }

  await globalDb.execute(
    "UPDATE issues SET title = $1, project_id = $2 WHERE id = $3",
    [body.title, body.projectId, issueId]
  );
  return new Response("OK", { status: 200 });
}

export async function deleteComment(commentId: string) {
  await globalDb.execute("DELETE FROM comments WHERE id = $1", [commentId]);
}

export async function resolveActor(req: Request) {
  const session = await verifySession(req);
  const orgId = req.headers.get("x-org-id") ?? session.defaultOrgId;
  return { userId: session.sub, tenantId: orgId };
}
```

<details>
<summary>Reveal the bugs</summary>

1. `updateIssue`: `403` vs `404` existence oracle; `body.projectId` is never checked against the caller's tenant (foreign-key attach); the caller's role and project visibility are never consulted (a guest could edit and re-parent any issue in the tenant).
2. `deleteComment`: the primary key is the only filter, so any authenticated caller deletes any tenant's comment.
3. `resolveActor`: the active tenant is whatever the client says. Authentication succeeded, but **membership of the selected org was never checked**.

</details>

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (OWASP ASVS `v5.0.0-8.1.1`, `8.2.1`, `8.2.2`, `8.3.1`).
- **Mechanism:** Broken Object Level Authorization (BOLA / IDOR) happens when an endpoint authenticates the caller (`User B` in `Tenant B`), reads a target resource identifier from the URL path, query string, or JSON body (`item_id`, `project_id`, `invoice_id`), and executes a read or write query filtered only by that primary key (`WHERE id = $1`) without binding the caller's authorized `tenant_id` (and project/role capability).
- **Secondary Mechanism (`403` vs. `404` Enumeration Oracle):** When a developer checks `if (resource.tenantId !== actor.tenantId) return res.status(403)`, an attacker can distinguish between an existing cross-tenant resource (`403 Forbidden`) and a non-existent resource (`404 Not Found`), leaking resource existence, active UUIDs, and timing metadata.
- **Tertiary Mechanism (Client-Selected Tenant):** The "active org/workspace" is chosen from `X-Org-Id`, an `active_org` cookie, a subdomain or a body field, and the server never proves that the authenticated user is a live member of that org. Everything downstream is then correctly scoped to the *wrong* tenant, so scoped-query tests pass.
- **Why happy-path tests pass:** tests authenticate as one tenant, create data in that tenant and read it back. They never present a second tenant's identifiers or select a tenant the user does not belong to.

### 3.1 Why Relying on Database Row-Level Security (RLS) Fails in Practice

A common piece of generic advice is *"just turn on PostgreSQL Row-Level Security (RLS) and forget about tenant filtering in application code."* **Do not do this—not even in pure PostgreSQL applications.**

Relying on database RLS as your primary or mandatory isolation guard introduces four severe operational failure modes:
1. **Easy to Forget on New Tables (Silent Fail-Open):** In PostgreSQL, every new `CREATE TABLE` defaults to **RLS disabled**. If an engineer or coding agent adds a migration for `issue_comments` or `export_jobs` and forgets `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`, every query against that table returns rows across all tenants with zero compiler warnings.
2. **Hidden Outside the Code Under Review:** When access control lives in SQL migration files from six months ago rather than in the TypeScript/Rust repository method being modified, neither a human reviewer nor a static analyzer can tell by reading `db.query("SELECT * FROM invoices WHERE id = $1", [id])` whether that query is safe.
3. **Silently Bypassed by Roles & Connection Poolers:**
   - Any role with `BYPASSRLS`, superuser, or table ownership (unless `FORCE ROW LEVEL SECURITY` is set on every single table) ignores RLS policies completely.
   - In transaction-pooled environments (`PgBouncer`, Neon, Supavisor), session-level settings (`SET app.current_tenant_id = ...`) either fail or bleed across concurrent requests on the same pooled connection if `SET LOCAL` / `set_config(..., true)` is ever misused outside an explicit transaction block.
4. **Zero Protection for Non-Postgres Stores:** Application state rarely lives only in one Postgres instance. As soon as a route reads from SQLite/D1, Redis caches, search indexes, or S3/R2 object storage, engineers conditioned to rely on Postgres RLS write unscoped queries that immediately leak cross-tenant data.

**The Playbook Rule:** Enforce tenant and capability scoping **explicitly in application code by construction** (via typed `ScopedDb(scope)` capability handles where unscoped queries cannot be called, specified in full in [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)), and verify isolation from the outside using an automated **Cross-Tenant Canary Harness**, a CI schema-introspection test and the SQL query-log tenant-predicate oracle. If a team already runs database row policies, this playbook does not count them as a control: audits, canary sweeps and patch proofs are computed as if they were absent, so a gap in the application layer is always reported.

*The "forgot the new table" objection applies to any scheme, so it is closed mechanically rather than by trust:* the catalog test in [`scoped-db.md`](../../strategy/scoped-db.md#4-the-ci-catalog-test-every-tenant-table-is-reachable-only-via-scopeddb) fails CI when a table with a tenant column (or one FK-derived from it) is not registered, and the query-log oracle flags any statement lacking the actor-bound predicate.

### Where It Hides

- `PATCH`, `PUT`, and `DELETE` handlers that look up or mutate a child record by its UUID (`DELETE FROM comments WHERE id = $1`) assuming the UI only renders delete buttons on the owner's comments.
- Foreign-key attachment on create/update (`POST /api/issues` passing `{ projectId: "<victim_project_uuid>", assigneeId: "<victim_user_uuid>" }`), where the handler checks that the caller is in `Tenant B`, creates the issue in `Tenant B`, but links it to `Tenant A`'s `projectId` or `attachmentId`.
- Batch operations (`POST /api/items/bulk-delete` with `{ ids: [...] }`) that verify ownership of `ids[0]` and then execute `DELETE FROM items WHERE id = ANY($1)` across the whole array.
- Active-tenant resolution (`X-Org-Id`, `active_org` cookie, `?org=`, subdomain) that is trusted without a live membership lookup.
- Non-ID selectors: slugs, short codes, email addresses and invite codes resolve resources across tenants just like UUIDs do.

## 4. Hardened Pattern

### 4.1 Active tenant from live membership, never from the client

```typescript
export async function resolveScope(req: Request, db: AuthDb): Promise<TenantScope> {
  const session = await verifySession(req);                       // I1: signature, aud, iss, exp, purpose
  const requestedOrg = req.headers.get("x-org-id") ?? session.defaultOrgId; // a *request*, not a fact
  const membership = await db.queryOne<LiveMembership>(
    `SELECT m.user_id AS "userId", m.org_id AS "tenantId", m.role, m.revoked_at AS "revokedAt",
            COALESCE(array_agg(g.project_id) FILTER (WHERE g.project_id IS NOT NULL), '{}') AS "projectGrants"
       FROM org_members m
       JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
       LEFT JOIN project_guests g ON g.org_id = m.org_id AND g.user_id = m.user_id AND g.revoked_at IS NULL
      WHERE m.user_id = $1 AND m.org_id = $2 AND m.revoked_at IS NULL
      GROUP BY m.user_id, m.org_id, m.role, m.revoked_at`,
    [session.sub, requestedOrg]
  );
  if (!membership) throw notFound();                              // same 404 as a nonexistent org
  return scopeFromVerifiedSession(session, membership);           // only mint site; see scoped-db.md
}
```

### 4.2 Scope types and the repository (ORM-free SQL)

`TenantScope` is the union `FullMemberScope | ProjectGuestScope` defined in [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md). Note on TypeScript limits: a `private constructor` is a compile-time convention only. Forgery is prevented by a nominal `#brand` field, by the fact that the sole minting function is imported only by auth middleware (enforced by an import-boundary lint), and by the query-log oracle for anything that slips past. Do not describe the class as "private to the auth middleware" in review comments; describe the lint rule.

```typescript
export class IssueRepository {
  constructor(private readonly db: SqlExecutor) {}

  /**
   * Moving an issue between projects is a FULL-MEMBER capability; a guest scope cannot call this
   * (the parameter type excludes it).
   */
  async moveIssue(
    scope: FullMemberScope,
    issueId: string,
    targetProjectId: string
  ): Promise<{ id: string; projectId: string } | null> {
    const rows = await this.db.query<{ id: string; project_id: string }>(
      `UPDATE issues AS i
          SET project_id = $2,
              updated_at = CURRENT_TIMESTAMP
        WHERE i.id = $1
          AND i.tenant_id = $3
          AND i.deleted_at IS NULL
          AND EXISTS (
                SELECT 1 FROM projects AS p
                 WHERE p.id = $2
                   AND p.tenant_id = $3
                   AND p.archived_at IS NULL
              )
      RETURNING i.id, i.project_id`,
      [issueId, targetProjectId, scope.tenantId]
    );
    return rows.length === 0 ? null : { id: rows[0].id, projectId: rows[0].project_id }; // null -> 404
  }

  /**
   * Text edits are allowed for guests, but ONLY on issues in projects they currently hold.
   * `allowedProjects` is NULL for full members.
   */
  async updateIssueText(
    scope: TenantScope,
    issueId: string,
    input: { title: string; description: string }
  ): Promise<{ id: string; title: string } | null> {
    const allowed = scope.kind === "guest" ? [...scope.allowedProjectIds] : null;
    const rows = await this.db.query<{ id: string; title: string }>(
      `UPDATE issues AS i
          SET title = $1, description = $2, updated_at = CURRENT_TIMESTAMP
        WHERE i.id = $3
          AND i.tenant_id = $4
          AND i.deleted_at IS NULL
          AND ($5::uuid[] IS NULL OR i.project_id = ANY($5::uuid[]))
      RETURNING i.id, i.title`,
      [input.title, input.description, issueId, scope.tenantId, allowed]
    );
    return rows.length === 0 ? null : rows[0];
  }
}
```

Both statements return zero rows for: nonexistent issue, another tenant's issue, an issue in a project the guest cannot see, a target project in another tenant, or an archived target. All five collapse to the same `notFound()` response.

### 4.3 Single `notFound()` and strict input

```typescript
export function notFound(): Response {
  return new Response(JSON.stringify({ error: "Not Found" }), {
    status: 404,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}

const MoveSchema = z.object({ targetProjectId: z.string().uuid() }).strict();
```

## 5. Residual Edge Cases

- **Timing oracle.** A `404` produced by an early `return` is faster than one produced after a full query. Both paths here run one statement, but verify with the differential oracle's timing check on routes that do extra work for existing rows.
- **Batch endpoints.** Apply the predicate to the whole set and compare counts: `DELETE … WHERE id = ANY($1) AND tenant_id = $2 RETURNING id`, then require `rows.length === ids.length`, otherwise roll back and return `404`. Partial success leaks which IDs exist.
- **Other foreign keys on the same row** (`assignee_id`, `parent_id`, `attachment_id`) need their own same-statement `EXISTS`, not just `project_id`. Composite `(tenant_id, parent_id)` foreign keys make a wrong reference unrepresentable even if a query is wrong.
- **Same-tenant authorization is separate from tenancy.** `tenant_id` binding stops cross-tenant bleed; a member editing an owner-only object is a function-level check (`v5.0.0-8.2.1`) and needs its own type-level capability.
- **Non-UUID selectors** (slug, invite code, email) must be resolved through the same scoped query, and error responses must not distinguish "no such slug" from "slug exists elsewhere".
- **Joins.** Every joined tenant table needs its own predicate in the `ON` clause; one scoped table joined to an unscoped one still leaks.
- **Cache and queue copies.** Scope is lost when the row is cached or handed to a worker: see [`cache-and-derived-data.md`](cache-and-derived-data.md) and [`async-jobs-and-scope-propagation.md`](async-jobs-and-scope-propagation.md).

## 6. How to Discover It Automatically

### A. Static AST / Grep Audit
Every SQL query or ORM call touching a tenant-owned table must bind `tenant_id` (or `org_id` / `workspace_id`). Scan for raw primary-key lookups missing a tenant predicate:

```bash
# Find SQL queries with `WHERE id =` that do not also include `tenant_id` or `org_id`:
rg -n -i 'WHERE\s+id\s*=' src/ | rg -v -i 'tenant_id|org_id|workspace_id|owner_id'

# Multi-line SQL and tagged templates: look for a statement with an `id =` predicate and no tenant column.
rg -nU -i '(?s)(SELECT|UPDATE|DELETE)[^;`"]*?\bWHERE\b[^;`"]*?\bid\s*=\s*\$\d+(?![^;`"]*(tenant_id|org_id|workspace_id))' src/
```

Preferred (structure-aware, with fixtures `vulnerable.ts` / `safe.ts` that unit-test the rule):

```yaml
# rules/handler-uses-raw-db.yml  (Semgrep)
rules:
  - id: raw-db-in-request-code
    languages: [typescript]
    severity: ERROR
    message: Request code must use ScopedDb, not the raw handle.
    pattern-either:
      - pattern: import { $X } from "$P"
      - pattern: globalDb.$M(...)
    metavariable-regex:
      metavariable: $P
      regex: .*/db/raw(\.ts)?$
    paths:
      include: ["src/routes/**", "src/app/**", "src/actions/**"]

  - id: tenant-selected-by-client
    languages: [typescript]
    severity: ERROR
    message: Active tenant must come from a live membership lookup, not a header/cookie/query value.
    pattern-either:
      - pattern: $TENANT = $REQ.headers.get("x-org-id")
      - pattern: $TENANT = $REQ.cookies.get("active_org")
      - pattern: $TENANT = $REQ.nextUrl.searchParams.get("org")
```

For ORMs, ban unscoped accessor shapes the same way (Drizzle `eq(table.id, x)` outside `and(eq(table.tenantId, …))`; Prisma `findUnique({ where: { id } })` on registered models).

### B. Dynamic Attacker Test (Cross-Tenant Canary + `404` Indistinguishability Oracle)
1. **Seed Victim (`User A`, `Tenant A`):** Create one record of every entity type (`Project`, `Issue`, `Comment`, `Webhook`, `Attachment`) containing a unique canary `flag{UUID}` in its text fields. Record their primary keys `ID_A`.
2. **Execute Cross-Tenant Matrix as `User B` (`Tenant B`):**
   - For every `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` route, substitute `ID_A` both as the primary URL parameter (`/api/issues/{ID_A}`) and as every foreign-key field in JSON payloads (`{ "projectId": "{ID_A}", "parentId": "{ID_A}" }`).
   - Also send the exact same requests using a freshly generated random UUID `ID_NONEXISTENT`.
   - Send every request again with `X-Org-Id: <tenant A>`, an `active_org=<tenant A>` cookie and `?org=<tenant A>`.
3. **Pass Criteria:**
   - Zero responses contain `flag{UUID}` or match `SHA-256(flag)`.
   - Modifying `User A`'s database state via `User B`'s requests fails 100% of the time (`User A` re-reads its records and verifies zero mutations, using a database-level diff, not only the API).
   - For every route, `status(ID_A) === status(ID_NONEXISTENT) === 404` and error response schemas and headers match identically.
4. **Query-log oracle (no LLM, catches empty-table and masked cases):** run the same matrix with the driver hook from [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md#7-the-deterministic-sql-query-log-tenant-predicate-oracle) and fail on any statement against a tenant table whose tenant predicate is not bound to Tenant B. See also [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md) and [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md).

## 7. How to Eliminate the Bug Class by Construction

1. **Hide the Raw Database Connection from Route Handlers:** Do not export `db` to `src/app/api/**` or `src/routes/**`. Export only repository functions or a `ScopedDb(scope: TenantScope)` wrapper created after authentication ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
2. **Always Validate Foreign Keys Inside the Same `tenant_id`:** Any `INSERT` or `UPDATE` that accepts a foreign key (`project_id`, `team_id`, `attachment_id`, `parent_id`) must verify in the same SQL statement (`EXISTS (SELECT 1 FROM parent WHERE id = $fk AND tenant_id = $tenant)`) that the referenced object belongs to the caller's tenant; back it with composite `(tenant_id, parent_id)` foreign keys.
3. **Standardize a Single `notFoundResponse()` Helper:** Use one `notFound()` response helper for both "row not found" and "row outside caller's scope" so status codes, headers, and JSON error keys never diverge.
4. **Derive the active tenant from a live membership row** and mint the scope in exactly one place; ban `x-org-id`-style reads outside it.
5. **Close the "new table" gap mechanically:** catalog test + import-boundary lint + query-log oracle (all specified in [`scoped-db.md`](../../strategy/scoped-db.md)).
