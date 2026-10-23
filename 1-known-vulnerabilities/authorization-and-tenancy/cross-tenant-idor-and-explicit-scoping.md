# Cross-Tenant IDOR/BOLA & Why Explicit Scoping Beats Database RLS

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (OWASP ASVS `v5.0.0-8.1.1`, `8.2.1`, `8.2.2`, `8.3.1`).
- **Mechanism:** Broken Object Level Authorization (BOLA / IDOR) happens when an endpoint authenticates the caller (`User B` in `Tenant B`), reads a target resource identifier from the URL path, query string, or JSON body (`item_id`, `project_id`, `invoice_id`), and executes a read or write query filtered only by that primary key (`WHERE id = $1`) without binding the caller's authorized `tenant_id` (and project/role capability).
- **Secondary Mechanism (`403` vs. `404` Enumeration Oracle):** When a developer checks `if (resource.tenantId !== actor.tenantId) return res.status(403)`, an attacker can distinguish between an existing cross-tenant resource (`403 Forbidden`) and a non-existent resource (`404 Not Found`), leaking resource existence, active UUIDs, and timing metadata.

---

## 2. Why Relying on Database Row-Level Security (RLS) Fails in Practice

A common piece of generic advice is *"just turn on PostgreSQL Row-Level Security (RLS) and forget about tenant filtering in application code."* **Do not do this—not even in pure PostgreSQL applications.**

Relying on database RLS as your primary or mandatory isolation guard introduces four severe operational failure modes:
1. **Easy to Forget on New Tables (Silent Fail-Open):** In PostgreSQL, every new `CREATE TABLE` defaults to **RLS disabled**. If an engineer or coding agent adds a migration for `issue_comments` or `export_jobs` and forgets `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`, every query against that table returns rows across all tenants with zero compiler warnings.
2. **Hidden Outside the Code Under Review:** When access control lives in SQL migration files from six months ago rather than in the TypeScript/Rust repository method being modified, neither a human reviewer nor a static analyzer can tell by reading `db.query("SELECT * FROM invoices WHERE id = $1", [id])` whether that query is safe.
3. **Silently Bypassed by Roles & Connection Poolers:**
   - Any role with `BYPASSRLS`, superuser, or table ownership (unless `FORCE ROW LEVEL SECURITY` is set on every single table) ignores RLS policies completely.
   - In transaction-pooled environments (`PgBouncer`, Neon, Supavisor), session-level settings (`SET app.current_tenant_id = ...`) either fail or bleed across concurrent requests on the same pooled connection if `SET LOCAL` / `set_config(..., true)` is ever misused outside an explicit transaction block.
4. **Zero Protection for Non-Postgres Stores:** Application state rarely lives only in one Postgres instance. As soon as a route reads from SQLite/D1, Redis caches, search indexes, or S3/R2 object storage, engineers conditioned to rely on Postgres RLS write unscoped queries that immediately leak cross-tenant data.

**The Playbook Rule:** Enforce tenant and capability scoping **explicitly in application code by construction** (via typed `TenantScopedDb` capability handles where unscoped queries cannot be called), and verify isolation from the outside using an automated **Cross-Tenant Canary Harness**. If a team already uses Postgres RLS, treat it strictly as an optional secondary seatbelt—never as a substitute for explicit `WHERE tenant_id = ...` predicates in every query.

---

## 3. Where It Hides

- `PATCH`, `PUT`, and `DELETE` handlers that look up or mutate a child record by its UUID (`DELETE FROM comments WHERE id = $1`) assuming the UI only renders delete buttons on the owner's comments.
- Foreign-key attachment on create/update (`POST /api/issues` passing `{ projectId: "<victim_project_uuid>", assigneeId: "<victim_user_uuid>" }`), where the handler checks that the caller is in `Tenant B`, creates the issue in `Tenant B`, but links it to `Tenant A`'s `projectId` or `attachmentId`.
- Batch operations (`POST /api/items/bulk-delete` with `{ ids: [...] }`) that verify ownership of `ids[0]` and then execute `DELETE FROM items WHERE id = ANY($1)` across the whole array.

---

## 4. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Raw Database Client + `403` Enumeration Leak)

```typescript
// VULNERABLE:
// 1. Route handler has direct access to the global `db` pool.
// 2. Returns 403 when tenant_id mismatches, creating an existence oracle.
// 3. Update query forgets `AND tenant_id = $3` and fails to verify foreign-key `projectId` ownership!
export async function updateIssueVulnerable(req: Request, issueId: string, actor: { tenantId: string }) {
  const body = await req.json();

  const issue = await globalDb.queryOne("SELECT id, tenant_id FROM issues WHERE id = $1", [issueId]);
  if (!issue) {
    return new Response("Not found", { status: 404 });
  }
  if (issue.tenant_id !== actor.tenantId) {
    // Leak: tells attacker that `issueId` exists and belongs to another tenant!
    return new Response("Forbidden", { status: 403 });
  }

  // Bug: `body.projectId` is never verified to belong to `actor.tenantId`!
  await globalDb.execute(
    "UPDATE issues SET title = $1, project_id = $2 WHERE id = $3",
    [body.title, body.projectId, issueId]
  );
  return new Response("OK", { status: 200 });
}
```

### Hardened Pattern (TypeScript — Explicit Capability-Scoped Repository Handle + `404` Anti-Enumeration)

```typescript
// Only the auth middleware can instantiate `TenantScope` after verifying the token/session.
const TENant_SCOPE_BRAND = Symbol("TenantScope");

export class TenantScope {
  readonly [TENant_SCOPE_BRAND] = true;
  constructor(
    public readonly tenantId: string,
    public readonly actorId: string,
    public readonly role: "owner" | "member" | "guest",
    public readonly allowedProjectIds: ReadonlySet<string> | "ALL"
  ) {}

  public canAccessProject(projectId: string): boolean {
    return this.allowedProjectIds === "ALL" || this.allowedProjectIds.has(projectId);
  }
}

// Repository methods REQUIRE `scope: TenantScope` as their first parameter and bind
// `tenant_id` in every SELECT, INSERT, UPDATE, and DELETE statement, plus every FK join.
export class IssueRepository {
  constructor(private readonly db: SqlExecutor) {}

  async updateIssue(
    scope: TenantScope,
    issueId: string,
    input: { title: string; targetProjectId: string }
  ): Promise<{ id: string; title: string } | null> {
    if (!scope.canAccessProject(input.targetProjectId)) {
      // Return null -> maps to 404 Not Found (never 403)
      return null;
    }

    // Single atomic statement that:
    // 1. Filters the target issue by BOTH `id` AND `tenant_id` (and guest project scope).
    // 2. Verifies via an EXISTS subquery that `targetProjectId` ALSO belongs to `scope.tenantId`.
    const rows = await this.db.query<{ id: string; title: string }>(
      `UPDATE issues AS i
          SET title = $1,
              project_id = $2,
              updated_at = CURRENT_TIMESTAMP
        WHERE i.id = $3
          AND i.tenant_id = $4
          AND EXISTS (
                SELECT 1 FROM projects AS p
                 WHERE p.id = $2
                   AND p.tenant_id = $4
              )
      RETURNING i.id, i.title`,
      [input.title, input.targetProjectId, issueId, scope.tenantId]
    );

    if (rows.length === 0) {
      // Whether the issue UUID does not exist OR belongs to another tenant,
      // the caller receives the exact same null -> 404 Not Found response.
      return null;
    }
    return rows[0];
  }
}
```

---

## 5. How to Discover It Automatically

### A. Static AST / Grep Audit
Every SQL query or ORM call touching a tenant-owned table must bind `tenant_id` (or `org_id` / `workspace_id`). Scan for raw primary-key lookups missing a tenant predicate:

```bash
# Find SQL queries with `WHERE id =` that do not also include `tenant_id` or `org_id`:
rg -n -i 'WHERE\s+id\s*=' src/ | rg -v -i 'tenant_id|org_id|workspace_id|owner_id'
```

### B. Dynamic Attacker Test (Cross-Tenant Canary + `404` Indistinguishability Oracle)
1. **Seed Victim (`User A`, `Tenant A`):** Create one record of every entity type (`Project`, `Issue`, `Comment`, `Webhook`, `Attachment`) containing a unique canary `flag{UUID}` in its text fields. Record their primary keys `ID_A`.
2. **Execute Cross-Tenant Matrix as `User B` (`Tenant B`):**
   - For every `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` route, substitute `ID_A` both as the primary URL parameter (`/api/issues/{ID_A}`) and as every foreign-key field in JSON payloads (`{ "projectId": "{ID_A}", "parentId": "{ID_A}" }`).
   - Also send the exact same requests using a freshly generated random UUID `ID_NONEXISTENT`.
3. **Pass Criteria:**
   - Zero responses contain `flag{UUID}` or match `SHA-256(flag)`.
   - Modifying `User A`'s database state via `User B`'s requests fails 100% of the time (`User A` re-reads its records and verifies zero mutations).
   - For every route, `status(ID_A) === status(ID_NONEXISTENT) === 404` and error response schemas match identically.

---

## 6. How to Eliminate the Bug Class by Construction

1. **Hide the Raw Database Connection from Route Handlers:** Do not export `db` to `src/app/api/**` or `src/routes/**`. Export only repository functions or a `ScopedDb(scope: TenantScope)` wrapper created after authentication.
2. **Always Validate Foreign Keys Inside the Same `tenant_id`:** Any `INSERT` or `UPDATE` that accepts a foreign key (`project_id`, `team_id`, `attachment_id`, `parent_id`) must verify in the same SQL statement (`EXISTS (SELECT 1 FROM parent WHERE id = $fk AND tenant_id = $tenant)`) that the referenced object belongs to the caller's tenant.
3. **Standardize a Single `notFoundResponse()` Helper:** Use one `notFound()` response helper for both "row not found" and "row outside caller's scope" so status codes, headers, and JSON error keys never diverge.
