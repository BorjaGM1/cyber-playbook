# `ScopedDb`: The Keystone Reference Implementation for Application-Layer Tenancy

[`principles.md`](principles.md) (Principle 2 and 3) and almost every note in [`../1-known-vulnerabilities/`](../1-known-vulnerabilities/README.md) say "enforce tenancy through a typed `ScopedDb(scope)` handle". This file is that handle. It specifies what the handle must guarantee, gives a TypeScript and a Rust reference implementation, and defines the three deterministic checks that stop the classic failure ("someone added a table or a query and forgot the tenant predicate") **without any database-side policy machinery**:

1. a **schema-introspection CI test** (a table that carries a tenant column, or is FK-derived from one, cannot exist unless it is registered in `ScopedDb` or explicitly reviewed);
2. an **import-boundary lint** (route handlers cannot import the raw database handle);
3. the **SQL query-log tenant-predicate oracle** (a no-LLM check that executes the routes as Tenant B and flags every statement against a tenant table that is not bound to Tenant B).

---

## 1. What the Handle Must Guarantee

| # | Guarantee | Mechanism |
|---|-----------|-----------|
| G1 | A handler can only obtain a `ScopedDb` from a `TenantScope` that the auth layer minted from a verified credential. | Nominal scope types, minted only inside `src/auth/`. |
| G2 | Every `SELECT`/`UPDATE`/`DELETE` on a registered table carries `tenant_id = scope.tenantId` (and the guest project predicate when the scope is a guest). | Query builders inject it; callers never write it. |
| G3 | Every `INSERT`/`UPDATE` that sets a foreign key proves in the **same statement** that the referenced row belongs to the same tenant (and, for guests, to an allowed project). | `EXISTS` sub-select generated from the registry's `fks` map. |
| G4 | Every joined tenant table receives the same predicate. | Join helper adds the predicate to the `ON` clause. |
| G5 | No caller-supplied `tenant_id`, no mass assignment. | Column allowlists (`insertable`, `mutable`, `guestMutable`) per table. |
| G6 | Raw SQL is impossible except for named, CI-parsed queries that bind `:tenant`. | Raw-query registry. |
| G7 | Cross-tenant work (cron, migrations, billing reconciliation) goes through an audited `SystemScope` that cannot be reached from a request. | Allowlisted callers, audit row, request-context guard. |
| G8 | A new table cannot silently bypass G2–G6. | Schema-introspection CI test + import boundary + query-log oracle. |

Defence in depth for the tenant boundary comes from layers **inside the application and schema** (typed scope, registry, composite foreign keys, lint, oracles). This playbook does not use database-side row policies as a control; see [Section 8](#8-why-this-replaces-a-database-side-safety-net).

---

## 2. TypeScript Reference Implementation (Kysely)

### 2.1 Scope types (`src/auth/scope.ts`): the only module that mints scopes

Honest limit up front: **TypeScript cannot make a constructor truly private at runtime.** `private constructor` is compile-time only, and `as any` defeats it. The design below therefore stacks three things: a private `#brand` field (so the type is nominal and cannot be forged structurally), minting via a function captured in a `static` block (so there is no public `new`), and a lint rule that bans importing the minting function anywhere except the auth middleware. Treat the lint rule and the query-log oracle as the enforcement; the types are the ergonomic guide.

```typescript
// src/auth/scope.ts
import type { VerifiedSession, LiveMembership } from "./verify";

let mintMember!: (m: LiveMembership) => FullMemberScope;
let mintGuest!: (m: LiveMembership) => ProjectGuestScope;

export class FullMemberScope {
  readonly kind = "member" as const;
  readonly #brand = true; // makes the type nominal: object literals cannot satisfy it

  private constructor(
    readonly tenantId: string,
    readonly actorId: string,
    readonly role: "owner" | "member"
  ) {}

  static {
    mintMember = (m) => new FullMemberScope(m.tenantId, m.actorId, m.role as "owner" | "member");
  }
}

export class ProjectGuestScope {
  readonly kind = "guest" as const;
  readonly #brand = true;

  private constructor(
    readonly tenantId: string,
    readonly actorId: string,
    readonly allowedProjectIds: ReadonlySet<string>
  ) {}

  static {
    mintGuest = (m) => new ProjectGuestScope(m.tenantId, m.actorId, new Set(m.projectGrants));
  }
}

export type TenantScope = FullMemberScope | ProjectGuestScope;

/**
 * The ONLY minting function. Lint rule `no-scope-mint-outside-auth` (Section 6) restricts
 * importers to `src/auth/middleware.ts` and `src/jobs/scope-rehydrate.ts`.
 * `membership` MUST be loaded live from the database (not from a cookie claim) so revocation
 * and project-grant changes apply on the next request.
 */
export function scopeFromVerifiedSession(session: VerifiedSession, membership: LiveMembership): TenantScope {
  if (membership.userId !== session.sub || membership.revokedAt !== null) {
    throw new Error("SCOPE_DENIED");
  }
  return membership.role === "guest" ? mintGuest(membership) : mintMember(membership);
}
```

The active tenant is **never** taken from `X-Org-Id`, a cookie or a body field. `LiveMembership` is the result of `SELECT … FROM org_members WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL` where `$2` is the *requested* org; no row means the request is rejected (see [`cross-tenant-idor-and-explicit-scoping.md`](../1-known-vulnerabilities/authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md)).

### 2.2 The table registry (`src/db/registry.ts`)

The registry is the single source of truth that the CI test compares against the real schema.

```typescript
// src/db/registry.ts
export interface TableSpec {
  readonly tenantCol: string;                      // column holding the owning tenant
  readonly projectCol?: string;                    // column used for guest project scoping
  readonly deletedCol?: string;                    // soft-delete column, always filtered
  readonly fks: Readonly<Record<string, TableName>>; // fk column -> referenced registered table
  readonly insertable: readonly string[];
  readonly mutable: readonly string[];             // columns a full member may update
  readonly guestMutable: readonly string[];        // columns a guest may update ([] = read-only)
  readonly types: Readonly<Record<string, string>>; // pg type per insertable column, for casts
}

export const TABLES = {
  projects: {
    tenantCol: "tenant_id", projectCol: "id", deletedCol: "archived_at",
    fks: {}, insertable: ["id", "name"], mutable: ["name"], guestMutable: [],
    types: { id: "uuid", name: "text" },
  },
  issues: {
    tenantCol: "tenant_id", projectCol: "project_id", deletedCol: "deleted_at",
    fks: { project_id: "projects" },
    insertable: ["id", "project_id", "title", "description"],
    mutable: ["title", "description", "project_id", "status"],
    guestMutable: ["title", "description"],          // a guest can edit text, never move an issue
    types: { id: "uuid", project_id: "uuid", title: "text", description: "text" },
  },
  comments: {
    tenantCol: "tenant_id", projectCol: "project_id", deletedCol: "deleted_at",
    fks: { issue_id: "issues", project_id: "projects" },
    insertable: ["id", "issue_id", "project_id", "body"],
    mutable: ["body"], guestMutable: ["body"],
    types: { id: "uuid", issue_id: "uuid", project_id: "uuid", body: "text" },
  },
} as const satisfies Record<string, TableSpec>;

export type TableName = keyof typeof TABLES;

/** Reviewed exceptions: tables that carry a tenant column but are intentionally not reachable via ScopedDb. */
export const REVIEWED_ALLOWLIST: ReadonlyArray<{
  table: string; reason: string; reviewedBy: string; expires: string; // ISO date, CI fails after this
}> = [
  { table: "audit_log", reason: "append-only; written via SystemScope, read via AuditReader", reviewedBy: "security-owner", expires: "2027-06-30" },
];
```

Child tables **carry their own tenant column** and reference the parent with a **composite foreign key** `(tenant_id, parent_id) REFERENCES parent (tenant_id, id)`. This is a plain relational constraint, not a policy: a comment in Tenant B pointing at an issue in Tenant A becomes unrepresentable at the storage layer even if a query is wrong.

```sql
ALTER TABLE issues  ADD CONSTRAINT issues_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE projects ADD CONSTRAINT projects_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE issues  ADD CONSTRAINT issues_project_fk
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id);
ALTER TABLE comments ADD CONSTRAINT comments_issue_fk
  FOREIGN KEY (tenant_id, issue_id) REFERENCES issues (tenant_id, id);
```

### 2.3 `ScopedDb` (`src/db/scoped.ts`)

Types are simplified with `any` at the Kysely boundary for readability; a production version derives column types from the generated `DB` interface.

```typescript
// src/db/scoped.ts
import { sql, CompiledQuery, type Expression, type ExpressionBuilder, type SqlBool } from "kysely";
import { rawDb } from "./raw";                  // lint: importable ONLY from src/db/** and src/jobs/system-scope.ts
import { TABLES, type TableName, type TableSpec } from "./registry";
import { RAW_QUERIES, type RawQueryName } from "./raw-queries";
import type { TenantScope } from "../auth/scope";

export class ScopedDb {
  readonly #brand = true;
  private constructor(readonly scope: TenantScope) {}

  static forScope(scope: TenantScope): ScopedDb {
    return new ScopedDb(scope);
  }

  /** Predicate every read/write of `table` must satisfy (G2). */
  visible(eb: ExpressionBuilder<any, any>, table: TableName, alias: string = table): Expression<SqlBool> {
    const spec: TableSpec = TABLES[table];
    const preds: Expression<SqlBool>[] = [eb(`${alias}.${spec.tenantCol}`, "=", this.scope.tenantId)];
    if (spec.deletedCol) preds.push(eb(`${alias}.${spec.deletedCol}`, "is", null));
    if (this.scope.kind === "guest" && spec.projectCol) {
      // `IN ()` is invalid SQL, and an empty grant set must mean "sees nothing".
      preds.push(
        this.scope.allowedProjectIds.size === 0
          ? sql<SqlBool>`false`
          : eb(`${alias}.${spec.projectCol}`, "in", [...this.scope.allowedProjectIds])
      );
    }
    return eb.and(preds);
  }

  select(table: TableName, alias: string = table) {
    return rawDb
      .selectFrom(`${table} as ${alias}` as any)
      .where((eb: ExpressionBuilder<any, any>) => this.visible(eb, table, alias));
  }

  /** Joins (G4): the visibility predicate of the joined table goes into the ON clause. */
  joinScoped(qb: any, table: TableName, alias: string, on: (eb: ExpressionBuilder<any, any>) => Expression<SqlBool>) {
    return qb.innerJoin(`${table} as ${alias}`, (join: any) =>
      join.on(on).on((eb: ExpressionBuilder<any, any>) => this.visible(eb, table, alias))
    );
  }

  /** Aggregates must be built from the same predicate; there is no unscoped count(). */
  async count(table: TableName): Promise<number> {
    const row = await this.select(table).select((eb: any) => eb.fn.countAll().as("n")).executeTakeFirstOrThrow();
    return Number((row as any).n);
  }

  /** G3 + G5: tenant column forced, columns allowlisted, FK targets proven in the same statement. */
  async insert(table: TableName, values: Record<string, unknown>) {
    const spec: TableSpec = TABLES[table];
    this.assertColumns(values, spec.insertable);
    if (this.scope.kind === "guest" && spec.guestMutable.length === 0) throw new Error("SCOPE_READ_ONLY");

    const cols = Object.keys(values);
    const selectList = [
      sql`${this.scope.tenantId}::uuid`,
      ...cols.map((c) => sql`${values[c]}::${sql.raw(spec.types[c])}`), // types come from the registry, never from callers
    ];
    const existsChecks = Object.entries(spec.fks)
      .filter(([col]) => col in values)
      .map(([col, parent]) => sql`EXISTS (
        SELECT 1 FROM ${sql.table(parent)} AS p
         WHERE p.id = ${values[col]}::uuid AND ${this.visibleRaw(parent, "p")}
      )`);

    const result = await sql<any>`
      INSERT INTO ${sql.table(table)} (${sql.join([spec.tenantCol, ...cols].map((c) => sql.ref(c)))})
      SELECT ${sql.join(selectList)}
       WHERE ${existsChecks.length ? sql.join(existsChecks, sql` AND `) : sql`true`}
      RETURNING *`.execute(rawDb);
    return result.rows[0] ?? null; // null => parent not in scope => caller maps to 404
  }

  /** G3 + G5: guest scope can only touch guestMutable columns; FK retargets are proven in-statement. */
  async update(table: TableName, id: string, patch: Record<string, unknown>) {
    const spec: TableSpec = TABLES[table];
    const allowed = this.scope.kind === "guest" ? spec.guestMutable : spec.mutable;
    this.assertColumns(patch, allowed);

    let qb: any = rawDb
      .updateTable(table as any)
      .set(patch)
      .where((eb: any) => eb.and([eb(`${table}.id`, "=", id), this.visible(eb, table)]));

    for (const [col, parent] of Object.entries(spec.fks)) {
      if (!(col in patch)) continue;
      qb = qb.where((eb: any) =>
        eb.exists(
          eb.selectFrom(`${parent} as fk_${parent}`)
            .select(sql.lit(1).as("one"))
            .where(`fk_${parent}.id`, "=", patch[col])
            .where((e2: any) => this.visible(e2, parent, `fk_${parent}`))
        )
      );
    }
    return (await qb.returningAll().executeTakeFirst()) ?? null; // null => 404, never 403
  }

  async delete(table: TableName, id: string) {
    if (this.scope.kind === "guest") throw new Error("SCOPE_READ_ONLY");
    return (
      (await rawDb
        .deleteFrom(table as any)
        .where((eb: any) => eb.and([eb(`${table}.id`, "=", id), this.visible(eb, table)]))
        .returning("id" as any)
        .executeTakeFirst()) ?? null
    );
  }

  /** G6: raw SQL only by registered name; `:tenant` and `:allowed_projects` are bound here, never by callers. */
  async named<T>(name: RawQueryName, params: Record<string, unknown> = {}): Promise<T[]> {
    const q = RAW_QUERIES[name];
    if ("tenant" in params || "allowed_projects" in params) throw new Error("RESERVED_PARAM");
    const bound: Record<string, unknown> = {
      ...params,
      tenant: this.scope.tenantId,
      allowed_projects: this.scope.kind === "guest" ? [...this.scope.allowedProjectIds] : null,
    };
    const values: unknown[] = [];
    const text = q.text.replace(/(?<!:):([a-z_]+)/g, (_m, p: string) => { // lookbehind skips `::uuid` casts
      if (!(p in bound)) throw new Error(`MISSING_PARAM:${p}`);
      values.push(bound[p]);
      return `$${values.length}`;
    });
    // `text` is a registered, CI-parsed constant; only `values` vary, and they travel as driver parameters.
    const res = await rawDb.executeQuery<T>(CompiledQuery.raw(text, values));
    return res.rows as T[];
  }

  private visibleRaw(table: TableName, alias: string) {
    const spec: TableSpec = TABLES[table];
    const parts = [sql`${sql.ref(`${alias}.${spec.tenantCol}`)} = ${this.scope.tenantId}::uuid`];
    if (spec.deletedCol) parts.push(sql`${sql.ref(`${alias}.${spec.deletedCol}`)} IS NULL`);
    if (this.scope.kind === "guest" && spec.projectCol) {
      parts.push(sql`${sql.ref(`${alias}.${spec.projectCol}`)} = ANY(${[...this.scope.allowedProjectIds]}::uuid[])`);
    }
    return sql.join(parts, sql` AND `);
  }

  private assertColumns(values: Record<string, unknown>, allowed: readonly string[]) {
    for (const k of Object.keys(values)) {
      if (!allowed.includes(k)) throw new Error(`COLUMN_NOT_ALLOWED:${k}`); // blocks tenant_id, role, plan, balance...
      if (values[k] === undefined) throw new Error(`UNDEFINED_VALUE:${k}`);  // the undefined-predicate trap
    }
  }
}
```

`:name` placeholders are rewritten to positional `$n` parameters (a repeated name is bound again per occurrence, which is correct if wasteful). The registry check below is what guarantees the text itself is safe.

**Raw-query registry (`src/db/raw-queries.ts`).**

```typescript
export const RAW_QUERIES = {
  issueBurndown: {
    text: `SELECT date_trunc('day', i.closed_at) AS day, count(*) AS closed
             FROM issues i
            WHERE i.tenant_id = :tenant
              AND i.deleted_at IS NULL
              AND (:allowed_projects::uuid[] IS NULL OR i.project_id = ANY(:allowed_projects::uuid[]))
              AND i.closed_at >= :since
            GROUP BY 1 ORDER BY 1`,
  },
} as const;
export type RawQueryName = keyof typeof RAW_QUERIES;
```

CI parses every entry with a real SQL parser (`libpg-query` for Postgres) and fails unless **every** reference to a registered tenant table in `FROM`/`JOIN`/sub-selects has a top-level `AND`-conjunct `alias.tenant_col = :tenant` (and a guest-project conjunct if the table has a `projectCol`). Aggregates, window functions and CTEs are therefore allowed, but only if each tenant table inside them is individually predicated.

### 2.4 Pagination

```typescript
import { signPurposeBoundToken, verifyPurposeBoundToken } from "../auth/tokens";

export function paginate(qb: any, scope: TenantScope, opts: { limit?: number; cursor?: string; orderKey: string }) {
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 100);   // clamp
  let q = qb.orderBy(opts.orderKey).orderBy("id").limit(limit + 1);
  if (opts.cursor) {
    const c = verifyPurposeBoundToken("page_cursor:v1", opts.cursor, process.env.CURSOR_SECRET!);
    if (!c || c.scopeHash !== scopeHash(scope)) throw new Error("BAD_CURSOR"); // cursor from another actor/scope is rejected
    q = q.where(sql`(${sql.ref(opts.orderKey)}, id)`, ">", sql`(${c.lastKey}, ${c.lastId})`);
  }
  return q;
}
```

The `orderKey` comes from an allowlist map (see [`sql-and-query-construction.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/sql-and-query-construction.md)); the cursor is bound to the scope so it cannot be replayed across actors.

### 2.5 `SystemScope`: the audited escape hatch (`src/jobs/system-scope.ts`)

Some work is legitimately cross-tenant (retention sweeps, billing reconciliation, search reindex, migrations). It must be **loud, narrow and unreachable from request handlers**.

```typescript
// src/jobs/system-scope.ts  (lint: importable only from src/jobs/** and src/cli/**)
import { AsyncLocalStorage } from "node:async_hooks";
import { requestContext } from "../http/request-context"; // an AsyncLocalStorage set by the router for every inbound request
import { auditDb } from "./audit-db";                     // separate connection; INSERT-only credentials

export const SYSTEM_CALLERS = ["retention-sweeper", "billing-reconciler", "search-reindexer"] as const;
export type SystemCaller = (typeof SYSTEM_CALLERS)[number];

export async function withSystemScope<T>(
  caller: SystemCaller,
  reason: string,
  fn: (sys: SystemDb) => Promise<T>
): Promise<T> {
  if (requestContext.getStore() !== undefined) throw new Error("SYSTEM_SCOPE_IN_REQUEST_CONTEXT"); // reachable only from jobs
  if (!SYSTEM_CALLERS.includes(caller)) throw new Error("SYSTEM_CALLER_NOT_ALLOWLISTED");
  if (reason.trim().length < 10) throw new Error("SYSTEM_SCOPE_REASON_REQUIRED");

  const runId = crypto.randomUUID();
  await auditDb.insertInto("system_scope_audit").values({ run_id: runId, caller, reason, started_at: new Date() }).execute();
  try {
    return await fn(new SystemDb(caller, runId));
  } finally {
    await auditDb.updateTable("system_scope_audit").set({ finished_at: new Date() }).where("run_id", "=", runId).execute();
  }
}

class SystemDb {
  constructor(readonly caller: SystemCaller, readonly runId: string) {}

  /** Preferred: act on exactly one tenant with that tenant's registered scope shape. Each call is audited. */
  async forTenant(tenantId: string, why: string): Promise<ScopedDb> {
    await auditDb.insertInto("system_scope_tenant_access").values({ run_id: this.runId, tenant_id: tenantId, why }).execute();
    return ScopedDb.forScope(await systemMemberScope(tenantId)); // minted via a second, jobs-only mint in src/auth
  }
}
```

Rules: no `SystemScope` import under `src/routes/**`, `src/app/**` or `src/mcp/**`; the audit table is append-only and reviewed; every use needs a one-line reason; a request-context guard is a runtime backstop in case lint is bypassed.

---

## 3. Rust Reference Implementation (`sqlx`)

Rust gives what TypeScript cannot: field privacy and `pub(in path)` visibility make forging a scope a compile error.

```rust
// src/auth/scope.rs
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role { Owner, Member }

pub struct FullMemberScope { tenant_id: Uuid, actor_id: Uuid, role: Role }   // private fields: no struct literals outside this module
pub struct ProjectGuestScope { tenant_id: Uuid, actor_id: Uuid, allowed_projects: Vec<Uuid> }

pub enum Scope { Member(FullMemberScope), Guest(ProjectGuestScope) }

impl FullMemberScope {
    pub(in crate::auth) fn new(tenant_id: Uuid, actor_id: Uuid, role: Role) -> Self { Self { tenant_id, actor_id, role } }
    pub fn tenant_id(&self) -> Uuid { self.tenant_id }
    pub fn role(&self) -> Role { self.role }
}
impl ProjectGuestScope {
    pub(in crate::auth) fn new(tenant_id: Uuid, actor_id: Uuid, allowed_projects: Vec<Uuid>) -> Self {
        Self { tenant_id, actor_id, allowed_projects }
    }
    pub fn tenant_id(&self) -> Uuid { self.tenant_id }
    pub fn allowed_projects(&self) -> &[Uuid] { &self.allowed_projects }
}

/// Shared read surface: (tenant, is_full_member, allowed_projects)
pub trait ScopeLike {
    fn tenant_id(&self) -> Uuid;
    fn visibility(&self) -> (bool, Vec<Uuid>);
}
impl ScopeLike for FullMemberScope {
    fn tenant_id(&self) -> Uuid { self.tenant_id }
    fn visibility(&self) -> (bool, Vec<Uuid>) { (true, vec![]) }
}
impl ScopeLike for ProjectGuestScope {
    fn tenant_id(&self) -> Uuid { self.tenant_id }
    fn visibility(&self) -> (bool, Vec<Uuid>) { (false, self.allowed_projects.clone()) }
}
```

```rust
// src/db/scoped.rs
use sqlx::PgPool;
use uuid::Uuid;
use crate::auth::scope::{FullMemberScope, ScopeLike};

pub struct Scoped<'a, S: ScopeLike> {
    pool: &'a PgPool,          // private; the pool field of AppState is pub(in crate::db), so handlers cannot reach it
    scope: &'a S,
}

impl<'a, S: ScopeLike> Scoped<'a, S> {
    pub(in crate::auth) fn new(pool: &'a PgPool, scope: &'a S) -> Self { Self { pool, scope } }

    /// Reads exist for every scope type; the guest predicate is part of the statement.
    pub async fn issue_by_id(&self, id: Uuid) -> Result<Option<Issue>, sqlx::Error> {
        let (is_member, projects) = self.scope.visibility();
        sqlx::query_as::<_, Issue>(
            "SELECT id, tenant_id, project_id, title FROM issues
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
                AND ($3 OR project_id = ANY($4))",
        )
        .bind(id).bind(self.scope.tenant_id()).bind(is_member).bind(projects)
        .fetch_optional(self.pool).await
    }
}

/// Moves exist ONLY on the full-member instantiation: a guest scope has no `move_issue` method to call.
impl<'a> Scoped<'a, FullMemberScope> {
    pub async fn move_issue(&self, issue_id: Uuid, target_project: Uuid) -> Result<Option<Issue>, sqlx::Error> {
        sqlx::query_as::<_, Issue>(
            "UPDATE issues AS i SET project_id = $1, updated_at = now()
              WHERE i.id = $2 AND i.tenant_id = $3 AND i.deleted_at IS NULL
                AND EXISTS (SELECT 1 FROM projects p
                             WHERE p.id = $1 AND p.tenant_id = $3 AND p.archived_at IS NULL)
          RETURNING i.id, i.tenant_id, i.project_id, i.title",
        )
        .bind(target_project).bind(issue_id).bind(self.scope.tenant_id())
        .fetch_optional(self.pool).await // None => 404
    }
}
```

```rust
// src/jobs/system_scope.rs
pub enum SystemCaller { RetentionSweeper, BillingReconciler, SearchReindexer }

pub struct SystemScope { run_id: Uuid, caller: SystemCaller }

impl SystemScope {
    /// Only the jobs module can start one; writes the audit row before returning.
    pub(in crate::jobs) async fn begin(audit: &PgPool, caller: SystemCaller, reason: &'static str) -> Result<Self, sqlx::Error> {
        let run_id = Uuid::new_v4();
        sqlx::query("INSERT INTO system_scope_audit (run_id, caller, reason, started_at) VALUES ($1,$2,$3,now())")
            .bind(run_id).bind(caller.as_str()).bind(reason).execute(audit).await?;
        Ok(Self { run_id, caller })
    }
}
```

Enforcement in Rust: `clippy.toml` with `disallowed-methods` for `sqlx::query`, `sqlx::query_as` and `sqlx::query_scalar` outside `crate::db` (via `#![deny(clippy::disallowed_methods)]` in `src/routes/`), and `pub(in crate::db)` on the pool accessor. The query-log oracle (Section 7) covers anything the compiler cannot.

---

## 4. The CI Catalog Test: "Every Tenant Table Is Reachable Only via `ScopedDb`"

This is the answer to "what stops a developer from adding `CREATE TABLE issue_attachments` and forgetting the tenant predicate?" The test introspects the **real migrated schema** and fails CI if the registry and reality disagree.

```typescript
// test/scoped-db-catalog.test.ts  (run against a freshly migrated Postgres in CI)
import { describe, it, expect } from "vitest";
import { TABLES, REVIEWED_ALLOWLIST } from "../src/db/registry";
import { rawDb } from "../src/db/raw";
import { sql } from "kysely";

const TENANT_COLS = ["tenant_id", "org_id", "workspace_id"];

async function relationsWithTenantColumn() {
  // r=table, p=partitioned, v=view, m=materialized view, f=foreign table. Views and matviews are NOT exempt.
  const { rows } = await sql<{ relname: string; relkind: string; attname: string }>`
    SELECT c.relname, c.relkind, a.attname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
     WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','f')
       AND a.attname = ANY(${TENANT_COLS})`.execute(rawDb);
  return rows;
}

async function foreignKeys() {
  const { rows } = await sql<{ child: string; parent: string; cols: string[] }>`
    SELECT cl.relname AS child, pl.relname AS parent, array_agg(a.attname ORDER BY k.ord) AS cols
      FROM pg_constraint c
      JOIN pg_class cl ON cl.oid = c.conrelid
      JOIN pg_class pl ON pl.oid = c.confrelid
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.contype = 'f' AND n.nspname = 'public'
     GROUP BY c.oid, cl.relname, pl.relname`.execute(rawDb);
  return rows;
}

describe("ScopedDb catalog invariants", () => {
  const registered = new Set<string>(Object.keys(TABLES));
  const allowlisted = new Set(REVIEWED_ALLOWLIST.map((a) => a.table));

  it("every relation with a tenant column is registered or reviewed", async () => {
    const tenantish = new Set((await relationsWithTenantColumn()).map((r) => r.relname));
    const unregistered = [...tenantish].filter((t) => !registered.has(t) && !allowlisted.has(t));
    expect(unregistered, `Unregistered tenant relations: ${unregistered.join(", ")}. Add to src/db/registry.ts or REVIEWED_ALLOWLIST.`).toEqual([]);
  });

  it("every relation FK-derived from a tenant relation is registered or reviewed", async () => {
    const fks = await foreignKeys();
    const derived = new Set((await relationsWithTenantColumn()).map((r) => r.relname));
    let grew = true;
    while (grew) {
      grew = false;
      for (const fk of fks) {
        if (derived.has(fk.parent) && !derived.has(fk.child)) { derived.add(fk.child); grew = true; }
      }
    }
    const missing = [...derived].filter((t) => !registered.has(t) && !allowlisted.has(t));
    expect(missing, `FK-derived tenant data not registered: ${missing.join(", ")}`).toEqual([]);
  });

  it("registry matches the real schema and each declared fk is a COMPOSITE foreign key including the tenant column", async () => {
    const fks = await foreignKeys();
    for (const [table, spec] of Object.entries(TABLES)) {
      for (const [col, parent] of Object.entries(spec.fks)) {
        const fk = fks.find((f) => f.child === table && f.parent === parent && f.cols.includes(col));
        expect(fk, `${table}.${col} -> ${parent} has no FK`).toBeTruthy();
        expect(fk!.cols, `${table}.${col} FK must include ${spec.tenantCol} (composite)`).toContain(spec.tenantCol);
      }
    }
    const real = new Set((await relationsWithTenantColumn()).map((r) => r.relname));
    for (const t of registered) expect(real.has(t), `registry lists ${t} but schema has no such tenant relation`).toBe(true);
  });

  it("reviewed allowlist entries have not expired", () => {
    for (const a of REVIEWED_ALLOWLIST) {
      expect(new Date(a.expires).getTime(), `allowlist entry ${a.table} expired ${a.expires}`).toBeGreaterThan(Date.now());
    }
  });
});
```

SQLite/D1 variant: replace the catalog queries with `SELECT name, type FROM sqlite_master WHERE type IN ('table','view')`, `PRAGMA table_info(<name>)` for the tenant-column scan, and `PRAGMA foreign_key_list(<name>)` for the FK graph. With Drizzle, additionally iterate the exported schema objects (`getTableConfig`) so a table in the TS schema that is missing from the migration set, or vice versa, also fails.

### 4.1 Import-boundary lint

```jsonc
// .eslintrc overrides (or the equivalent dependency-cruiser "forbidden" rules)
{
  "overrides": [
    {
      "files": ["src/routes/**", "src/app/**", "src/actions/**", "src/mcp/**"],
      "rules": {
        "no-restricted-imports": ["error", {
          "patterns": [
            { "group": ["**/db/raw", "**/db/raw.ts"], "message": "Raw DB handle is forbidden in request code. Use ScopedDb." },
            { "group": ["**/jobs/system-scope*"], "message": "SystemScope is not reachable from request code." },
            { "group": ["**/auth/scope"], "importNames": ["scopeFromVerifiedSession"], "message": "Only auth middleware mints scopes." }
          ]
        }]
      }
    }
  ]
}
```

Companion ast-grep/Semgrep-style rule, so the ban also holds for dynamic and re-exported paths:

```yaml
# rules/no-raw-sql-outside-db.yml  (ast-grep)
id: no-raw-sql-outside-db
language: typescript
severity: error
rule:
  any:
    - pattern: sql.raw($$$)
    - pattern: $X.executeQuery($$$)
    - pattern: $X.$METHOD(`$$$`)   # template-literal passed to a query/execute method
      inside: { kind: call_expression }
constraints:
  METHOD: { regex: "^(query|execute|raw|unsafe)$" }
files: ["src/**"]
ignores: ["src/db/**", "src/jobs/system-scope.ts", "test/**"]
```

---

## 5. Policy Engine Option (Single Decision Point)

If the guest/project/role hierarchy outgrows hand-written predicates, make the decision explicit rather than scattered: expose exactly two functions and implement both from one policy source (a Cedar/OpenFGA-style relationship model that lives in application code and is evaluated by the app):

```typescript
interface Policy {
  can(scope: TenantScope, action: "read" | "write" | "move" | "delete", resource: { type: string; id: string }): Promise<boolean>;
  /** Compiles the same rules into a predicate over a table alias; used by ScopedDb.visible(). */
  listVisible(scope: TenantScope, type: string): (eb: ExpressionBuilder<any, any>, alias: string) => Expression<SqlBool>;
}
```

`ScopedDb.visible()` calls `listVisible`, point lookups call `can`, and a **property test asserts `can(x) ⇔ x ∈ listVisible`** for generated actors and resources. That equivalence test is the equivalent of the surface-parity oracle ([`differential-and-side-door-oracles.md`](../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md)) at the policy layer, and policy-language tooling can analyse the rules (for example, "can a guest ever `move`?") before any code runs. The cost is a new DSL and an evaluation hot path; adopt it when you have more than roughly three scope kinds or per-resource sharing.

---

## 6. Where the Handle Is Used (Hardened Callers)

```typescript
export async function moveIssueRoute(req: Request, ctx: { db: ScopedDb; scope: FullMemberScope }) {
  const { issueId, targetProjectId } = MoveSchema.parse(await readBoundedJson(req, 4096)); // .strict()
  const row = await ctx.db.update("issues", issueId, { project_id: targetProjectId });
  return row ? Response.json({ id: row.id }) : notFound();   // missing, other tenant, hidden project, bad target: one 404
}
```

A guest cannot reach this route's type (`FullMemberScope`), and even if it could, `ScopedDb.update` rejects `project_id` for guest scopes because `guestMutable` excludes it.

---

## 7. The Deterministic SQL Query-Log Tenant-Predicate Oracle

Canary tests only fail when the leaked row happens to exist and be returned. A query with a missing predicate on an **empty table**, or one that is masked by a later in-memory filter, passes every canary test while being one seed row away from a breach. This oracle checks the SQL itself and needs no LLM. It is Step 1 of [`../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

**Protocol (runs in the isolated lab):**

1. Hook the driver so every statement is recorded with `{ text, values, route, actorLabel }`. For `pg`: wrap `Client.prototype.query`; for Kysely: the `log` option; for `sqlx`: the `tracing` statement logger or a `PgConnectOptions::log_statements` sink.
2. Authenticate as **Tenant B**, and optionally as `Guest G`, and call **every mapped route** (and every job and MCP tool) with realistic and with Tenant A's identifiers. Many calls return `404`; that is expected and irrelevant to the oracle.
3. Parse each recorded statement with the real Postgres parser (`libpg-query`, `sqlglot`, `pg_query`), resolve every range variable to a base relation, and for each **registered tenant relation** require a top-level conjunct `<alias>.<tenantCol> = <param>` where `values[param] === B.tenantId`. For tables with `projectCol` under a guest actor, additionally require a conjunct restricting to `G`'s allowed projects. For `INSERT`, require the tenant column value to equal `B.tenantId`.
4. Violations (a conservative rule, deliberately simple and deterministic):
   - a tenant relation with no matching conjunct;
   - the predicate appears only under an `OR`;
   - the bound value is not `B.tenantId` (including Tenant A's id, or a client-supplied value);
   - a statement against a tenant relation executed outside a registered `ScopedDb` call site (stack-tag check);
   - a view or materialized view with a tenant column that is read without the predicate.

```typescript
// scripts/query-log-oracle.mjs (core loop)
import { parseSync } from "libpg-query";

export function checkStatement({ text, values }, actor, registry) {
  const ast = parseSync(text);
  const violations = [];
  for (const ref of collectRangeVars(ast)) {                // { relname, alias, whereConjuncts }
    const spec = registry[ref.relname];
    if (!spec) continue;                                    // not a tenant table
    const hasTenant = ref.whereConjuncts.some((c) =>
      c.op === "=" && c.left === `${ref.alias}.${spec.tenantCol}` && c.param !== undefined && values[c.param - 1] === actor.tenantId);
    if (!hasTenant) violations.push({ relname: ref.relname, text, reason: "NO_TENANT_PREDICATE_BOUND_TO_ACTOR" });
    if (actor.kind === "guest" && spec.projectCol &&
        !ref.whereConjuncts.some((c) => c.left === `${ref.alias}.${spec.projectCol}` && coversOnly(c, values, actor.allowedProjectIds))) {
      violations.push({ relname: ref.relname, text, reason: "NO_GUEST_PROJECT_PREDICATE" });
    }
  }
  return violations;
}
```

This oracle is the reason the playbook can retire "reviewer remembers to check" from the threat model: a forgotten predicate on a brand-new table is detected on the first CI run that touches the route, and the guard-mutation self-test (delete one predicate from `ScopedDb.visible`; this oracle and the canary sweep must both go red) proves the oracle is not blind.

---

## 8. Why This Replaces a Database-Side Safety Net

The remaining failure mode people worry about is "the developer forgets a table or a predicate". Here is what covers that, layer by layer, with every layer living in code the reviewer and the agent can read:

| Failure | Control |
|---|---|
| New table added, nobody registers it | Catalog test fails CI (Section 4): unregistered tenant relation, FK-derived relation, view or matview. |
| Route imports the raw handle | Import-boundary lint + ast-grep rule fail CI (Section 4.1); in Rust, field privacy and `pub(in …)` fail the build. |
| Query builder bypass or hand-written SQL | Raw SQL only through the CI-parsed registry; the query-log oracle flags any statement lacking the actor-bound predicate (Section 7). |
| Child row points at another tenant's parent | Composite `(tenant_id, parent_id)` foreign keys make it unrepresentable at storage (Section 2.2); `ScopedDb` also proves it in-statement. |
| Guest widens to the full tenant | Distinct `ProjectGuestScope` type; moves exist only on `FullMemberScope`; `guestMutable` allowlist. |
| Cross-tenant job or cron | Signed scope envelope and audited `SystemScope`; see [`async-jobs-and-scope-propagation.md`](../1-known-vulnerabilities/authorization-and-tenancy/async-jobs-and-scope-propagation.md). |
| Cache or derived store ignores the tenant | Scoped cache keys and index hydration through `ScopedDb`; see [`cache-and-derived-data.md`](../1-known-vulnerabilities/authorization-and-tenancy/cache-and-derived-data.md). |
| The whole scheme silently stops working | Canary + differential oracles ([`differential-and-side-door-oracles.md`](../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md)) and the guard-mutation self-test. |

This also works unchanged on SQLite, D1, Turso, key-value stores, search indexes and object storage, which a single-engine mechanism cannot cover. Agent-facing tools (MCP, tool routers) must obtain a `ScopedDb` from the caller's scope like any other surface; see [`agentic-and-mcp-threats.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md).

---

## 9. Adoption Checklist

1. Put every tenant-owned table in `registry.ts` and add `(tenant_id, id)` unique keys plus composite FKs.
2. Delete every route-level import of the raw handle; make `ScopedDb` the only data access in `src/routes/**`, server actions and MCP tools.
3. Wire the catalog test into the pre-deploy gate ([`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md)).
4. Wire the query-log oracle into the lab sweep and run the guard-mutation self-test once per release.
5. Move cron, queue and migration code to `SystemScope` and the signed job envelope.
