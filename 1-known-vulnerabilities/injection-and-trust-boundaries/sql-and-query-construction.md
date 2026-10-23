# SQL & Query Construction Guards (Tagged Templates, Dynamic Identifiers, Undefined Traps & ORM Operator Injection)

## 1. Attack Transcript

```text
# (a) Dynamic ORDER BY — time-based confirmation
$ time curl -s 'https://app.example.com/api/issues?sort=(CASE+WHEN+(SELECT+1)=1+THEN+pg_sleep(5)::text+ELSE+title+END)'
real 5.2s

# (b) ORM operator injection — the filter object arrives straight from the query string.
#     qs/Express turn bracket syntax into nested objects, so this is a *relation traversal*:
$ curl -s -H "Cookie: $B" \
   'https://app.example.com/api/issues?filter[creator][passwordHash][startsWith]=$argon2id$v=19$m=65536$a'
{"items":[{"id":"iss_17"}]}            # a hit: the first characters of the hash are right
$ curl -s -H "Cookie: $B" \
   'https://app.example.com/api/issues?filter[creator][passwordHash][startsWith]=$argon2id$v=19$m=65536$b'
{"items":[]}                           # no hit -> one-bit oracle per request, hash recovered character by character

# (c) The filter overrides the tenant predicate because it is spread LAST
$ curl -s -H "Cookie: $B" 'https://app.example.com/api/issues?filter[tenantId][not]=x'
{"items":[ ...every other tenant's issues... ]}

# (d) undefined parameter drops the WHERE key
$ curl -s -X DELETE -H "Cookie: $B" 'https://app.example.com/api/items'    # no ?id= at all
{"deleted":4812}                       # whole-tenant wipe: "id" was undefined and the predicate vanished
```

---

## 2. Spot the Bug

```typescript
export async function listIssues(
  tenantId: string,
  sortField = "created_at",
  sortDir = "DESC"
) {
  return rawDb.query(
    `SELECT id, title FROM issues WHERE tenant_id = $1 ORDER BY ${sortField} ${sortDir}`,
    [tenantId]
  );
}

export async function searchIssues(tenantId: string, q: string) {
  return rawDb.query(
    "SELECT id, title FROM issues WHERE tenant_id = $1 AND title ILIKE '%' || $2 || '%'",
    [tenantId, q]
  );
}

export async function deleteItem(tenantId: string, req: Request) {
  const id = new URL(req.url).searchParams.get("id") ?? undefined;
  return orm.item.deleteMany({ where: { tenantId, id } });
}

export async function listFiltered(tenantId: string, req: Request) {
  const filter = parseQs(new URL(req.url).search).filter; // qs.parse: nested objects allowed
  return prisma.issue.findMany({ where: { tenantId, ...filter } });
}

export async function createIssue(scope: TenantScope, body: any) {
  return prisma.issue.create({ data: { ...body, tenantId: scope.tenantId } });
}
```

<details>
<summary>Reveal</summary>

1. `ORDER BY ${sortField} ${sortDir}`: placeholders cannot bind identifiers, so the developer interpolated; SQL injection in the sort position.
2. `ILIKE '%' || $2 || '%'`: parameterized, but `%` and `_` in `q` are wildcards (`q=%` returns everything, `q=a_____` probes lengths) — query corruption and a cheap enumeration oracle, and in the worst case a slow-LIKE DoS.
3. `deleteMany({ where: { tenantId, id: undefined } })`: Prisma (and several query builders) treats `undefined` as "no condition". The tenant's entire table is deleted.
4. `{ tenantId, ...filter }`: user-controlled `filter` is spread after the tenant predicate (can override it), and may contain operators (`not`, `OR`, `contains`) and relation filters (`creator: { passwordHash: { startsWith } }`) — blind data extraction over any reachable relation.
5. `{ ...body, tenantId }` into `create`: nested writes (`project: { connect: { id: <victim project> } }`) attach the new row to another tenant's object; mass assignment of any column.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I4 — Context-Safe Boundary Parsing` (OWASP ASVS `v5.0.0-1.2.4`).
- **Mechanism:** modern TypeScript and Rust codebases rarely contain textbook `'${name}'` injection in `WHERE` values, because ORMs and tagged-template clients bind parameters. Real-world query corruption concentrates in five places:
  1. **Dynamic Identifiers (`ORDER BY`, column names, table names):** `$1` cannot bind identifiers, so developers interpolate (`ORDER BY ${sortBy} ${sortDir}`) without mapping through a constant dictionary.
  2. **Tagged-Template Misuse (`sql("SELECT …" + input)`):** a tagged template is just a function whose first argument is a `TemplateStringsArray`; calling it with parentheses and a pre-built string executes the string unless the wrapper asserts `Array.isArray(strings?.raw)`.
  3. **The `undefined` Parameter Trap:** several JS drivers/ORMs silently drop `WHERE` keys whose value is `undefined` (turning a scoped delete into a tenant-wide wipe).
  4. **ORM Operator Injection / Filter Pass-Through:** user JSON (or `qs` brackets) spread into a `where` object lets the caller choose operators and traverse relations. This is "SQL injection" at the ORM's query-language level: it bypasses parameter binding entirely because the *structure* of the query is attacker-chosen.
  5. **Nested relation writes (`connect`, `create`, `set`)** accepted from request bodies.
- **Why Happy-Path Tests Miss It:** tests send `sort=created_at` and a flat `filter={status:"open"}`; they never send `sort=(CASE…)`, bracketed nested filters, a missing `id`, or `%`.

### Where It Hides

- List/pagination endpoints (`GET /api/issues?sort=…&order=…&filter=…&fields=…&include=…`) that assemble `ORDER BY`, `GROUP BY`, `select`, `include` or JSONB path expressions.
- `db.raw()`, `sql.unsafe()`, `prisma.$queryRawUnsafe()`, `sqlx::query(&format!(…))`.
- Repository methods with optional filters (`{ id?: string; projectId?: string }`).
- Generic "search/filter builder" endpoints and table components that post a filter tree.
- Query-string parsers configured for nested objects (`qs`, `extended: true` in Express body/query parsers).

---

## 4. Hardened Pattern

### 4.1 Tagged template with runtime assertions (rejects `sql("…" + x)` and `undefined`)

```typescript
export interface SqlQueryObject {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * 1. Verifies `Array.isArray(strings?.raw)` and `Object.isFrozen(strings.raw)` so it
 *    CANNOT be invoked as a regular function `sql("SELECT " + x)`.
 * 2. Rejects `undefined` parameter values immediately (preventing silent predicate drops).
 */
export function sql(strings: TemplateStringsArray, ...values: unknown[]): SqlQueryObject {
  if (!Array.isArray(strings) || !Array.isArray(strings.raw) || !Object.isFrozen(strings.raw)) {
    throw new Error("SECURITY_VIOLATION: `sql` must be used strictly as a tagged template literal: sql`...`");
  }

  let text = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) {
    const val = values[i];
    if (val === undefined) {
      throw new Error(`SECURITY_VIOLATION: SQL parameter at index ${i + 1} is undefined`);
    }
    text += `$${i + 1}${strings[i + 1] ?? ""}`;
  }
  return Object.freeze({ text, values: Object.freeze([...values]) });
}
```

### 4.2 Identifier allowlist, own-property checked

```typescript
const ISSUE_SORT_COLUMNS: ReadonlyMap<string, string> = new Map([
  ["created_at", "i.created_at"],
  ["updated_at", "i.updated_at"],
  ["priority", "i.priority"],
  ["title", "i.title"],
]);

export function buildSafeIssueOrderBy(sortKey: unknown, sortDir: unknown): string {
  const col = (typeof sortKey === "string" && ISSUE_SORT_COLUMNS.get(sortKey)) || "i.created_at";
  const dir = typeof sortDir === "string" && sortDir.toUpperCase() === "ASC" ? "ASC" : "DESC";
  return `${col} ${dir}, i.id ASC`;
}
```

A `Map` (or `hasOwnProperty`) means `"toString"`, `"__proto__"` and `"constructor"` can never resolve to a function coerced into SQL text.

### 4.3 `LIKE` wildcard escaping

```typescript
export function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}

// sql`... WHERE title ILIKE ${"%" + escapeLike(q.slice(0, 100)) + "%"} ESCAPE '\\'`
```

### 4.4 Filter pass-through: a closed grammar, tenant predicate applied last and unconditionally

Never hand a user-shaped object to the ORM. Define the exact fields and operators a client may use, parse with a `.strict()` schema, then *build* the `where` yourself.

```typescript
import { z } from "zod";

const IssueFilterSchema = z
  .object({
    status: z.enum(["open", "closed"]).optional(),
    priority: z
      .object({
        gte: z.number().int().min(0).max(5).optional(),
        lte: z.number().int().min(0).max(5).optional(),
      })
      .strict()
      .optional(),
    titleContains: z.string().min(1).max(100).optional(),
    projectId: z.string().uuid().optional(),
  })
  .strict(); // no relation filters, no OR/NOT, no unknown keys

export function buildIssueWhere(scope: TenantScope, rawFilter: unknown): Prisma.IssueWhereInput {
  const f = IssueFilterSchema.parse(rawFilter ?? {});
  const clauses: Prisma.IssueWhereInput[] = [];
  if (f.status) clauses.push({ status: f.status });
  if (f.priority) clauses.push({ priority: { gte: f.priority.gte, lte: f.priority.lte } });
  if (f.titleContains) clauses.push({ title: { contains: f.titleContains, mode: "insensitive" } });
  if (f.projectId) {
    // A filter on a project the caller cannot see must behave like an empty project, not an error.
    if (!scope.canAccessProject(f.projectId)) return { id: { in: [] } };
    clauses.push({ projectId: f.projectId });
  }
  // Tenant (and guest project scope) are ANDed last as a separate clause: no user key can override them.
  return {
    AND: [{ tenantId: scope.tenantId }, scope.guestProjectClause(), ...clauses],
  };
}
```

Parse the query string with a parser configured **without** nested-object support (or reject non-string values) unless the endpoint genuinely needs it; if you need a filter tree, send it as one JSON parameter and validate it with the schema above.

### 4.5 Nested writes and the `undefined` trap at the repository boundary

```typescript
const CreateIssueSchema = z
  .object({
    title: z.string().trim().min(1).max(200),
    description: z.string().max(20_000).default(""),
    projectId: z.string().uuid(), // a plain scalar; never { connect: ... }
  })
  .strict();

export async function createIssueHardened(scope: TenantScope, rawBody: unknown) {
  const input = CreateIssueSchema.parse(rawBody);
  if (!scope.canAccessProject(input.projectId)) return null; // -> 404
  // FK validated inside the same tenant in the same statement; see ../authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md
  return scopedDb(scope).issue.createInProject(input);
}

export async function deleteItemHardened(scope: TenantScope, id: unknown) {
  const itemId = z.string().uuid().parse(id); // undefined/array/object -> throws before any query exists
  return scopedDb(scope).item.deleteById(itemId);
}
```

Scoped repositories and their guarantees are specified in [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md).

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Allowlisted sort on a sensitive column is still an oracle:** `sort=salary` leaks ordering of values the caller cannot read. Only allow sorting by columns the caller may also see.
- **`contains` filters on sensitive text are an oracle** (`titleContains=acq` returns a count). Apply the same visibility predicate as every other surface (see [`../authorization-and-tenancy/side-door-data-leaks.md`](../authorization-and-tenancy/side-door-data-leaks.md)).
- **Pagination cursors:** opaque cursors that embed a value (`createdAt|id`) are attacker-editable; sign them or treat them as untrusted inputs validated by schema.
- **Second-order injection:** a stored value (a column name saved in a "saved view", a sort preference) that is later interpolated into SQL by a background job is injection with a delay. Re-apply the allowlist at the use site.
- **`IN` lists / array parameters:** `= ANY($1)` requires the array parameter to be a real array of validated scalars; an empty array must produce "no rows", not "no predicate" in builders that omit empty `IN`.
- **JSON operators and full-text syntax:** `to_tsquery`/`websearch_to_tsquery` input and JSONB path expressions have their own metacharacters.
- **Raw escape hatches:** one remaining `queryRawUnsafe` voids the guarantee. Keep the hatch in one audited module.
- **Prototype pollution:** merging user JSON into config objects before building queries can change `Object.prototype`; parse into null-prototype structures or via schemas.

---

## 6. How to Discover It Automatically

### A. Static

```yaml
# semgrep
rules:
  - id: sql-template-literal-in-query
    languages: [typescript, javascript]
    severity: ERROR
    message: Template literal with interpolation passed to a SQL execution method
    pattern-either:
      - pattern: $DB.query(`...${$X}...`, ...)
      - pattern: $DB.execute(`...${$X}...`, ...)
      - pattern: $DB.$RAW(`...${$X}...`)
  - id: prisma-where-from-request
    languages: [typescript, javascript]
    severity: ERROR
    message: ORM where/data built from request-shaped input; parse with a closed .strict() schema and build the clause explicitly
    pattern-either:
      - pattern: $P.$M.findMany({ where: { ...$FILTER, ... } })
      - pattern: $P.$M.findMany({ where: { ..., ...$FILTER } })
      - pattern: $P.$M.update({ ..., data: { ...$BODY, ... } })
      - pattern: $P.$M.create({ data: { ...$BODY, ... } })
```

```bash
# 1. Template literal interpolation inside query helpers or unsafe wrappers:
rg -n '\.(query|execute|raw)\s*\(\s*`[^`]*\$\{' src/
rg -n 'queryRawUnsafe|executeRawUnsafe|sql\.unsafe|sqlx::query\s*\(\s*&format!' src/

# 2. Dynamic ORDER BY / GROUP BY:
rg -n -i 'ORDER\s+BY\s+\$\{|GROUP\s+BY\s+\$\{' src/

# 3. Where-objects containing spreads, and nested relation writes:
rg -n 'where:\s*\{[^}]*\.\.\.' src/
rg -n '\b(connect|connectOrCreate|disconnect|set)\s*:' src/

# 4. Query-string parsers that allow nested objects:
rg -n "from 'qs'|require\('qs'\)|extended:\s*true|parseNestedQuery" src/
```

### B. Dynamic Attacker Test

1. **Identifier & sort fuzzing:** on every endpoint accepting `sort`, `order`, `orderBy`, `fields`, `groupBy`, `include`, `cursor`, send `created_at;SELECT pg_sleep(5)--`, `(CASE WHEN (1=1) THEN title ELSE created_at END)`, `__proto__`, `constructor`, `toString`. Expect `400` or the default sort, zero `500`, zero timing delay.
2. **Type confusion:** `?id[]=1`, `?id[$ne]=x`, `{"id":{"not":null}}`, `?filter[tenantId][not]=x`, `?filter[creator][passwordHash][startsWith]=a`. Expect `400` (strict schema) and zero change in the response set size between a matching and non-matching `startsWith`.
3. **Missing key:** call every `DELETE`/`PATCH` with the identifier absent, empty, `null`, an array. Expect `400`; the DB-diff oracle (see [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)) must report zero rows changed.
4. **Wildcards:** `q=%`, `q=_`, `q=\` must behave as literals.
5. **Query-log tenant-predicate oracle:** replay every request as `Tenant B` with the database statement log enabled and assert every statement on a tenant table binds `B`'s tenant id. This catches filter overrides that never produce a visible leak.

---

## 7. How to Eliminate the Bug Class by Construction

1. **Central SQL tag with runtime assertions:** `Array.isArray(strings?.raw)` and `val !== undefined`; ban the driver's untagged string API outside that module.
2. **Identifier maps use `Map` / `hasOwnProperty`:** never `SORT_MAP[userInput]` on a plain object.
3. **Closed query grammar:** every list endpoint owns a `.strict()` filter/sort/include schema; the `where` clause is built from parsed fields and the tenant/guest clause is ANDed last by the scoped builder ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
4. **Scalar foreign keys only:** request schemas accept `projectId: uuid`, never relation-operation objects; the repository validates FK ownership in the same tenant.
5. **No unscoped ORM client in handlers:** only `scopedDb(scope)` is importable from route code; the raw client lives in the persistence module and `SystemScope`.
