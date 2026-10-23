# SQL & Query Construction Guards (Tagged Templates, Dynamic Identifiers & Undefined Traps)

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I4 — Context-Safe Boundary Parsing` (OWASP ASVS `v5.0.0-1.2.4`).
- **Mechanism:** Modern TypeScript and Rust codebases rarely suffer from textbook `SELECT * FROM users WHERE name = '${name}'` on static `WHERE` values because ORMs and tagged-template clients (`sql\`...\``) bind parameters automatically. Instead, real-world SQL injection and query corruption in modern stacks happen in three specific places:
  1. **Dynamic Identifiers (`ORDER BY`, column names, table names):** Parameter placeholders (`$1` / `?`) cannot bind SQL identifiers (column names, sort directions, table names). Developers fall back to string interpolation (`ORDER BY ${sortBy} ${sortDir}`) without mapping `sortBy` through a compile-time constant dictionary.
  2. **Tagged-Template Misuse (`sql("SELECT ..." + input)`):** In JavaScript/TypeScript, a tagged template function `sql\`SELECT * FROM t WHERE id = ${id}\`` is just a function whose first argument is `TemplateStringsArray`. If a developer or coding agent accidentally calls it with parentheses (`sql(\`SELECT * FROM t WHERE id = '${id}'\`)`) and the wrapper does not assert `Array.isArray(strings?.raw)`, the raw interpolated string is executed directly as SQL.
  3. **The `undefined` Parameter Trap in JS Query Builders:** Passing `{ tenantId: actor.tenantId, id: req.query.id }` to an ORM/query helper when `req.query.id` is `undefined`. Several popular JS SQL drivers/ORMs silently strip `WHERE` keys whose value is `undefined` (turning `DELETE FROM items WHERE tenant_id = $1 AND id = $2` into `DELETE FROM items WHERE tenant_id = $1`—wiping the entire tenant's table) or throw an unhandled driver error.

---

## 2. Where It Hides

- List and pagination endpoints (`GET /api/issues?sort=created_at&order=desc&filter=...`) that dynamically assemble `ORDER BY`, `GROUP BY`, or JSONB path expressions.
- Custom database wrapper utilities (`db.raw()`, `sql.unsafe()`, `prisma.$queryRawUnsafe()`, `sqlx::query(&format!(...))`).
- Repository methods that accept optional filter objects (`{ id?: string; projectId?: string }`) and pass properties that might be `undefined` directly into positional or named SQL bindings.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Dynamic `ORDER BY` Interpolation + Unsafe Template Wrapper)

```typescript
// VULNERABLE:
// 1. Does not verify `Array.isArray(strings.raw)` — can be called as `sql(`...${unsafe}...`)`!
// 2. Interpolates `sortField` and `sortDir` directly into the query string!
// 3. Does not reject `undefined` values in `values`!
export async function listIssuesVulnerable(
  tenantId: string,
  sortField = "created_at",
  sortDir = "DESC"
) {
  return rawDb.query(
    `SELECT id, title FROM issues WHERE tenant_id = $1 ORDER BY ${sortField} ${sortDir}`,
    [tenantId]
  );
}
```

### Hardened Pattern (TypeScript — Runtime Tagged-Template Assertion + Identifier Allowlist Map)

```typescript
export interface SqlQueryObject {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * Hardened SQL tagged-template tag:
 * 1. Verifies `Array.isArray(strings?.raw)` and `Object.isFrozen(strings.raw)` so it
 *    CANNOT be invoked as a regular function `sql("SELECT " + x)`.
 * 2. Rejects `undefined` parameter values immediately (preventing silent predicate drops).
 */
export function sql(strings: TemplateStringsArray, ...values: unknown[]): SqlQueryObject {
  if (!Array.isArray(strings) || !Array.isArray(strings.raw) || !Object.isFrozen(strings.raw)) {
    throw new Error(
      "SECURITY_VIOLATION: `sql` must be used strictly as a tagged template literal: sql`...`"
    );
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

// Safe dynamic sorting via an immutable allowlist dictionary (user input never touches SQL text):
const ISSUE_SORT_COLUMNS: Readonly<Record<string, string>> = Object.freeze({
  created_at: "i.created_at",
  updated_at: "i.updated_at",
  priority: "i.priority",
  title: "i.title",
});

export function buildSafeIssueOrderBy(sortKey: string, sortDir: string): string {
  const col = Object.prototype.hasOwnProperty.call(ISSUE_SORT_COLUMNS, sortKey)
    ? ISSUE_SORT_COLUMNS[sortKey]
    : "i.created_at";
  const dir = sortDir.toUpperCase() === "ASC" ? "ASC" : "DESC";
  return `${col} ${dir}, i.id ASC`;
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Catch any template literal `${...}` inside `.query(`, `.execute(`, `queryRawUnsafe`, or `format!` SQL:
rg -n '\.(query|execute|raw)\s*\(\s*`[^`]*\$\{' src/
rg -n 'queryRawUnsafe|executeRawUnsafe|sql\.unsafe|sqlx::query\s*\(\s*&format!' src/

# 2. Catch any dynamic `ORDER BY` or `GROUP BY` string construction:
rg -n -i 'ORDER\s+BY\s+\$\{' src/
```

### B. Dynamic Attacker Test (SQL Syntax & Sort/Filter Fuzzing)
1. **Identifier & Sort Parameter Fuzzing:** On every endpoint accepting `sort`, `order`, `orderBy`, `fields`, `groupBy`, or `cursor`, send:
   - `?sort=created_at;SELECT+pg_sleep(5)--`
   - `?sort=(CASE+WHEN+(1=1)+THEN+title+ELSE+created_at+END)`
   - `?sort=__proto__` and `?sort=constructor` (prototype pollution into lookup objects — defeated by `Object.prototype.hasOwnProperty.call`)
   Assert `400 Bad Request` or fallback to default sort with zero `500` database syntax errors and zero timing delay.
2. **JSON Type Confusion (`?id[]=1` / `{ "id": { "$ne": null } }`):** Send arrays and nested objects where scalar strings are expected. Assert strict schema rejection (`400`) before the query layer is reached.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Enforce `Array.isArray(strings?.raw)` and `val !== undefined` in the Central SQL Tag:** Make it impossible at runtime to pass a dynamically concatenated string or an `undefined` binding to the database driver.
2. **Use `Object.prototype.hasOwnProperty.call` on Identifier Maps:** Never index a plain object `SORT_MAP[userInput]` without an own-property check (or use a `Map<string, string>`), preventing `"toString"` or `"valueOf"` from resolving to a function object coerced into SQL text.
