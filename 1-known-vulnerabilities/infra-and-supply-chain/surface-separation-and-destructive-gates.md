# Surface Separation (Human UI vs. Machine API) & Destructive Operation Gates

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I5 — Minimal Blast Radius & Fail-Closed Boot`.
- **Mechanism:** When a single monolithic router mounts human administrative endpoints, machine-to-machine worker endpoints, and database maintenance/migration hooks on the same domain and privilege tier, a single failure in one surface compromises the entire system:
  1. **Collapsed Human vs. Machine Surfaces:** If the public machine API (`api.example.com`, authenticated via `Bearer` API keys) mounts the same routes as the human dashboard (`app.example.com`, protected by edge Zero-Trust Access + browser session), a leaked machine key can access human-only admin actions (`POST /api/keys`, `DELETE /api/workspace`, billing mutations).
  2. **Unchecked Destructive SQL / Schema Drift in CI:** Automated deploy pipelines or coding agents running migrations that contain `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, or `DELETE FROM` without an explicit human break-glass flag, or mutating an already-applied historical migration file so staging/production schemas silently diverge from what tests verified.

---

## 2. Where It Hides

- Single-entry-point applications where `app.use("/api", apiRouter)` serves both browser sessions and external webhook/CLI callers without route-level surface tags.
- Deploy scripts (`package.json` `"deploy": "migrate && deploy"`) that apply arbitrary SQL files in `migrations/` without verifying SHA-256 checksums of already-applied migrations or scanning new migrations for destructive statements.
- Internal admin or debug endpoints (`/api/admin/impersonate`, `/api/admin/sql`, `/api/internal/recompute`) mounted on the public internet router instead of an isolated internal listener or separate worker.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Shared Router + Unchecked Migration Runner)

```typescript
// VULNERABLE:
// Mounts `createApiKey` and `deleteOrganization` on the exact same router used by
// external machine API keys, and runs raw SQL migrations without checking for DROP/TRUNCATE
// or historical migration edits.
app.post("/api/keys", requireAnyAuth, createApiKeyHandler);
app.delete("/api/orgs/:id", requireAnyAuth, deleteOrganizationHandler);
```

### Hardened Pattern 1: Explicit Router-Level Surface Separation

```typescript
export type SurfaceKind = "human_ui_only" | "machine_api_allowed";

export interface RouteRegistration {
  readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly path: string;
  readonly surface: SurfaceKind;
  readonly handler: (req: Request, ctx: ExecutionContext) => Promise<Response>;
}

/**
 * Dispatcher that enforces physical/logical surface separation:
 * - On the Machine Worker deployment (`DEPLOYMENT_SURFACE === "machine"`), routes marked
 *   `human_ui_only` (like `/api/keys`, `/api/billing`, `/api/orgs/delete`) are NOT even
 *   reachable (returns 404 immediately) AND Bearer API keys are rejected on `human_ui_only` routes.
 */
export async function dispatchBySurface(
  req: Request,
  deploymentSurface: "human_ui" | "machine_api",
  route: RouteRegistration,
  ctx: ExecutionContext
): Promise<Response> {
  if (deploymentSurface === "machine_api" && route.surface === "human_ui_only") {
    return new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }

  if (route.surface === "human_ui_only" && req.headers.get("authorization")?.startsWith("Bearer ")) {
    return new Response(
      JSON.stringify({ error: "FORBIDDEN_SURFACE: Bearer API keys cannot call human_ui_only routes" }),
      { status: 403, headers: { "content-type": "application/json; charset=utf-8" } }
    );
  }

  return route.handler(req, ctx);
}
```

### Hardened Pattern 2: Append-Only Checksummed Migration & Destructive SQL Gate

```typescript
import crypto from "node:crypto";

const DESTRUCTIVE_SQL_REGEX =
  /\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE\s+TABLE?|DELETE\s+FROM|ALTER\s+TABLE\s+\S+\s+DROP)\b/i;

export interface MigrationFile {
  readonly filename: string; // e.g., "0004_add_issue_history.sql"
  readonly sql: string;
}

export function verifyMigrationsBeforeApply(
  filesOnDisk: ReadonlyArray<MigrationFile>,
  appliedRecords: ReadonlyArray<{ filename: string; sha256: string }>,
  env: { ALLOW_DESTRUCTIVE_MIGRATION?: string }
): void {
  // 1. Verify strict sequential ordering and immutable history (no editing applied migrations):
  for (let i = 0; i < appliedRecords.length; i++) {
    const applied = appliedRecords[i];
    const onDisk = filesOnDisk[i];
    if (!onDisk || onDisk.filename !== applied.filename) {
      throw new Error(
        `MIGRATION_HISTORY_TAMPERED: Expected ${applied.filename} at index ${i}, found ${onDisk?.filename ?? "NONE"}`
      );
    }
    const diskHash = crypto.createHash("sha256").update(onDisk.sql, "utf8").digest("hex");
    if (diskHash !== applied.sha256) {
      throw new Error(
        `MIGRATION_CHECKSUM_MISMATCH: Applied migration ${applied.filename} was modified after deployment!`
      );
    }
  }

  // 2. Scan unapplied migrations for destructive SQL (`DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, `DELETE FROM`):
  const pending = filesOnDisk.slice(appliedRecords.length);
  for (const mig of pending) {
    const match = DESTRUCTIVE_SQL_REGEX.exec(mig.sql);
    if (match && env.ALLOW_DESTRUCTIVE_MIGRATION !== mig.filename) {
      throw new Error(
        `DESTRUCTIVE_MIGRATION_BLOCKED: ${mig.filename} contains "${match[0]}". ` +
          `Require explicit human approval via ALLOW_DESTRUCTIVE_MIGRATION=${mig.filename}`
      );
    }
  }
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. List all route registrations and check which auth middleware / surface they use:
rg -n '\.(get|post|put|patch|delete)\s*\(' src/

# 2. Scan migrations for destructive SQL operations:
rg -n -i '\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE|DELETE\s+FROM)\b' migrations/
```

### B. Dynamic Attacker Test
1. **Machine Surface Enumeration:** Against the machine API endpoint (or using a `Bearer` API key), send requests to every administrative route (`POST /api/keys`, `DELETE /api/keys/:id`, `DELETE /api/orgs/:id`, `POST /api/billing/portal`). Assert all return `404` or `403`.
2. **Migration Tamper Test:** In the test suite, mutate 1 character of an already-applied migration and assert `verifyMigrationsBeforeApply` throws `MIGRATION_CHECKSUM_MISMATCH`; add a pending migration containing `DROP TABLE users;` without `ALLOW_DESTRUCTIVE_MIGRATION` and assert it throws `DESTRUCTIVE_MIGRATION_BLOCKED`.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Mandatory `surface` Property on Route Definitions:** Make `surface: "human_ui_only" | "machine_api_allowed"` a required field on your route registration helper so every new route forces an explicit decision.
2. **Run `verifyMigrationsBeforeApply` in CI on Every PR:** Fail the PR build automatically if an existing migration file in `migrations/` differs from `main` or if a new migration contains destructive SQL without an explicit break-glass approval annotation.
