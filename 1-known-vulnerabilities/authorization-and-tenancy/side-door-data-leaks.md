# Side-Door Data Leaks (Search, History, Exports, Aggregates & MCP)

## 1. Attack Transcript

`Guest G` is invited **only** to `Project Public`. The issue `Quarterly acquisition target flag{CANARY_SECRET_PROJ}` lives in `Project Secret`.

```bash
# Front door: correctly locked
$ curl -s -H "Authorization: Bearer $G" https://app.example.com/api/issues/5c1e…   # the secret issue
{"error":"Not Found"}                                                               # 404, good

# Side door 1: global search runs the FTS query, then filters by org only
$ curl -s -H "Authorization: Bearer $G" 'https://app.example.com/api/search?q=acquisition'
{"total":2,"results":[{"id":"5c1e…","title":"Quarterly acquisition target flag{CANARY_SECRET_PROJ}","snippet":"…<mark>acquisition</mark> target…"}, …]}

# Side door 2: history of an issue that was MOVED from Secret to Public
$ curl -s -H "Authorization: Bearer $G" https://app.example.com/api/issues/9a77…/history
[{"field":"comment","new_value":"merger price flag{CANARY_MOVED_3}","project_id":"<Secret>", …}]

# Side door 3: no secret rows are returned, but the numbers still leak
$ curl -s -H "Authorization: Bearer $G" 'https://app.example.com/api/search?q=acquisition&limit=1'
{"total":2,"results":[…1 visible…]}            # "total" counts hidden rows
$ curl -s -H "Authorization: Bearer $G" 'https://app.example.com/api/projects/stats'
[{"project":"Project Secret","open_issues":14}]
```

## 2. Spot the Bug

The primary route is correct. Find every way a restricted guest can still read or infer Secret data.

```sql
SELECT i.id, i.title, i.description
FROM issues i
WHERE i.org_id = $1
  AND (i.title ILIKE '%' || $2 || '%' OR i.description ILIKE '%' || $2 || '%')
ORDER BY i.updated_at DESC
LIMIT 50;

SELECT id, actor_id, field_name, old_value, new_value, created_at
FROM issue_history
WHERE issue_id = $1
ORDER BY created_at DESC;

SELECT project_id, count(*) AS open_issues
FROM issues
WHERE org_id = $1 AND status = 'open'
GROUP BY project_id;
```

<details>
<summary>Reveal the bugs</summary>

1. Search filters by `org_id` only: protects against another org, fails against a project guest. `ILIKE` input also does not escape `%` and `_`, so a guest can run wildcard probes (`q=_____`) to measure content length.
2. History is keyed by `issue_id` with no check that the caller can view the parent issue now, nor the project the event was recorded in.
3. The aggregate groups every project and returns the private ones.
4. Not visible in the SQL: soft-deleted issues (`deleted_at`) are still returned by all three.

</details>

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (Surface Parity: $\text{Visible}(\text{Actor}, S_{\text{secondary}}) \subseteq \text{Visible}(\text{Actor}, S_{\text{primary}})$).
- **Mechanism:** In production applications, primary CRUD endpoints (`GET /api/issues/:id` or `GET /api/projects/:id`) almost always have authorization checks because they are the first routes built and tested. Data leaks happen through **side doors**—secondary surfaces added later for convenience, analytics, or AI integrations that read from denormalized tables, full-text search indexes (`FTS5`, `tsvector`, Meilisearch/Typesense), audit/activity logs, CSV/JSON export jobs, GraphQL/JSON batch resolvers, or Model Context Protocol (MCP) tool handlers without applying the exact same tenant and project-level visibility filters as the primary route.
- **Why Happy-Path Tests Miss It:** A test for `GET /api/search?q=roadmap` runs as a single logged-in user and asserts that their own `"roadmap"` item is returned. It never seeds a private `"roadmap flag{CANARY}"` item in a restricted project (or another tenant) and queries the search endpoint, activity feed, and MCP tool as a restricted Guest or Stranger.
- **Leaks without content:** a side door can leak by *count* (`total`, facet counts, badge numbers), *order* (ranking changes when a hidden row matches), *autocomplete* (prefix completion from a global dictionary), *timing*, or *error shape*. A canary-substring oracle alone misses all of these.

### Where It Hides

1. **Full-Text Search & Autocomplete (`/api/search`, `/api/mentions`):** Querying an FTS index (`WHERE issues_fts MATCH $1`) and filtering by `org_id`, while forgetting that **Project Guests** inside that org are only allowed to see 1 of the org's 12 projects. Post-filtering hits after the engine computed `total`, facets or ranking still leaks.
2. **Activity Feeds, Audit Logs & Changelogs (`/api/activity`, `/api/issues/:id/history`):** When an issue is moved from a restricted project to a public project (or vice versa), or when an org-wide activity stream renders `issue_events`, historical events leak titles, descriptions, or comment snippets from projects the caller cannot access.
3. **CSV / PDF / Bulk Exports (`/api/export`):** Background jobs or streaming export endpoints that accept a filter object from the client (`{ orgId, projectIds }`) and trust the client-supplied `projectIds` array instead of intersecting it with the caller's authorized project set. The job also loses the caller's scope; see [`async-jobs-and-scope-propagation.md`](async-jobs-and-scope-propagation.md).
4. **Count, Sum & Dashboard Aggregates (`/api/stats`):** Leaking sensitive numerical metrics (revenue, salaries, issue counts per private project) via `GROUP BY` queries that omit per-project capability filters.
5. **Agent / MCP Tool Endpoints (`/mcp`, tool-calling handlers):** Internal service helpers wired directly into an LLM agent or MCP server using a service-level database handle instead of the caller's `TenantScope` (see [`../injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../injection-and-trust-boundaries/agentic-and-mcp-threats.md)).
6. **Comments, attachments and reactions of a moved issue:** child rows keep pointing at the `issue_id` and silently become visible to whoever can see the issue *now*, even though they were written when it lived in a restricted project.
7. **Soft-deleted rows:** `deleted_at IS NULL` is applied on the primary list and forgotten in search, exports, history and aggregates.
8. **Derived stores:** search indexes, embeddings/RAG stores, materialized views and denormalized counters; see [`cache-and-derived-data.md`](cache-and-derived-data.md).

## 4. Hardened Pattern

Instead of writing ad-hoc `WHERE` clauses in every endpoint, define **one canonical visibility predicate** (or SQL view/CTE helper bound to `TenantScope`) and require every secondary surface to join through `visible_issues`. In application code this is `ScopedDb.visible()` from [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md); the SQL below is its ORM-free form.

### Canonical `visible_issues` (note `deleted_at`)

```sql
-- Bound to ($1 = org_id, $2 = actor_id, $3 = is_full_member).
-- Every secondary surface (search, history, export, aggregates, attachments, MCP tools)
-- MUST join against `visible_issues` so side doors can NEVER return a row that primary CRUD hides.
WITH visible_issues AS (
    SELECT i.id, i.org_id, i.project_id, i.title, i.description, i.updated_at
    FROM issues i
    WHERE i.org_id = $1
      AND i.deleted_at IS NULL
      AND (
          $3 = TRUE -- Full org owner/member
          OR EXISTS (
              SELECT 1
              FROM project_guests pg
              WHERE pg.org_id = i.org_id
                AND pg.project_id = i.project_id
                AND pg.user_id = $2
                AND pg.revoked_at IS NULL
          )
      )
)
-- Example 1: Search uses `visible_issues`, with LIKE metacharacters escaped (see escapeLike below)
SELECT v.id, v.title, v.description
FROM visible_issues v
WHERE v.title ILIKE '%' || $4 || '%' ESCAPE '\'
   OR v.description ILIKE '%' || $4 || '%' ESCAPE '\'
ORDER BY v.updated_at DESC
LIMIT 50;
```

```typescript
export const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);
```

### History: no fail-open on unattributed rows

```sql
-- Issue history joins `visible_issues` AND requires the actor to hold the project in which the
-- EVENT was recorded. Rows without an attributed project (legacy rows before the column existed)
-- are visible to full members ONLY, until they are backfilled. NULL never means "public".
WITH visible_issues AS (
    SELECT i.id, i.org_id
    FROM issues i
    WHERE i.org_id = $1
      AND i.id = $4
      AND i.deleted_at IS NULL
      AND (
          $3 = TRUE
          OR EXISTS (
              SELECT 1 FROM project_guests pg
              WHERE pg.org_id = i.org_id
                AND pg.project_id = i.project_id
                AND pg.user_id = $2
                AND pg.revoked_at IS NULL
          )
      )
)
SELECT h.id, h.actor_id, h.field_name, h.old_value, h.new_value, h.created_at
FROM issue_history h
INNER JOIN visible_issues vi ON vi.id = h.issue_id AND vi.org_id = h.org_id
WHERE $3 = TRUE
   OR (
        h.project_id IS NOT NULL
        AND EXISTS (
            SELECT 1 FROM project_guests pg
            WHERE pg.org_id = vi.org_id
              AND pg.project_id = h.project_id
              AND pg.user_id = $2
              AND pg.revoked_at IS NULL
        )
   )
ORDER BY h.created_at DESC;
```

Comments, attachments and reactions get the same treatment: each child row stores the `project_id` it was **written in** (`comments.project_id`, `attachments.project_id`), and the guest predicate is applied to that column, not only to the parent's current project. After a Secret to Public move, the guest sees the issue and the post-move comments, not the pre-move ones.

### Aggregates and search totals come from the same predicate

```sql
-- Stats: aggregate over visible_issues, never over `issues`
SELECT v.project_id, count(*) AS open_issues
FROM visible_issues v
JOIN issues i ON i.id = v.id AND i.status = 'open'
GROUP BY v.project_id;
```

For full-text engines, push the tenant and project filter **into the engine query** (a mandatory filter parameter, or one index partition per tenant) so `total`, facets, ranking and snippets are computed over permitted documents only. If the engine cannot filter natively, treat its output as a list of **candidate IDs** and hydrate every hit through `ScopedDb`; return `total` only as the count of hydrated visible hits, and never expose engine-side facet counts.

## 5. Residual Edge Cases

- **Index lag.** Moves, revocations and deletes reach the search/vector index asynchronously. Hydration through `ScopedDb` is what closes the window; the index is never an authority ([`cache-and-derived-data.md`](cache-and-derived-data.md)).
- **Snippets and highlights.** Highlight markup can split a canary (`fl<mark>ag</mark>`); test with fragment matching, not only exact substrings.
- **Ordering and pagination oracles.** A hidden row that changes ranking, or a cursor that encodes an internal row ID, reveals existence; bind cursors to the actor's scope.
- **Autocomplete.** Suggestions built from a global term dictionary leak terms from other tenants or projects; build per-scope dictionaries or generate suggestions from hydrated visible rows.
- **Backfill discipline.** The `h.project_id IS NOT NULL` rule hides legacy rows from guests until a migration attributes them; track it as a task, and never "fix" it with `IS NULL` fallbacks.
- **Webhook and notification payloads** are a read surface too; their content must be generated from the recipient's scope, not the actor's.
- **LIKE/regex input.** Escape `%`, `_` and `\`, cap query length, and cap wildcard-only queries, or the search box becomes a length/content oracle.
- **Time.** Revocation applies on the next request, subject to the SLO documented for replicas/caches ([`guest-boundaries-and-storage-blobs.md`](guest-boundaries-and-storage-blobs.md)).

## 6. How to Discover It Automatically

### A. Static Code Search
```bash
# List every query against secondary tables (`_fts`, `_history`, `audit_logs`, `activity`, `exports`)
# and check whether it joins or filters through the exact same capability helper as primary CRUD:
rg -n -i 'FROM\s+(issue_history|audit_logs|activities|.*_fts|search_index)' src/

# Aggregates over tenant tables that do not go through the visibility helper:
rg -n -i '(count|sum|avg)\s*\(' src/ | rg -v -i 'visible_|scoped\.|ScopedDb'

# Soft-delete column missing from a query that reads a table having one:
rg -nU -i 'FROM\s+issues\b(?![^;`"]*deleted_at)' src/
```

```yaml
# rules/search-without-scope.yml (Semgrep): index clients may only be called with a scope-derived filter
rules:
  - id: search-index-call-without-scope-filter
    languages: [typescript]
    severity: ERROR
    message: Search/vector queries must pass a filter derived from the caller's scope, then hydrate via ScopedDb.
    patterns:
      - pattern: $INDEX.search($Q, $OPTS)
      - pattern-not: $INDEX.search($Q, { ..., filter: $F, ... })
```

### B. Dynamic Attacker Test (The Differential Surface Oracle)
Follow the full protocol in [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md):
1. Seed `Org 1` with two projects: `Project Public-Guest` (where `Guest G` is invited) and `Project Secret` (where `Guest G` is **not** invited).
2. In `Project Secret`, create an issue with title `"Quarterly acquisition target flag{CANARY_SECRET_PROJ}"`, edit its title twice (populating `issue_history`), attach a file, and add a comment.
3. Also move an issue from `Project Secret` into `Project Public-Guest` after recording a sensitive comment/history event in `Project Secret`. Soft-delete one issue in `Project Public-Guest` that contains a canary.
4. As `Guest G` (and as cross-tenant `Stranger S`), query **every** read surface:
   - Primary CRUD: `GET /api/issues`, `GET /api/issues/:id`
   - Search: `GET /api/search?q=acquisition`, `GET /api/search?q=flag`, plus a prefix query and autocomplete
   - History / Activity: `GET /api/activity`, `GET /api/issues/:id/history`
   - Exports: `GET /api/export/issues.csv` (decode the file; do not scan only the HTTP body)
   - Aggregates: `GET /api/projects/stats`
   - MCP / Agent tools: `mcp.call("search_issues", { query: "acquisition" })`
5. Assert that **zero** secondary surfaces return any ID, snippet, count, ordering change or canary hash that was excluded from the primary CRUD list. Compute the subset property explicitly: `ReferencedIDs(G, S) ⊆ PrimaryIDs(G)` and `Counts(G, S)` equal to counts over primary-visible rows.
6. Run the query-log oracle on the same sweep ([`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)): each statement against `issues`, `issue_history`, `comments` or the FTS table must carry the actor-bound tenant and guest-project predicate.

## 7. How to Eliminate the Bug Class by Construction

1. **Single View/Query Builder for Resource Visibility:** Never write separate `WHERE` clauses for CRUD, Search, Exports, and History. Expose a single `scopedIssuesQuery(scope: TenantScope)` builder in your repository layer ([`ScopedDb.select`](../../strategy/scoped-db.md)); Search, Exports, Aggregates, and History must compose on top of that query builder.
2. **MCP Tools Must Call Scoped Application Services:** Never let an MCP tool handler execute raw SQL. Every MCP tool must require a `TenantScope` resolved from the caller's token and delegate to the exact same `IssueRepository` methods used by the HTTP API.
3. **Attribute every child row to the project it was written in**, and apply guest predicates to that column; make the column `NOT NULL` so "unattributed" cannot be represented.
4. **Treat indexes as candidate generators.** Hydrate through `ScopedDb` before returning anything; compute counts and facets from hydrated rows.
5. **Soft-delete lives in the registry** (`deletedCol`), so `ScopedDb.visible()` adds it everywhere; there is no query path that forgets it.
