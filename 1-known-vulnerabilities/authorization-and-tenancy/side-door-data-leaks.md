# Side-Door Data Leaks (Search, History, Exports, Aggregates & MCP)

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (Surface Parity: $\text{Visible}(\text{Actor}, S_{\text{secondary}}) \subseteq \text{Visible}(\text{Actor}, S_{\text{primary}})$).
- **Mechanism:** In production applications, primary CRUD endpoints (`GET /api/issues/:id` or `GET /api/projects/:id`) almost always have authorization checks because they are the first routes built and tested. Data leaks happen through **side doors**—secondary surfaces added later for convenience, analytics, or AI integrations that read from denormalized tables, full-text search indexes (`FTS5`, `tsvector`, Meilisearch/Typesense), audit/activity logs, CSV/JSON export jobs, GraphQL/JSON batch resolvers, or Model Context Protocol (MCP) tool handlers without applying the exact same tenant and project-level visibility filters as the primary route.
- **Why Happy-Path Tests Miss It:** A test for `GET /api/search?q=roadmap` runs as a single logged-in user and asserts that their own `"roadmap"` item is returned. It never seeds a private `"roadmap flag{CANARY}"` item in a restricted project (or another tenant) and queries the search endpoint, activity feed, and MCP tool as a restricted Guest or Stranger.

---

## 2. Where It Hides

1. **Full-Text Search & Autocomplete (`/api/search`, `/api/mentions`):** Querying an FTS index (`WHERE issues_fts MATCH $1`) and filtering by `org_id`, while forgetting that **Project Guests** inside that org are only allowed to see 1 of the org's 12 projects.
2. **Activity Feeds, Audit Logs & Changelogs (`/api/activity`, `/api/issues/:id/history`):** When an issue is moved from a restricted project to a public project (or vice versa), or when an org-wide activity stream renders `issue_events`, historical events leak titles, descriptions, or comment snippets from projects the caller cannot access.
3. **CSV / PDF / Bulk Exports (`/api/export`):** Background jobs or streaming export endpoints that accept a filter object from the client (`{ orgId, projectIds }`) and trust the client-supplied `projectIds` array instead of intersecting it with the caller's authorized project set.
4. **Count, Sum & Dashboard Aggregates (`/api/stats`):** Leaking sensitive numerical metrics (revenue, salaries, issue counts per private project) via `GROUP BY` queries that omit per-project capability filters.
5. **Agent / MCP Tool Endpoints (`/mcp`, tool-calling handlers):** Internal service helpers wired directly into an LLM agent or MCP server using a service-level database handle instead of the caller's `TenantScope`.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (Rust / SQL — Search & History Endpoints Bypassing Guest Scope)

```sql
-- VULNERABLE SEARCH QUERY:
-- Filters by `org_id`, which protects against a completely different organization,
-- but FAILS completely when the caller is a Project Guest who only has access to `project_a`
-- inside `org_id`! The guest can search and read every secret issue in `project_b`.
SELECT i.id, i.title, i.description
FROM issues i
WHERE i.org_id = $1
  AND (i.title ILIKE '%' || $2 || '%' OR i.description ILIKE '%' || $2 || '%')
ORDER BY i.updated_at DESC
LIMIT 50;

-- VULNERABLE HISTORY QUERY:
-- Fetches history events by `issue_id` without checking if the caller can currently view
-- the parent issue AND without filtering events recorded while the issue lived in a private project.
SELECT id, actor_id, field_name, old_value, new_value, created_at
FROM issue_history
WHERE issue_id = $1
ORDER BY created_at DESC;
```

### Hardened Pattern (Shared Visibility Predicate Across Primary CRUD, Search, History & Exports)

Instead of writing ad-hoc `WHERE` clauses in every endpoint, define **one canonical visibility predicate** (or SQL view/CTE helper bound to `TenantScope`) and require every secondary surface to join through `visible_issues`:

```sql
-- HARDENED: Canonical `visible_issues` CTE bound to ($1 = org_id, $2 = actor_id, $3 = is_full_member).
-- Every secondary surface (search, history, export, aggregates, attachments, MCP tools)
-- MUST join against `visible_issues` so side doors can NEVER return a row that primary CRUD hides.
WITH visible_issues AS (
    SELECT i.id, i.project_id, i.title, i.description, i.updated_at
    FROM issues i
    WHERE i.org_id = $1
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
-- Example 1: Search uses `visible_issues`
SELECT v.id, v.title, v.description
FROM visible_issues v
WHERE v.title ILIKE '%' || $4 || '%'
   OR v.description ILIKE '%' || $4 || '%'
ORDER BY v.updated_at DESC
LIMIT 50;
```

```sql
-- Example 2: Issue History joins `visible_issues` AND verifies the actor has access
-- to the project associated with the historical event (preventing cross-project move leaks):
WITH visible_issues AS (
    SELECT i.id, i.org_id
    FROM issues i
    WHERE i.org_id = $1
      AND i.id = $4
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
INNER JOIN visible_issues vi ON vi.id = h.issue_id
WHERE $3 = TRUE
   OR h.project_id IS NULL
   OR EXISTS (
       SELECT 1 FROM project_guests pg
       WHERE pg.org_id = vi.org_id
         AND pg.project_id = h.project_id
         AND pg.user_id = $2
         AND pg.revoked_at IS NULL
   )
ORDER BY h.created_at DESC;
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# List every query against secondary tables (`_fts`, `_history`, `audit_logs`, `activity`, `exports`)
# and check whether it joins or filters through the exact same capability helper as primary CRUD:
rg -n -i 'FROM\s+(issue_history|audit_logs|activities|.*_fts|search_index)' src/
```

### B. Dynamic Attacker Test (The Differential Surface Oracle)
Follow the full protocol in [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md):
1. Seed `Org 1` with two projects: `Project Public-Guest` (where `Guest G` is invited) and `Project Secret` (where `Guest G` is **not** invited).
2. In `Project Secret`, create an issue with title `"Quarterly acquisition target flag{CANARY_SECRET_PROJ}"`, edit its title twice (populating `issue_history`), attach a file, and add a comment.
3. Also move an issue from `Project Secret` into `Project Public-Guest` after recording a sensitive comment/history event in `Project Secret`.
4. As `Guest G` (and as cross-tenant `Stranger S`), query **every** read surface:
   - Primary CRUD: `GET /api/issues`, `GET /api/issues/:id`
   - Search: `GET /api/search?q=acquisition`, `GET /api/search?q=flag`
   - History / Activity: `GET /api/activity`, `GET /api/issues/:id/history`
   - Exports: `GET /api/export/issues.csv`
   - Aggregates: `GET /api/projects/stats`
   - MCP / Agent tools: `mcp.call("search_issues", { query: "acquisition" })`
5. Assert that **zero** secondary surfaces return any ID, snippet, or canary hash that was excluded from the primary CRUD list.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Single View/Query Builder for Resource Visibility:** Never write separate `WHERE` clauses for CRUD, Search, Exports, and History. Expose a single `scopedIssuesQuery(scope: TenantScope)` builder in your repository layer; Search, Exports, Aggregates, and History must compose on top of that query builder.
2. **MCP Tools Must Call Scoped Application Services:** Never let an MCP tool handler execute raw SQL. Every MCP tool must require a `TenantScope` resolved from the caller's token and delegate to the exact same `IssueRepository` methods used by the HTTP API.
