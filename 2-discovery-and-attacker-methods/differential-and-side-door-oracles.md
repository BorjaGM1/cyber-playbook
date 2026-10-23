# Step 2: Differential Surface & Side-Door Oracles

## 1. Mental Model (Catching Leaks Without Knowing Where They Are)

How do you automatically detect authorization bugs across 40 endpoints—including search, activity history, exports, aggregates, webhooks, and MCP tools—without writing 40 custom test assertions by hand?

You use a **Differential Surface Oracle** built on two universal mathematical properties of multi-tenant applications:

### Property 1: Cross-Surface Visibility Subset (`Side-Door Parity`)
For any actor $A$, let $\text{PrimaryIDs}(A)$ be the set of resource UUIDs returned by the primary authenticated list endpoint (e.g., `GET /api/issues` or `GET /api/projects`).
Then for **every** secondary surface $S \in \{\text{Search}, \text{ActivityFeed}, \text{IssueHistory}, \text{CsvExport}, \text{Attachments}, \text{Stats}, \text{McpTools}\}$:
$$\text{ReferencedIDs}(A, S) \subseteq \text{PrimaryIDs}(A)$$
$$\text{CanariesVisible}(A, S) \subseteq \text{CanariesVisible}(A, \text{Primary})$$

If `ProjectGuest G` sees **1** issue on `GET /api/issues`, but `GET /api/search?q=a`, `GET /api/activity`, or `mcp.call("list_issues")` returns **2** issues (or leaks a snippet from `Project Secret`), the Differential Oracle flags a **Critical Side-Door Leak** automatically!

### Property 2: Unauthorized Indistinguishability (`404 Anti-Enumeration Oracle`)
For any actor $B$ who does not have access to resource $R_{\text{private}}$ (whether $B$ is in another tenant, is a restricted guest in the same tenant, or had their access revoked 5ms ago), let $R_{\text{fake}}$ be a newly generated random UUIDv4 that does not exist in the database.
For **every** endpoint $E(id)$ (`GET /api/issues/:id`, `PATCH /api/issues/:id`, `DELETE /api/issues/:id`, `GET /api/issues/:id/history`, `GET /api/attachments/:id`):
$$\text{Status}(B, E(R_{\text{private}})) = \text{Status}(B, E(R_{\text{fake}})) = 404$$
$$\text{Shape}(\text{Body}(B, E(R_{\text{private}}))) = \text{Shape}(\text{Body}(B, E(R_{\text{fake}})))$$

If `E(R_private)` returns `403 Forbidden`, `400 Bad Request`, or `200 []` (empty array) while `E(R_fake)` returns `404 Not Found`, the endpoint leaks the existence of private resources across tenants.

---

## 2. The 6-Actor × All-Surface Differential Matrix

Set up the local lab with a rich lifecycle state in `Tenant A` before running the oracle:
1. `Owner A` creates `Project Public` and `Project Secret`.
2. `Owner A` invites `Guest G` **only** to `Project Public`.
3. `Owner A` creates:
   - `Issue_Pub_1` in `Project Public` (`title: "roadmap alpha flag{CANARY_PUB_1}"`).
   - `Issue_Sec_2` in `Project Secret` (`title: "roadmap omega flag{CANARY_SEC_2}"`), edits it to generate `issue_history`, adds a comment, and uploads an attachment `Blob_Sec_2`.
   - `Issue_Moved_3`: Initially created in `Project Secret` with a secret comment `"merger price flag{CANARY_MOVED_3}"`, and then **moved** to `Project Public` (testing whether moving an issue leaks its prior restricted history/comments).
4. `Owner A` also creates and immediately revokes `RevokedUser R` and `RevokedApiKey K`.

Then the oracle automatically sweeps every surface across all 6 actors:

| Actor | Allowed Canaries | Forbidden Canaries (Must be 0%) | Expected Status on `Issue_Sec_2` & `Blob_Sec_2` |
|-------|------------------|---------------------------------|------------------------------------------------|
| `Owner A` (`Tenant A`) | `PUB_1`, `SEC_2`, `MOVED_3` | `CANARY_SSRF` | `200 OK` |
| `Member A` (`Tenant A`) | `PUB_1`, `SEC_2`, `MOVED_3` | `CANARY_SSRF` | `200 OK` (`404`/`403` on owner-only billing) |
| `Guest G` (`Tenant A`, `Project Public` only) | `PUB_1` only | `SEC_2`, `MOVED_3` (secret history), `CANARY_SSRF` | **`404 Not Found`** (identical to random UUID) |
| `Stranger B` (`Tenant B` Owner) | None (only `Tenant B` data) | `PUB_1`, `SEC_2`, `MOVED_3`, `CANARY_SSRF` | **`404 Not Found`** (identical to random UUID) |
| `Revoked R / K` (`Tenant A` revoked) | None | All canaries | **`401 Unauthorized`** |
| `Anonymous` | None | All canaries | **`401 Unauthorized`** |

---

## 3. Reference Implementation: Automated Differential & Anti-Enumeration Runner

```typescript
// differential-oracle.ts — Automated Side-Door & 404 Anti-Enumeration Verifier
export interface SurfaceProbe {
  readonly name: string;
  readonly kind: "primary_list" | "secondary_surface" | "by_id_probe";
  readonly execute: (credHeader: Record<string, string>, targetId?: string) => Promise<{
    status: number;
    bodyText: string;
  }>;
}

export async function runDifferentialOracle(params: {
  actorName: string;
  credHeader: Record<string, string>;
  forbiddenCanaries: ReadonlyArray<{ label: string; sha256: string; rawFlag: string }>;
  privateTargetIds: ReadonlyArray<string>;
  nonExistentId: string;
  probes: ReadonlyArray<SurfaceProbe>;
}): Promise<string[]> {
  const failures: string[] = [];

  for (const probe of params.probes) {
    if (probe.kind === "by_id_probe") {
      // Compare response for every private cross-tenant/restricted ID against a random non-existent UUID:
      const baseline = await probe.execute(params.credHeader, params.nonExistentId);

      for (const privateId of params.privateTargetIds) {
        const res = await probe.execute(params.credHeader, privateId);

        // 1. Check for canary leaks in response body:
        for (const canary of params.forbiddenCanaries) {
          if (res.bodyText.includes(canary.rawFlag)) {
            failures.push(
              `[CRITICAL CANARY LEAK] Actor=${params.actorName} Probe=${probe.name}(${privateId}) leaked ${canary.label}`
            );
          }
        }

        // 2. Check 404 Anti-Enumeration Indistinguishability:
        if (res.status !== baseline.status) {
          failures.push(
            `[EXISTENCE ORACLE] Actor=${params.actorName} Probe=${probe.name}: ` +
              `private ID returned HTTP ${res.status}, but non-existent ID returned HTTP ${baseline.status}`
          );
        }
      }
    } else {
      // Primary list or secondary surface (search, activity, exports, stats, MCP):
      const res = await probe.execute(params.credHeader);
      for (const canary of params.forbiddenCanaries) {
        if (res.bodyText.includes(canary.rawFlag)) {
          failures.push(
            `[CRITICAL SIDE-DOOR LEAK] Actor=${params.actorName} Surface=${probe.name} leaked ${canary.label}`
          );
        }
      }
    }
  }

  return failures;
}
```

---

## 4. Subtle Side-Door Traps Caught by This Oracle

1. **Empty Array `200 []` vs. `404 Not Found` on Child Collections:**
   - Calling `GET /api/issues/{private_issue_id}/comments` or `GET /api/issues/{private_issue_id}/history` often executes `SELECT * FROM comments WHERE issue_id = $1 AND tenant_id = $2` and returns `200 OK` with `[]` when the issue belongs to another project or tenant, whereas `GET /api/issues/{private_issue_id}` returns `404`. Always verify parent resource visibility first and return `404` when the parent does not exist in the caller's scope.
2. **Search Highlighting / Prefix Autocomplete (`q=flag` or `q=a`):**
   - Full-text search endpoints that query an inverted index (`FTS5` or `tsvector`) before filtering by guest project permissions leak restricted records via search snippets.
3. **Cross-Project Issue Moves (`Issue_Moved_3`):**
   - When an issue starts in `Project Secret` and is later moved to `Project Public`, `issue_history` rows recorded while the issue was in `Project Secret` remain attached to `issue_id`. The Differential Oracle immediately catches if `Guest G` can read those pre-move secret history entries.
