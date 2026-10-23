# Step 2: Differential Surface & Side-Door Oracles

## 1. Mental Model (Catching Leaks Without Knowing Where They Are)

How do you automatically detect authorization bugs across 40 endpoints—including search, activity history, exports, aggregates, webhooks, and MCP tools—without writing 40 custom test assertions by hand?

You use a **Differential Surface Oracle** built on two properties of multi-tenant applications. Both are **computed** by the reference implementation below (an earlier revision only substring-matched canaries, so ID/count/metadata leaks without a canary went undetected).

### Property 1: Cross-Surface Visibility Subset (`Side-Door Parity`)
For any actor $A$, let $\text{PrimaryIDs}_k(A)$ be the set of kind-$k$ resource UUIDs (issues, projects, attachments, users…) returned by the primary authenticated list endpoints. Then for **every** secondary surface $S \in \{\text{Search}, \text{ActivityFeed}, \text{IssueHistory}, \text{CsvExport}, \text{Attachments}, \text{Stats}, \text{McpTools}\}$:
$$\big(\text{ReferencedIDs}_k(A, S) \cap \text{SeededUniverse}_k\big) \setminus \text{PrimaryIDs}_k(A) \setminus \text{IntendedExposures}(A, S) = \varnothing$$
$$\text{CanariesVisible}(A, S) \subseteq \text{CanariesVisible}(A, \text{Primary})$$

Because the lab seeded every entity, "ReferencedIDs ∩ SeededUniverse" is exact: any seeded ID that appears in a secondary surface but not in the actor's primary view is a leak, with or without a canary in the body.

If `ProjectGuest G` sees **1** issue on `GET /api/issues`, but `GET /api/search?q=a`, `GET /api/activity`, or `mcp.call("list_issues")` returns **2** issues (or a count of `7`, or a snippet from `Project Secret`), the oracle flags a **Critical Side-Door Leak**.

### Property 2: Unauthorized Indistinguishability (`404 Anti-Enumeration Oracle`)
For any actor $B$ without access to $R_{\text{private}}$ (another tenant, a restricted guest in the same tenant, or access revoked 5 ms ago), let $R_{\text{fake}}$ be a fresh random UUIDv4. For **every** endpoint $E(id)$:
$$\text{Status}(B, E(R_{\text{private}})) = \text{Status}(B, E(R_{\text{fake}})) = 404$$
$$\text{Headers}^{*}(\cdot)\ \text{equal},\quad \text{Shape}(\text{Body}(\cdot))\ \text{equal},\quad \text{Normalize}(\text{Body}(\cdot))\ \text{equal}$$
where $\text{Headers}^{*}$ is the allowlisted comparable subset and $\text{Normalize}$ replaces the requested ID with a placeholder.
Timing is compared as an advisory (Section 5): a statistically separable gap is a lead for a human or micro-agent, not an automatic failure.

---

## 2. The Actor × All-Surface Differential Matrix

Set up the lab with a rich lifecycle state in `Tenant A` ([`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md)):
1. `Owner A` creates `Project Public` and `Project Secret`.
2. `Owner A` invites `Guest G` **only** to `Project Public`.
3. `Owner A` creates:
   - `Issue_Pub_1` in `Project Public` (visible).
   - `Issue_Sec_2` in `Project Secret`, edits it (history), adds a comment, uploads `Blob_Sec_2`.
   - `Issue_Moved_3`: created in `Project Secret` with a secret comment, then **moved** to `Project Public` (does move leak prior restricted history/comments?).
   - `Issue_Del_4`: carries a canary, then is **soft-deleted** (deleted-resource oracle).
   - **7 hidden items** in `Project Secret` (count canary) beside 2 visible ones.
4. `Owner A` creates and immediately revokes `RevokedUser R` and `RevokedApiKey K`.
5. `Member A` exists with the lowest full-member role (vertical-escalation probes).

| Actor | Allowed | Forbidden (must be 0%) | Expected on `Issue_Sec_2` / `Blob_Sec_2` |
|-------|---------|------------------------|-----------------------------------------|
| `Owner A` | `PUB_1`, `SEC_2`, `MOVED_3` | `Issue_Del_4` canary (outside the explicit trash surface), all SSRF fixtures | `200` |
| `Member A` | `PUB_1`, `SEC_2`, `MOVED_3` | `Issue_Del_4`, owner-only data | `200`; owner-only routes `403`/`404` |
| `Guest G` (`Public` only) | `PUB_1` | `SEC_2`, `MOVED_3` pre-move history/comments, hidden-count `7`, `Issue_Del_4` | **`404`** (identical to random UUID) |
| `Stranger B` | own tenant only | everything of `Tenant A` | **`404`** |
| `Revoked R / K` | none | all canaries | **`401`** |
| `Anonymous` | none | all canaries | **`401`** |

`intended-exposures.yaml` (human-confirmed, one file per app) is the **only** way a surface may show more than the primary view:

```yaml
# intended-exposures.yaml
- surface: "GET /api/members"
  actors: [GuestG]
  kinds: [user]
  reason: "guests may see names of members of projects they belong to"
  fields: [id, displayName]          # email must NOT appear
- surface: "GET /public/share/:token"
  actors: [Anonymous]
  kinds: [issue]
  reason: "explicit public share link"
```

---

## 3. Reference Implementation: Automated Differential, Subset and Anti-Enumeration Runner

```typescript
// differential-oracle.ts — Side-door parity, indistinguishability, deleted/revoked/vertical oracles
import { scanOutputForCanaries, scanCounts } from "./canary-lab.mjs";

export interface Observed {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  elapsedMs: number;
}
export interface Actor { name: string; headers: Record<string, string> }
export interface Probe {
  readonly name: string;
  readonly kind: "primary_list" | "secondary_surface" | "by_id_probe";
  /** entity kinds whose IDs this probe is the primary/secondary view of */
  readonly kinds?: readonly string[];
  readonly execute: (actor: Actor, targetId?: string) => Promise<Observed>;
}
export interface Exposure { surface: string; actors: string[]; kinds: string[]; fields?: string[] }

const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
export const extractIds = (text: string): Set<string> =>
  new Set((text.match(UUID) ?? []).map((s) => s.toLowerCase()));

// ---- Property 2 helpers -------------------------------------------------------------------

const COMPARABLE_HEADERS = ["content-type", "cache-control", "www-authenticate", "vary",
  "content-security-policy", "x-content-type-options", "referrer-policy"];

export function comparableHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of COMPARABLE_HEADERS) if (h[k] !== undefined) out[k] = h[k];
  const setCookie = h["set-cookie"];
  if (setCookie) out["set-cookie-names"] = setCookie.split(/,(?=\s*[\w-]+=)/).map((c) => c.split("=")[0].trim()).sort().join(",");
  return out;
}

/** Structural fingerprint: keys and value *types*, never values. */
export function bodyShape(text: string): string {
  const fp = (v: unknown): string => {
    if (v === null) return "null";
    if (Array.isArray(v)) return v.length ? `[${fp(v[0])}]` : "[]";
    if (typeof v === "object") return `{${Object.keys(v as object).sort().map((k) => `${k}:${fp((v as Record<string, unknown>)[k])}`).join(",")}}`;
    return typeof v;
  };
  try { return fp(JSON.parse(text)); } catch { return `text:${text.length > 0 ? "nonempty" : "empty"}`; }
}

export const normalizeBody = (text: string, requestedId: string, volatile: RegExp[] = []): string =>
  volatile.reduce((t, re) => t.replace(re, "<VOLATILE>"), text.split(requestedId).join("<ID>"));

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

export interface Indistinguishability {
  statusEqual: boolean; headersEqual: boolean; shapeEqual: boolean; bodyEqual: boolean;
  timingSuspect: boolean; detail: string[];
}

export async function compareUnauthorized(
  probe: Probe, actor: Actor, privateId: string, fakeId: string,
  opts: { volatile?: RegExp[]; timingSamples?: number } = {}
): Promise<Indistinguishability> {
  const n = opts.timingSamples ?? 15;
  const privT: number[] = [], fakeT: number[] = [];
  let priv!: Observed, fake!: Observed;
  for (let i = 0; i < n; i++) {                       // interleave to cancel drift
    priv = await probe.execute(actor, privateId); privT.push(priv.elapsedMs);
    fake = await probe.execute(actor, fakeId);    fakeT.push(fake.elapsedMs);
  }
  const detail: string[] = [];
  const statusEqual = priv.status === fake.status;
  if (!statusEqual) detail.push(`status ${priv.status} vs ${fake.status}`);
  const hp = JSON.stringify(comparableHeaders(priv.headers));
  const hf = JSON.stringify(comparableHeaders(fake.headers));
  const headersEqual = hp === hf;
  if (!headersEqual) detail.push(`headers ${hp} vs ${hf}`);
  const shapeEqual = bodyShape(priv.bodyText) === bodyShape(fake.bodyText);
  if (!shapeEqual) detail.push("body shape differs");
  const bodyEqual = normalizeBody(priv.bodyText, privateId, opts.volatile) === normalizeBody(fake.bodyText, fakeId, opts.volatile);
  if (!bodyEqual) detail.push("normalized body differs");
  const [mp, mf] = [median(privT), median(fakeT)];
  const timingSuspect = Math.abs(mp - mf) > 5 && Math.max(mp, mf) / Math.max(1, Math.min(mp, mf)) > 1.5;
  if (timingSuspect) detail.push(`timing median ${mp.toFixed(1)}ms vs ${mf.toFixed(1)}ms`);
  return { statusEqual, headersEqual, shapeEqual, bodyEqual, timingSuspect, detail };
}

// ---- Property 1: the real subset computation ------------------------------------------------

export interface SweepParams {
  actor: Actor;
  canaryRegistry: ReadonlyArray<{ label: string; token: string; rawFlag: string; sha256: string }>;
  forbiddenLabels: ReadonlySet<string>;
  universe: Readonly<Record<string, ReadonlySet<string>>>;   // kind -> all seeded ids of that kind
  probes: ReadonlyArray<Probe>;
  exposures: ReadonlyArray<Exposure>;
  counts?: { hiddenCount: number; expectedVisible: number };
  privateTargetIds: ReadonlyArray<string>;
  nonExistentId: string;
}

export async function runDifferentialOracle(p: SweepParams): Promise<string[]> {
  const failures: string[] = [];
  const forbidden = p.canaryRegistry.filter((c) => p.forbiddenLabels.has(c.label));

  // 1. Primary view per kind.
  const primary: Record<string, Set<string>> = {};
  for (const probe of p.probes.filter((x) => x.kind === "primary_list")) {
    const res = await probe.execute(p.actor);
    const ids = extractIds(res.bodyText);
    for (const kind of probe.kinds ?? []) {
      primary[kind] ??= new Set();
      for (const id of ids) if (p.universe[kind]?.has(id)) primary[kind].add(id);
    }
  }

  // 2. Every secondary surface: canaries, counts, and the subset property.
  for (const probe of p.probes.filter((x) => x.kind === "secondary_surface")) {
    const res = await probe.execute(p.actor);
    for (const hit of scanOutputForCanaries(res.bodyText, forbidden)) {
      failures.push(`[CRITICAL SIDE-DOOR LEAK] actor=${p.actor.name} surface=${probe.name} canary=${hit.label} via=${hit.kind}`);
    }
    if (p.counts) {
      try {
        for (const c of scanCounts(JSON.parse(res.bodyText), p.counts)) {
          failures.push(`[COUNT LEAK] actor=${p.actor.name} surface=${probe.name} ${c.path}=${c.value}`);
        }
      } catch { /* non-JSON surface */ }
    }
    const referenced = extractIds(res.bodyText);
    for (const kind of probe.kinds ?? []) {
      const allowed = new Set<string>(primary[kind] ?? []);
      const exposed = p.exposures.some((e) => e.surface === probe.name && e.actors.includes(p.actor.name) && e.kinds.includes(kind));
      if (exposed) continue;
      for (const id of referenced) {
        if (p.universe[kind]?.has(id) && !allowed.has(id)) {
          failures.push(`[SUBSET VIOLATION] actor=${p.actor.name} surface=${probe.name} kind=${kind} id=${id} not in primary view`);
        }
      }
    }
  }

  // 3. By-ID probes: canary scan + full indistinguishability against a random UUID.
  for (const probe of p.probes.filter((x) => x.kind === "by_id_probe")) {
    for (const privateId of p.privateTargetIds) {
      const cmp = await compareUnauthorized(probe, p.actor, privateId, p.nonExistentId);
      if (!cmp.statusEqual || !cmp.headersEqual || !cmp.shapeEqual || !cmp.bodyEqual) {
        failures.push(`[EXISTENCE ORACLE] actor=${p.actor.name} probe=${probe.name}(${privateId}): ${cmp.detail.join("; ")}`);
      } else if (cmp.timingSuspect) {
        failures.push(`[TIMING_SUSPECT advisory -> residual] actor=${p.actor.name} probe=${probe.name}: ${cmp.detail.join("; ")}`);
      }
      const res = await probe.execute(p.actor, privateId);
      for (const hit of scanOutputForCanaries(res.bodyText, forbidden)) {
        failures.push(`[CRITICAL CANARY LEAK] actor=${p.actor.name} probe=${probe.name}(${privateId}) canary=${hit.label}`);
      }
    }
  }
  return failures;
}

// ---- Deleted-resource oracle ---------------------------------------------------------------

/** After Owner soft-deletes a canary-bearing entity, NO surface for ANY actor may still show it (except an allowlisted trash surface). */
export async function runDeletedResourceOracle(
  actors: ReadonlyArray<Actor>, probes: ReadonlyArray<Probe>,
  deletedCanary: { label: string; token: string; rawFlag: string; sha256: string }, deletedId: string,
  trashSurfaces: ReadonlySet<string>
): Promise<string[]> {
  const failures: string[] = [];
  for (const actor of actors) for (const probe of probes) {
    if (trashSurfaces.has(probe.name) && probe.kind !== "by_id_probe") continue;
    const res = await probe.execute(actor, probe.kind === "by_id_probe" ? deletedId : undefined);
    const leaks = scanOutputForCanaries(res.bodyText, [deletedCanary]);
    if (leaks.length || (probe.kind !== "by_id_probe" && extractIds(res.bodyText).has(deletedId.toLowerCase()))) {
      failures.push(`[DELETED RESOURCE STILL VISIBLE] actor=${actor.name} surface=${probe.name}`);
    }
    if (probe.kind === "by_id_probe" && res.status !== 404) {
      failures.push(`[DELETED RESOURCE BY-ID] actor=${actor.name} surface=${probe.name} status=${res.status}`);
    }
  }
  return failures;
}

// ---- Revoked-actor oracle --------------------------------------------------------------------

/**
 * Credentials captured BEFORE revocation must fail on every surface after it. With a read replica / KV the
 * documented revocation SLO applies: poll up to sloMs, but the FIRST post-commit denial must hold forever (no flapping).
 */
export async function runRevokedActorOracle(
  revoked: Actor, probes: ReadonlyArray<Probe>, sloMs: number
): Promise<string[]> {
  const failures: string[] = [];
  for (const probe of probes) {
    const deadline = Date.now() + sloMs;
    let denied = false, flapped = false, last = 0;
    do {
      const res = await probe.execute(revoked);
      last = res.status;
      if (res.status === 401) denied = true;
      else if (denied) flapped = true;                // a 2xx after a 401 = stale replica / cache race
      await new Promise((r) => setTimeout(r, 25));
    } while (Date.now() <= deadline);
    if (!denied) failures.push(`[REVOCATION NOT EFFECTIVE within ${sloMs}ms] surface=${probe.name} last=${last}`);
    if (flapped) failures.push(`[REVOCATION FLAPPING] surface=${probe.name}`);
  }
  return failures;
}

// ---- Vertical privilege escalation (same-tenant member -> owner) ---------------------------------

export interface OwnerOnlyRoute { method: string; path: string; body?: unknown; minRole: "owner" | "admin" }

export const SELF_ESCALATION_BODIES: ReadonlyArray<{ name: string; method: string; path: (self: string) => string; body: unknown }> = [
  { name: "self-promote via members route", method: "PATCH", path: (s) => `/api/members/${s}`, body: { role: "owner" } },
  { name: "mass-assign role in profile update", method: "PATCH", path: () => "/api/me", body: { role: "owner", isAdmin: true } },
  { name: "invite above own role", method: "POST", path: () => "/api/invites", body: { email: "x@lab.test", role: "owner" } },
  { name: "mint key with broader scope", method: "POST", path: () => "/api/keys", body: { scopes: ["*"], role: "owner" } },
];

export async function runVerticalEscalationProbes(
  member: Actor, memberId: string,
  ownerOnly: ReadonlyArray<OwnerOnlyRoute>,
  send: (actor: Actor, method: string, path: string, body?: unknown) => Promise<Observed>,
  snapshotDiff: () => Promise<number>        // number of changed rows in Tenant A since baseline (DB-level)
): Promise<string[]> {
  const failures: string[] = [];
  for (const r of ownerOnly) {
    const res = await send(member, r.method, r.path, r.body);
    if (res.status < 400 || res.status >= 500) failures.push(`[VERTICAL ESCALATION] ${member.name} ${r.method} ${r.path} -> ${res.status}`);
  }
  for (const s of SELF_ESCALATION_BODIES) {
    await send(member, s.method, s.path(memberId), s.body);
  }
  const changed = await snapshotDiff();
  if (changed > 0) failures.push(`[VERTICAL ESCALATION STATE CHANGE] ${changed} Tenant A rows changed after member self-escalation probes`);
  return failures;
}
```

---

## 4. Subtle Side-Door Traps Caught by This Oracle

1. **Empty Array `200 []` vs. `404 Not Found` on Child Collections:** `GET /api/issues/{private}/comments` often runs `SELECT … WHERE issue_id = $1 AND tenant_id = $2` and returns `200 []`, while `GET /api/issues/{private}` returns `404`. Verify the parent first and return `404` when the parent is not in the caller's scope. `compareUnauthorized` catches this through status, shape and normalized-body differences against a random UUID.
2. **Search Highlighting / Prefix Autocomplete (`q=a`):** Full-text endpoints that query an inverted index before filtering by guest project permissions leak restricted records through snippets and counts. The squashed/fragment scanner and `scanCounts` catch highlight-split tokens and `total: 7`.
3. **Cross-Project Issue Moves (`Issue_Moved_3`):** History rows and comments recorded while the issue lived in `Project Secret` remain attached to `issue_id`. The oracle checks that `Guest G` sees none of the pre-move content on any surface.
4. **Soft-Deleted Rows on Side Surfaces:** `deleted_at IS NULL` is applied on the primary list and forgotten in search, export, and aggregates. See `runDeletedResourceOracle`.
5. **Revocation Through a Cache or Replica:** the first `401` followed by a later `200` (flapping) is a stale read replica or per-instance cache; see `runRevokedActorOracle` and the SLO discussion in [`../strategy/five-universal-invariants.md`](../strategy/five-universal-invariants.md).
6. **Counts and Aggregates:** `GET /api/projects/stats` returning `issueCount: 9` for a guest who can see 2 issues leaks the existence of 7 hidden ones even with no canary text.

---

## 5. Timing Is an Advisory Oracle

Response-time differences between an existing-but-forbidden and a non-existent ID can distinguish them even when status, headers and bodies are identical (an extra authorization query runs only when the row exists). Because timing is noisy, the oracle:

- interleaves 15 samples per side and compares medians;
- flags only when the gap exceeds both `5 ms` absolute and `1.5×` relative;
- **never fails the build on timing alone**; it adds `TIMING_SUSPECT` to the residual list ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md)) for a micro-agent or human to confirm with more samples and a quiet machine.

The structural fix is in [`../1-known-vulnerabilities/authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md`](../1-known-vulnerabilities/authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md): a single scoped query that returns "no row" for both cases, so there is no second code path to time.
