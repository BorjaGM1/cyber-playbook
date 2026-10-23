# Cache, Module-Global State & Derived Data (CDN, Data Cache, Indexes, RAG)

## 1. Attack Transcript

Three independent leaks; none requires a bug in authorization code.

```bash
# (a) Shared cache entry: Tenant A warms it, Tenant B reads it
$ curl -s -H "Cookie: __Host-session=$A" https://app.example.com/api/dashboard   # warms the cache
{"tenant":"Acme","revenue_ytd":1840000}
$ curl -s -H "Cookie: __Host-session=$B" https://app.example.com/api/dashboard
{"tenant":"Acme","revenue_ytd":1840000}                                            # B sees A's data

# (b) Web cache deception: attacker lures victim to a URL the CDN treats as a static asset
#     attacker's page:  <img src="https://app.example.com/account/settings/avatar.css">
#     victim (logged in) loads it -> origin ignores the suffix and returns the settings page -> CDN caches by extension
$ curl -s https://app.example.com/account/settings/avatar.css                      # attacker, no cookie
<html>… victim@example.com … csrf_token=… …</html>

# (c) Module-global request state: two sessions interleaved
$ for i in $(seq 200); do
    curl -s -H "Cookie: __Host-session=$A" https://app.example.com/api/me &
    curl -s -H "Cookie: __Host-session=$B" https://app.example.com/api/me &
  done | sort | uniq -c
    200 {"email":"a@acme.test"}
      3 {"email":"b@beta.test"}       # <- A's requests answered with B's identity (and vice versa)
```

## 2. Spot the Bug

```typescript
// 1. Next.js route handler
import { unstable_cache } from "next/cache";

export async function getDashboard(tenantId: string) {
  return unstable_cache(async () => queryDashboard(tenantId), ["dashboard"], { revalidate: 60 })();
}

// 2. Cloudflare Worker / Node server module
let currentUser: { id: string; tenantId: string } | null = null;

export default {
  async fetch(req: Request, env: Env) {
    currentUser = await authenticate(req, env);
    const rows = await loadRows(env);          // awaits: other requests run here
    return Response.json(rows.filter((r) => r.tenantId === currentUser!.tenantId));
  },
};

// 3. Memoized lookup
const projectCache = new Map<string, Promise<Project>>();
export const getProject = (id: string) =>
  projectCache.get(id) ?? projectCache.set(id, db.projects.findById(id)).get(id)!;

// 4. Semantic answer cache for an AI assistant
export async function answer(question: string, scope: TenantScope) {
  const hit = await semanticCache.lookup(embed(question), { threshold: 0.92 });
  if (hit) return hit.answer;
  const a = await llmAnswerWithContext(question, scope);
  await semanticCache.store(embed(question), a);
  return a;
}

// 5. Vector retrieval
const hits = await vectorStore.query({ vector: await embed(q), topK: 8 });
return hits.filter((h) => h.metadata.tenantId === scope.tenantId);
```

<details>
<summary>Reveal the bugs</summary>

1. `tenantId` is captured by the closure, not part of the cache key: `unstable_cache` keys on `keyParts` plus explicit arguments, so every tenant shares `["dashboard"]`.
2. Per-request identity stored in a module variable. Isolates and Node processes serve concurrent requests; the value is overwritten while another request is suspended at an `await`.
3. The memo key is the project ID alone, so the first caller's authorization decision is reused for everyone (and the cache outlives revocation).
4. The cache key is the question's embedding with no tenant, scope or policy version; near-duplicate questions return another tenant's answer.
5. Post-filtering `topK` after the engine returned results: other tenants' chunks crowd out the list (leaks existence, and under-fills results), and the metadata of foreign hits already crossed the process boundary. The tenant filter must be part of the query.

</details>

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I2 — Strict Tenancy & Capability Isolation` (cache/derived data are secondary surfaces: $\text{Visible}(A, S_{\text{cache}}) \subseteq \text{Visible}(A, S_{\text{primary}})$), plus `I1` for deception/poisoning. OWASP ASVS `v5.0.0-8.2.2`, `8.3.1`, `3.2.1`, `15.3.1`.
- **Mechanism:** Authorization is computed once on the way in, then the *result* is stored somewhere that is looked up by a key which does not contain the authorization context. Every cache, memo, index, embedding store and denormalized table is a second copy of data with its own (usually missing) access control and its own staleness.
- **Why happy-path tests pass:** a single-user test warms and hits its own cache. Leaks need two principals, concurrency, or a stale window.

### Where It Hides

- **Framework caches:** Next.js data cache / `fetch` caching, `unstable_cache`, route-segment `revalidate`/`force-static`, ISR pages that embed per-user data; React `cache()` (per-request only; wrong if hoisted to module scope).
- **CDN/edge caches:** extension- or path-based "static" rules, caching keyed without `Cookie`/`Authorization`, `Vary` omitted, query-string normalization, unkeyed headers (`X-Forwarded-Host`, locale) reflected in cached bodies (poisoning).
- **Key-value stores** (Workers KV, Redis) holding computed views, session-derived permissions or API-key lookups. KV is eventually consistent, which contradicts any "instant revocation" claim.
- **In-process memoization** (`Map`, `lru-cache`, `memoize`) keyed by resource ID only.
- **Module-global mutable state** in Workers isolates and Node servers: `let user`, `let tenant`, a shared `Headers` or buffer, singleton clients that remember "current" context.
- **Semantic/answer caches and prompt-assembly caches** for LLM features; **RAG/vector stores** where the tenant filter is optional or applied after retrieval; agent "memory" shared across users.
- **Search indexes** updated asynchronously (move, revoke and delete lag); **materialized views, summary tables and denormalized counters** without a tenant column or scope.

## 4. Hardened Pattern

### 4.1 Scoped cache keys, one wrapper, no raw cache access

```typescript
// src/cache/scoped-cache.ts   (the only module that touches the cache backend; lint-enforced)
function scopeFingerprint(scope: TenantScope): string {
  const grants = scope.kind === "guest" ? [...scope.allowedProjectIds].sort().join(",") : "*";
  return sha256Hex(`${scope.kind}|${scope.tenantId}|${grants}`).slice(0, 32);
}

export function scopedCacheKey(scope: TenantScope, namespace: string, ...parts: readonly string[]): string {
  // tenant is a visible prefix (for bulk invalidation); fingerprint separates member/guest views of the same tenant
  return ["v3", scope.tenantId, scopeFingerprint(scope), namespace, ...parts.map(encodeURIComponent)].join(":");
}

export async function cached<T>(
  scope: TenantScope, namespace: string, parts: readonly string[], ttlSec: number, load: () => Promise<T>
): Promise<T> {
  const key = scopedCacheKey(scope, namespace, ...parts);
  const hit = await backend.get(key);
  if (hit !== null) return hit as T;
  const value = await load();                   // `load` closes over a ScopedDb for THIS scope
  await backend.put(key, value, { ttl: Math.min(ttlSec, MAX_TTL_FOR[namespace] ?? 60) });
  return value;
}
```

Next.js: include every closure input in `keyParts` (`unstable_cache(fn, ["dashboard", tenantId, fingerprint], { tags: [`tenant:${tenantId}`] })`) and call `revalidateTag` on mutations; prefer not caching per-user data in the framework data cache at all.

### 4.2 Request-scoped state only

- Pass `scope`/`ScopedDb` **explicitly** down the call chain. On Node, `AsyncLocalStorage` is acceptable for request context; on Workers prefer explicit parameters (or the platform's per-request context object), and never assign request data to a module-level variable.
- Singletons hold only immutable configuration and connection pools.

```typescript
export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const scope = await resolveScope(req, env);        // local const
    const db = ScopedDb.forScope(scope);
    const rows = await loadRows(db);
    ctx.waitUntil(audit(scope, "list_rows"));          // closes over the local scope, not a global
    return Response.json(rows);
  },
};
```

### 4.3 Response caching headers: deny by default

```typescript
export function withCachePolicy(req: Request, res: Response, routePolicy: "public-static" | "private"): Response {
  const authed = req.headers.has("cookie") || req.headers.has("authorization");
  if (routePolicy === "public-static" && !authed) return res;       // only explicitly allowlisted, anonymous, static routes
  const h = new Headers(res.headers);
  h.set("cache-control", "private, no-store");
  h.append("vary", "Cookie, Authorization");
  return new Response(res.body, { status: res.status, headers: h });
}
```

Origin rules against **web cache deception**: unknown path suffixes return `404` (the origin must not "ignore" `/settings/x.css`), authenticated responses never carry public cache headers, and the CDN is configured to cache only an explicit allowlist of static asset paths and to respect origin `Cache-Control`.

### 4.4 LLM caches and RAG

```typescript
// Semantic/answer cache: scope fingerprint and policy version are part of the lookup, not just the embedding
const hit = await semanticCache.lookup(embed(question), {
  threshold: 0.95,
  partition: scopedCacheKey(scope, "answer", POLICY_VERSION),
});

// Vector store: the namespace/filter is mandatory and server-side; retrieval returns candidates, hydration authorizes
export async function retrieve(scope: TenantScope, db: ScopedDb, query: string) {
  const vec = await embed(query);
  const candidates = await vectorStore.query({
    vector: vec, topK: 24,
    namespace: scope.tenantId,                                         // one namespace per tenant, or...
    filter: scope.kind === "guest" ? { projectId: { $in: [...scope.allowedProjectIds] } } : undefined,
  });
  const visible = await db.select("documents").where("documents.id", "in", candidates.map((c) => c.docId)).execute();
  const ok = new Set(visible.map((d) => d.id));
  return candidates.filter((c) => ok.has(c.docId)).slice(0, 8);       // chunks of deleted/moved/revoked docs drop out here
}
```

### 4.5 Search indexes, derived tables and counters

- The index is a **candidate generator**: hydrate every hit through `ScopedDb`; compute `total`/facets from hydrated rows ([`side-door-data-leaks.md`](side-door-data-leaks.md)).
- Index writes carry `tenantId` and `projectId` as indexed filter fields; deletes and moves are applied synchronously for revocation-sensitive changes or covered by hydration while the index catches up.
- Materialized views and summary tables are tenant tables: they carry the tenant column, are registered in `ScopedDb`, and the catalog test fails CI if a view or matview with a tenant column is not registered ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
- Denormalized counters (`project.open_issue_count`) are read through the same visibility predicate or shown only to scopes allowed to see every underlying row.

## 5. Residual Edge Cases

- **Revocation latency.** A scoped key stops *cross-tenant* leaks; it does not make a cached view disappear when a permission changes. Keep permission-bearing caches short-lived (seconds), include a per-tenant "authz epoch" in the key that increments on membership/grant changes, and state the revocation SLO. KV and read replicas are eventually consistent; do not claim zero grace.
- **Key collisions through concatenation.** Percent-encode parts (as above) so `("a:b","c")` and `("a","b:c")` cannot collide.
- **Fingerprint truncation** is fine for separation, not for secrecy; do not put secrets in keys or logs.
- **Negative caching.** Caching a `404`/"not allowed" under a key without scope turns one user's denial into everyone's.
- **Prompt/provider caches.** Provider-side prompt caching is isolated per organization by the provider, but your own prompt-assembly cache is not; keep tenant data out of any shared cached prefix.
- **Agent memory.** Long-term memory stores need the same namespace discipline as a vector store; per-user memories must not be retrievable by other users of the tenant ([`../injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../injection-and-trust-boundaries/agentic-and-mcp-threats.md)).
- **Framework version behavior.** Whether request headers participate in a framework's fetch-cache key differs across versions; do not rely on it for authorization context, and test with the lab instead of reading docs.
- **Background refresh** (stale-while-revalidate) runs without the user: it must rebuild a scope ([`async-jobs-and-scope-propagation.md`](async-jobs-and-scope-propagation.md)).

## 6. How to Discover It Automatically

### A. Static
```bash
# Module-scope mutable variables in server code (candidate cross-request state)
rg -n '^(let|var)\s+\w+' src/ --glob '!**/*.test.*' --glob '!src/**/config*'
rg -n '^(export\s+)?const\s+\w+\s*=\s*new\s+(Map|Set|WeakMap)\(' src/

# Framework and library caches: inspect each key for tenant/scope inputs
rg -n 'unstable_cache\(|React\.cache\(|\bcache\(|memoize\(|lru-cache|new LRUCache|revalidate\s*[:=]|force-cache|force-static' src/

# Edge/CDN rules that cache by extension or path
rg -n -i 'cache-everything|edge_ttl|\.(css|js|png|svg)\$' infra/ wrangler.toml *.tf 2>/dev/null
```

```yaml
# rules/no-module-mutable-state.yml (ast-grep)
id: no-top-level-mutable-state
language: typescript
severity: error
rule:
  any:
    - pattern: let $X = $$$
    - pattern: var $X = $$$
  inside: { kind: program, stopBy: end }
files: ["src/**"]
ignores: ["src/**/*.test.ts", "src/config/**"]
---
id: unstable-cache-closure-not-in-key
language: typescript
severity: warning        # needs human review: report closures capturing identifiers absent from keyParts
rule:
  pattern: unstable_cache($FN, [$$$KEYS], $$$)
```

### B. Dynamic
1. **Two-actor cache probe.** For every GET route: request as A (warm), then as B (and as anonymous) with the same URL, plus variants (`?x=1`, trailing slash, `.css`/`.js`/`.png` suffix appended to dynamic paths, `Accept-Language`, `X-Forwarded-Host`). Assert B/anonymous responses contain no A canary and that the suffix variants return `404`.
2. **Header audit.** Assert every response to a credentialed request carries `Cache-Control: private, no-store` (or an allowlisted exception) and `Vary` including `Cookie`/`Authorization`.
3. **Interleaving harness for module-global state.** Fire barrier-synchronized bursts of A and B requests against each route (the race harness in [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md)) with awaits made likely by adding latency to the mock database; assert zero cross-identity responses. Run it under the production runtime (isolate, not a mocked unit).
4. **Stale-window probe.** Revoke or move, then read through cache/index/vector paths within and after the documented SLO; assert denial after the SLO and measure the actual window.
5. **Semantic/RAG probe.** Plant a canary in A's documents; as B ask paraphrases of questions whose answers would include it; assert none returned, and that deleted/moved documents disappear from retrieval.
6. **Query-log oracle** on index hydration and cache-fill paths ([`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)), and the parity sweep in [`../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md) extended with cache/index/vector surfaces.

## 7. How to Eliminate the Bug Class by Construction

1. **No raw cache/memo/index/vector client in request code.** Only the scoped wrappers (`cached(scope, …)`, `retrieve(scope, db, …)`) are importable; the key builder takes a `TenantScope`, so a key without a tenant cannot be built.
2. **Ban module-level mutable state in server code** by lint (rule above); request state travels as parameters or `AsyncLocalStorage`.
3. **Default-deny response caching** (Section 4.3) plus an origin that 404s unknown suffixes.
4. **Index and cache hold IDs; `ScopedDb` holds authority.** Hydrate before returning.
5. **Register every derived table, view and materialized view** with a tenant column in the `ScopedDb` registry; the catalog test makes an unregistered one a CI failure ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
