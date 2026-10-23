# Next.js, RSC & Edge-Runtime Specifics (Middleware Bypass, Server Actions, Prop Leaks, Workers)

> **Invariants:** `I1 — Authentic Identity & Purpose Binding`, `I2 — Strict Tenancy & Capability Isolation`, `I4 — Context-Safe Boundary Parsing` (OWASP ASVS `v5.0.0-8.2.1`, `8.3.1`, `3.5.1`, `15.3.1`, `14.2.1`).
> Related: [`jwt-and-edge-header-spoofing.md`](jwt-and-edge-header-spoofing.md) · [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md) · [`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md) · [`../injection-and-trust-boundaries/browser-boundary.md`](../injection-and-trust-boundaries/browser-boundary.md) · [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)

This note covers the failure modes that are specific to App Router / RSC / Server Actions stacks and to Workers-style edge runtimes. They share one root cause: **authorization performed at a routing layer that the framework does not guarantee runs for every code path that reaches the data.**

---

## 1. Attack Transcript

**1a. Middleware skipped by a request header (`CVE-2025-29927`).** Next.js used an internal header, `x-middleware-subrequest`, to stop recursive middleware invocations. Per the advisory ([GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw)), a client that sent a value naming the middleware skipped it entirely on self-hosted deployments. Affected and first patched versions: `next` >= 12.0.0, < 12.3.5 (patched 12.3.5); >= 13.0.0, < 13.5.9 (patched 13.5.9); >= 14.0.0, < 14.2.25 (patched 14.2.25); >= 15.0.0, < 15.2.3 (patched 15.2.3).

```http
GET /dashboard/billing HTTP/1.1
Host: app.example.com
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

HTTP/1.1 200 OK
<html>... billing page for an unauthenticated visitor ...
```

**1b. Matcher gap.** Auth lives only in `middleware.ts` with `matcher: ["/dashboard/:path*"]`. The same data is reachable by routes the matcher never names.

```http
GET /_next/data/BUILDID/dashboard/billing.json HTTP/1.1
GET /api/billing/invoices HTTP/1.1
GET /dashboard/billing/ HTTP/1.1
GET /dashboard/billing.json HTTP/1.1
```

```http
HTTP/1.1 200 OK
{"pageProps":{"invoices":[{"id":"inv_1","amount":99900, "customerEmail":"cfo@victim.example"}]}}
```

**1c. A Server Action is a public POST endpoint.** The client bundle contains the action ID; any HTTP client can call it.

```http
POST /dashboard HTTP/1.1
Host: app.example.com
Next-Action: 7f8a2c...e1
Content-Type: text/plain;charset=UTF-8

["usr_victim"]

HTTP/1.1 200 OK
0:{"a":"$@1","f":"","b":"..."}
1:{"ok":true,"deleted":"usr_victim"}
```

---

## 2. Spot the Bug

Four independent problems across these four files.

```typescript
// middleware.ts
export const config = { matcher: ["/dashboard/:path*"] };
export function middleware(req: NextRequest) {
  if (!req.cookies.get("session")) return NextResponse.redirect(new URL("/login", req.url));
}

// app/dashboard/team/page.tsx   (Server Component)
export default async function TeamPage() {
  const members = await db.select().from(users).where(eq(users.orgId, await currentOrgId()));
  return <TeamTable members={members} />;
}

// app/dashboard/team/TeamTable.tsx
"use client";
export function TeamTable({ members }: { members: User[] }) {
  return <ul>{members.map(m => <li key={m.id}>{m.name}</li>)}</ul>;
}

// app/dashboard/team/actions.ts
"use server";
export async function removeMember(userId: string) {
  await db.delete(users).where(eq(users.id, userId));
}
```

---

## 3. Invariant Violated & Mechanism

1. **Middleware is a convenience layer, not an authorization boundary.** It can be skipped (`CVE-2025-29927`), it runs only on matched paths, and path normalization differs between the matcher, the router, the data-route layer (`/_next/data/...`) and any proxy in front. A request that reaches a handler without crossing middleware must still be denied.
2. **A matcher is a deny-list in disguise.** `["/dashboard/:path*"]` protects what is named. New routes, `.json` variants, trailing-slash forms, `/api/*`, route groups and parallel/intercepting routes are unprotected by default. Default-allow at the routing layer plus "remember to add the path" is the bug.
3. **Server Actions are endpoints.** `"use server"` exports are invokable by anyone who can reach the app, by action ID, without rendering the page. Page-level auth (or hiding the button) does not apply. Server Action IDs must not be treated as an authorization control.
4. **RSC props are serialized to the browser.** In `TeamPage`, `members` is the full `users` row (hashes, emails, flags) passed to a Client Component. Everything in props is shipped in the HTML/RSC payload, regardless of what the component renders. `SELECT *` + client prop = over-fetch to the browser (ASVS `15.3.1`). `NEXT_PUBLIC_*` variables are inlined into the client bundle at build time.
5. **No ownership check on the mutation.** `removeMember(userId)` deletes by ID with no tenant predicate: IDOR, see [`../authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md`](../authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md).
6. **Image optimizer SSRF.** `/_next/image?url=...` fetches remote URLs allowed by `images.remotePatterns`/`domains`. Wildcard or over-broad patterns turn it into an SSRF/proxy and a content-type confusion primitive.
7. **Edge-vs-origin path differentials** (shared with [`jwt-and-edge-header-spoofing.md`](jwt-and-edge-header-spoofing.md)): the CDN/Access policy, the framework matcher and the file-system router each normalize `//`, `;`, `%2f`, case and trailing slashes differently.
8. **Edge-runtime (Workers-style) hazards:** module-level mutable state is shared across concurrent requests in an isolate (see [`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md)); the default platform hostname bypasses edge access policy; bindings (KV, R2, D1, service bindings, Durable Object stubs) are ambient authority inside the isolate, so an ID taken from the request and passed to a binding is a direct object reference.

Why happy-path tests pass: E2E tests browse the UI through middleware as a logged-in user. Nobody sends the bypass header, requests the `.json` data route anonymously, or calls the action by ID from `curl`.

---

## 4. Hardened Pattern

### 4.1 Authorize in a data-access layer, call it from every entry, treat middleware as optimistic redirect only

```typescript
// server/auth/actor.ts   (the only module that can construct an Actor)
import "server-only";

const ACTOR = Symbol("actor");
export interface Actor {
  readonly [ACTOR]: true;
  readonly userId: string;
  readonly tenantId: string;
  readonly role: "owner" | "member" | "guest";
}

export async function requireActor(): Promise<Actor> {
  const actor = await resolveActorFromSession(); // opaque server-side session, see cookie-purpose note
  if (!actor) throw new Response(null, { status: 401 });
  return actor;
}
```

```typescript
// server/dal/team.ts   (Data Access Layer: every function takes an Actor and returns a DTO)
import "server-only";

export interface TeamMemberDto { readonly id: string; readonly name: string }

export async function listTeam(actor: Actor): Promise<TeamMemberDto[]> {
  const db = scopedDb(actor); // see ../../strategy/scoped-db.md: tenant predicate is injected, not remembered
  const rows = await db.select(usersTable, { columns: ["id", "name"] });
  return rows.map((r) => ({ id: r.id, name: r.name })); // explicit allowlist; never a raw row
}

export async function removeMember(actor: Actor, userId: string): Promise<boolean> {
  if (actor.role !== "owner") return false;
  const db = scopedDb(actor);
  return (await db.delete(usersTable, { id: userId })) === 1; // tenant predicate injected; 0 rows => 404
}
```

```typescript
// app/dashboard/team/page.tsx
export default async function TeamPage() {
  const actor = await requireActor();                 // authorization lives here, not in middleware
  return <TeamTable members={await listTeam(actor)} />; // DTO only
}

// app/dashboard/team/actions.ts
"use server";
import { headers } from "next/headers";

export async function removeMemberAction(userId: string) {
  await assertSameOriginMutationFromHeaders(await headers()); // Origin/Sec-Fetch-Site check, see cookie note
  const input = z.string().uuid().parse(userId);               // validate: it is an untrusted network input
  const actor = await requireActor();
  if (!(await removeMember(actor, input))) notFound();
}
```

### 4.2 Middleware: default-deny matcher, strip the internal header, never the only check

```typescript
// middleware.ts
export const config = {
  // Match everything except explicit static assets; new routes are protected by default.
  matcher: ["/((?!_next/static|favicon.ico|robots.txt).*)"],
};

const PUBLIC = new Set(["/", "/login", "/auth/callback", "/api/health"]);

export function middleware(req: NextRequest) {
  const headers = new Headers(req.headers);
  headers.delete("x-middleware-subrequest"); // belt-and-braces; also strip at the proxy/CDN

  const path = req.nextUrl.pathname.replace(/\/+$/, "") || "/";
  if (!PUBLIC.has(path) && !req.cookies.get("__Host-session")) {
    return NextResponse.redirect(new URL("/login", req.url)); // optimistic UX only
  }
  return NextResponse.next({ request: { headers } });
}
```

The real fix for `CVE-2025-29927` is upgrading to a patched release; the header strip and, above all, per-handler `requireActor()` mean the next framework-level skip is not an incident.

### 4.3 Images and config

```typescript
// next.config.ts
images: {
  remotePatterns: [{ protocol: "https", hostname: "cdn.example.com", pathname: "/uploads/**" }], // exact host, no wildcards
},
serverActions: { allowedOrigins: ["app.example.com"] },
```

Only `NEXT_PUBLIC_` values that are meant to be public may exist; CI scans the client bundle for secret-shaped strings.

### 4.4 Workers-style runtimes

```typescript
// Hono on Workers: register the auth middleware BEFORE routes; ordering matters.
const app = new Hono<{ Bindings: Env; Variables: { actor: Actor } }>();
app.use("*", canonicalPath, verifyEdgeJwt, loadActor); // fails closed, sets c.var.actor
app.get("/api/files/:id", async (c) => {
  const file = await filesRepo(c.var.actor).get(c.req.param("id")); // bindings accessed via a scoped repo
  return file ? c.body(file.stream) : c.notFound();
});
// No module-level `let currentUser`, `const cache = new Map()` keyed without actor/tenant.
```

Set `workers_dev = false` (or restrict the route), verify the edge JWT in-process, and pass service-binding calls an explicit signed scope (see [`../authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../authorization-and-tenancy/async-jobs-and-scope-propagation.md)).

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **`requireActor()` must be called; nothing forces it.** A forgotten call in a new page or action is silent. Enforce with a lint rule and a route-table test that every handler/action reaches `requireActor` (section 7).
- **Caching can re-serve an authorized render.** A page that calls `requireActor()` but is statically rendered or sits behind `unstable_cache`/`fetch` cache keyed without the actor will serve one user's HTML to another. See [`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md).
- **Layouts do not re-run on client navigation.** Authorization placed in a shared layout is not a per-page guarantee.
- **Server Actions closure variables and bound arguments** are encrypted but not authenticated against your intent; re-validate every argument server-side.
- **Behind proxies, Origin/Host comparison breaks** (`X-Forwarded-Host` mismatches); misconfigured `allowedOrigins` tempts teams to disable the check.
- **Patched is not forever.** The bypass was in framework internals; the structural defense is that no single layer is the gate.
- **Open prefetch/data routes** (`/_next/data`) change with every release; test them from the built manifest, not from memory.

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. Every Server Action file and exported action:
rg -n '"use server"' src/ app/

# 2. Middleware matchers (allow-lists):
rg -n 'matcher' middleware.ts src/middleware.ts

# 3. Raw DB rows flowing into client components / props:
rg -n -B2 -A6 'select\(\)\.from|findMany\(|SELECT \*' app/ src/

# 4. Public env leakage:
rg -n 'NEXT_PUBLIC_' . --glob '!node_modules'

# 5. Use of the internal skip header anywhere:
rg -n -i 'x-middleware-subrequest' .
```

```yaml
rules:
  - id: server-action-without-actor
    languages: [typescript]
    severity: ERROR
    message: Every exported Server Action must call requireActor() before any data access.
    patterns:
      - pattern: |
          export async function $F(...) { ... }
      - pattern-inside: |
          "use server"; ...
      - pattern-not: |
          export async function $F(...) { ... requireActor(); ... }
```

### B. Dynamic
1. **Skip-header test:** send `x-middleware-subrequest` (single value and the repeated form) to each protected route anonymously. Assert `401/redirect`, never `200`.
2. **Route-variant matrix from the build manifest:** for each route in `routes-manifest.json` / `app-paths-manifest.json`, request: base, trailing slash, `.json`, `/_next/data/<buildId>/<path>.json`, `//path`, `/PATH`, `/path;x`, `/path%2f`. Anonymous and as tenant B. Assert uniform denial.
3. **Action by ID:** extract action IDs from the client bundle; call each without a session, with a stranger's session, and with a foreign tenant's object ID. Assert denial and no mutation.
4. **RSC payload canary:** log in as tenant B, load pages showing A-adjacent data, search the full HTML/RSC stream (not the rendered DOM) for A's canary and for secret-shaped fields (`password_hash`, `stripe_customer_id`).
5. **Image optimizer:** `GET /_next/image?url=http://127.0.0.1:19999/secret&w=64&q=75` and a redirecting host. Assert no hit on the lab listener.
6. **Edge-runtime concurrency:** fire parallel requests as two different tenants; assert no response contains the other's canary (catches module-global state).

These probes are generated deterministically from the route manifest by [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **One authorization seam:** handlers, pages and actions can reach data only through a DAL whose functions require an `Actor` and return DTOs. The raw DB client is not importable outside the DAL (`import "server-only"` plus a lint rule).
2. **Default-deny routing:** a catch-all matcher with an explicit `PUBLIC` allow-list, plus a CI test that diffs the build's route manifest against the allow-list.
3. **Action wrapper:** all Server Actions are created with `defineAction(schema, handler)` that runs Origin check, schema validation and `requireActor()` before `handler`; `"use server"` files may export nothing else.
4. **DTO-only props:** client components accept DTO types; tainting APIs (`experimental_taintObjectReference`) are a bonus, not the control.
5. **Strip internal framework headers at the edge** and keep the framework patched.
6. **Edge-runtime hygiene:** no mutable module state; bindings only through scoped repositories ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).
