# The Five Universal Security Invariants

When engineers ask, *"How do we make sure we catch every possible exploit—including obscure edge cases and unknown attack vectors—when we don't know in advance what to look for?"*, the answer is to invert the problem.

Instead of enumerating every possible **attack** (which is infinite), you enumerate your application's **security invariants** (which are finite and small). Every real-world vulnerability—whether it is a classic SQL injection, a subtle 7-step authorization bypass, or a sub-millisecond race condition—is a violation of one of five universal invariants.

---

## Overview: The 5 Universal Invariants

| # | Invariant | Formal Statement | Bug Classes Covered | Primary Verification Oracle |
|---|-----------|------------------|---------------------|-----------------------------|
| **I1** | **Authentic Identity & Purpose Binding** | Every actor identity, token, and session is cryptographically bound to its issuer, audience, expiration, and exact intended purpose. | JWT forgery, `alg:none`, edge header spoofing (`X-Forwarded-User`), cookie purpose confusion, OIDC unverified email takeover, machine key privilege escalation. | Token/Header Mutation Matrix |
| **I2** | **Strict Tenancy & Capability Isolation** | An actor $B$ can never read, infer the existence of, or mutate any state belonging to tenant/actor $A$ across any primary or secondary surface unless an explicit, unrevoked grant exists at execution time. | IDOR/BOLA, missing tenant `WHERE` clauses, side-door leaks (search, history, exports, webhooks, MCP), stale guest access after removal, private S3/R2 blob leaks, `403` vs `404` enumeration. | Cross-Tenant Canary CTF + Differential Surface Oracle |
| **I3** | **State-Machine & Economic Conservation** | Concurrent, replayed, or out-of-order requests can never create value, bypass mandatory workflow transitions, or exceed resource/rate quotas. | TOCTOU double-spend, coupon/credit race conditions, checkout step skipping, webhook replay, negative-amount transfers, unauthenticated compute / Denial-of-Wallet. | Barrier-Synchronized Race Harness + Stateful Property Testing |
| **I4** | **Context-Safe Boundary Parsing** | Untrusted bytes crossing into an interpreter (SQL, HTML/DOM, OS shell, URL fetcher, file path, terminal PTY, or LLM tool router) can never alter syntax or control flow. | SQL injection, XSS, SSRF, DNS rebinding, path traversal, malicious file uploads, terminal bracketed-paste escapes (`\x1b[201~`), indirect prompt injection. | Entry-Point Coverage Fuzzing + Sink Canary Monitors |
| **I5** | **Minimal Blast Radius & Fail-Closed Boot** | A compromise or misconfiguration of one component, key, or dependency cannot silently disable authentication, wipe production data, or escalate across environments. | Dev-bypass flags in prod, loopback hostname spoofing, machine keys minting admin keys, destructive unreviewed migrations, supply-chain `.pth`/postinstall execution. | Boot Assertion Tests + Supply-Chain Lockfile/AST Gates |

---

## Deep Dive into Each Invariant

### Invariant 1 (`I1`): Authentic Identity & Purpose Binding

#### What Must Always Hold
For any request $R$ resolved to an actor $A$ with capability set $C$:
1. The credential proving $A$ was verified using a pre-configured cryptographic key and explicit algorithm allowlist **before** any claim was read.
2. The credential was issued specifically for **this** service (`aud`), **this** environment (`iss`), and **this** exact step of the lifecycle (`purpose`: e.g., `"pending_mfa"` vs. `"session"`, or `"machine_worker"` vs. `"human_admin"`).
3. If the credential relies on an upstream reverse proxy or edge gateway (e.g., Cloudflare Access, AWS ALB, Envoy), the backend verifies the edge gateway's cryptographic JWT signature—never a plain-text identity header (`X-Forwarded-Email`, `Cf-Access-Authenticated-User-Email`) that could be spoofed if the origin is reached directly or if the edge route is misconfigured.

#### Why Happy-Path Tests Miss Violations
Normal integration tests send a valid session cookie or valid API token and assert `200 OK`, plus an empty request and assert `401 Unauthorized`. They never send a valid **pending-login cookie** to a protected API route, or a valid JWT signed for **Service B** to **Service A**, or a request with a forged `Cf-Access-Authenticated-User-Email` header and no JWT cookie.

#### How We Enforce & Verify `I1`
- **By construction:** The only way to obtain an `AuthenticatedActor` object in route handlers is through a single verifier module that enforces `alg`, `iss`, `aud`, `exp`, `nbf`, and an explicit HMAC/claim `purpose` tag.
- **Adversarial verification:** Run an automated 12-case token mutation matrix against every protected route (expired, not-yet-valid, wrong `aud`, wrong `purpose`, `alg:none`, mutated signature byte, plain header without JWT, revoked key). Every case must return `401`.

---

### Invariant 2 (`I2`): Strict Tenancy & Capability Isolation

#### What Must Always Hold
Let $\text{Visible}(A, S)$ be the set of resource IDs, fields, and metadata returned or affected by surface $S$ (CRUD route, search endpoint, audit log, export job, attachment download, webhook, MCP tool) when called by actor $A$.
1. **Zero cross-tenant bleed:** If resource $X$ belongs to Tenant 1 and actor $B$ belongs to Tenant 2 (with no explicit cross-tenant grant), $X \notin \text{Visible}(B, S)$ for **every** surface $S$.
2. **Surface parity:** For any restricted actor $G$ (such as a project-scoped guest), the set of resources visible through secondary surfaces (`search`, `activity`, `export`, `attachments`) must be a subset of the resources visible through the primary authorized surface:
   $$\text{Visible}(G, S_{\text{secondary}}) \subseteq \text{Visible}(G, S_{\text{primary}})$$
3. **Zero existence oracle (anti-enumeration):** For any unauthorized actor $B$, the observable response distribution (status code, response headers, error shape) when requesting an existing private resource $X_{\text{Tenant 1}}$ must be indistinguishable from requesting a non-existent resource $X_{\text{random UUID}}$: both must return `404 Not Found`.
4. **Immediate revocation:** The instant a user, guest membership, session, or API key is revoked at time $t$, any request arriving at $t + \Delta t$ must fail authorization with zero stale-cache grace window.

#### Why We Enforce `I2` in Application Code (Not Database RLS)
Database Row-Level Security (RLS) hides authorization logic inside SQL migrations, is silently bypassed when a developer creates a new table and forgets `ENABLE/FORCE ROW LEVEL SECURITY`, and breaks under connection pooling or multi-engine architectures (SQLite/D1/S3). Instead, we enforce `I2` in application code via **explicit capability-scoped data access handles** (`ScopedDb(actor)`) where every query explicitly binds `tenant_id` (and project/guest scope where applicable), backed by an external **Canary + Differential Surface Oracle** that attacks every endpoint as `User B` hunting for `User A`'s canary `flag{UUID}`.

---

### Invariant 3 (`I3`): State-Machine & Economic Conservation

#### What Must Always Hold
1. **Conservation of value and quota:** Across any sequence or parallel burst of requests $R_1, R_2, \dots, R_n$:
   $$\text{ Balance}_{t} = \text{Balance}_{0} + \sum \text{VerifiedCredits} - \sum \text{CommittedDebits} \ge 0$$
   $$\text{ActiveResources}(\text{tenant}) \le \text{PlanQuota}(\text{tenant})$$
2. **Idempotency:** Replaying the same webhook event ID, checkout session ID, or coupon code $k$ times ($k > 1$)—whether sequentially or in the same millisecond—produces the exact same state transition as executing it once ($k = 1$).
3. **Monotonic workflow transitions:** A multi-step state machine ($\text{Draft} \to \text{PendingPayment} \to \text{Paid} \to \text{Fulfilled}$) can only advance along explicitly defined directed edges triggered by verified actors (e.g., only a cryptographically verified payment webhook or internal billing service can transition $\text{PendingPayment} \to \text{Paid}$, never a client `PATCH` body).

#### How We Enforce & Verify `I3`
- **By construction:** All balance decrements, quota claims, coupon redemptions, and token revocations execute as **single-statement atomic compare-and-swap SQL queries** (`UPDATE wallets SET balance = balance - $1 WHERE tenant_id = $2 AND balance >= $1 RETURNING balance`) or inside `UNIQUE` idempotency-key constraints—never as `SELECT balance` followed by application-code math and a separate `UPDATE`.
- **Adversarial verification:** Barrier-synchronized parallel HTTP bursts (20+ concurrent requests released simultaneously against a balance of 1) and stateful property-based testing (`proptest-state-machine` / `fast-check` commands).

---

### Invariant 4 (`I4`): Context-Safe Boundary Parsing

#### What Must Always Hold
Whenever untrusted input crosses from a caller (HTTP params, JSON body, webhook payload, uploaded file, terminal output stream, or scraped web page) into a downstream interpreter:
1. **Data is never parsed as code/control:** SQL parameters are bound strictly via prepared statements / validated tagged templates; HTML is rendered as text (`textContent`) or stripped via strict allowlist sanitizers; file paths are constructed from internal UUIDs or canonicalized inside a jailed base directory; terminal paste buffers strip bracketed-paste closing sequences (`\x1b[201~`) and raw control bytes.
2. **Outbound network calls never reach internal infrastructure:** Any server-side URL fetch (`fetch`, webhook delivery, link preview, PDF/image renderer) resolves DNS once, blocks loopback/RFC1918/link-local/cloud-metadata IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, `::1`, etc.), disables unvalidated redirects, and pins the resolved IP for the socket connection to defeat DNS rebinding.
3. **Untrusted content never directly triggers privileged agent actions:** Data retrieved from third-party web pages, emails, issues, or user files is treated strictly as untrusted data and can never invoke state-changing tools or exfiltrate secrets without explicit user confirmation.

---

### Invariant 5 (`I5`): Minimal Blast Radius & Fail-Closed Boot

#### What Must Always Hold
1. **Boot-time fail-closed assertions:** If `NODE_ENV=production` (or `APP_ENV=production`), the process immediately aborts startup (`process.exit(1)` / `panic!`) if any development bypass variable is set, if required signing secrets/JWKS keys have insufficient entropy, or if CORS/host allowlists contain wildcards.
2. **Privilege non-amplification:** An authentication credential of tier $T$ can never mint or view a credential of tier $\ge T$ (e.g., a machine API key can never call `POST /api/keys`, change account email/password, or modify billing webhooks).
3. **Immutable, verified supply chain:** Every third-party dependency, container base image, and CI workflow action is pinned to an immutable cryptographic hash/SHA, and database migrations are append-only and checksum-verified before execution.
