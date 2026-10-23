# Security Engineering Principles

These twelve principles govern how we design systems, audit codebases, and build autonomous attacker harnesses when operating as a high-velocity engineering team without a dedicated security department.

---

## 1. Defend Invariants, Not Threat Lists
Checking a codebase against a list of known CVEs or OWASP Top 10 categories only catches yesterday's bugs. Novel business-logic flaws, multi-step state corruption, and cross-tenant leaks are discovered by defining **what must never happen** (an invariant) and systematically trying to violate it. If you know your five universal invariants ([`five-universal-invariants.md`](five-universal-invariants.md)), you can test for every possible exploit—including edge cases you have never seen before—because any exploit must violate at least one invariant.

## 2. Explicit Application-Layer Scoping Over Database RLS
**Never rely on PostgreSQL Row-Level Security (RLS) as a mandatory or primary tenant isolation mechanism—not even in pure PostgreSQL deployments.**
In real engineering teams, database RLS creates a dangerous false sense of security:
- **Invisible outside application code:** Access rules live in SQL migration history rather than in the handler or repository code an engineer or LLM agent reads during review.
- **Trivial to forget on new tables:** Adding a new table (`CREATE TABLE issue_attachments ...`) without `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` silently leaves that table wide open across tenants while the rest of the schema looks protected.
- **Silently bypassed by roles and poolers:** Table owners, superusers, background workers using service roles, and transaction-pooled connections (`PgBouncer` / Neon / Supavisor) where session variables (`SET app.tenant_id`) bleed or reset across queries routinely bypass or corrupt RLS policies.
- **Not portable:** It locks your mental model to one database engine and breaks immediately when moving a service to SQLite, D1, Turso, or an external object store (S3/R2).

**What we do instead:** Enforce **explicit application-layer scoping by construction** (typed capability handles such as `ScopedDb` or repository methods whose TypeScript/Rust signature requires an authenticated `TenantScope` and automatically appends explicit `WHERE tenant_id = ?` predicates), enforced by AST/lint rules that forbid raw unscoped table queries, and **verified from the outside** by automated cross-tenant canary tests on every build. The "forgotten new table" failure is closed by a CI schema-introspection test that fails the build when any table carrying a tenant column is reachable outside `ScopedDb`, and by a deterministic SQL query-log tenant-predicate oracle that flags any executed statement lacking the caller's tenant. The full reference implementation is in [`scoped-db.md`](scoped-db.md).

## 3. Eliminate Bug Classes by Construction
Whenever a vulnerability class is identified, do not fix it with a one-off `if` check that developers must remember to copy into the next 40 endpoints. Make the bug unrepresentable at compile time or lint time:
- Replace raw `req.headers.get("x-user-id")` strings with a verified `AuthenticatedActor` type whose constructor is private to the auth middleware.
- Replace raw SQL string interpolation with a tagged-template wrapper that throws at runtime if `Array.isArray(strings?.raw)` is false, paired with an AST check that fails CI on string concatenation inside SQL calls.
- Separate human browser cookies from machine API keys at the router level so a compromised machine key can never call a key-minting or billing-mutation route.

## 4. Deterministic Proof of Vulnerability (PoV) Over "CVE Slop"
An LLM reading source code in an open-ended chat and outputting a list of "potential vulnerabilities" produces 70–90% false positives ("CVE slop"). In this playbook, a dynamic security finding does not exist until it is proven by a deterministic oracle:
- **Canary capture:** An attacker session (`User B`) extracts a secret string `flag{UUID}` planted in `User A`'s private database rows, storage blobs, filesystem, or internal SSRF listener, verified by matching `SHA-256(flag)` without the agent ever knowing the plaintext flag in advance.
- **Conservation violation:** A parallel race harness causes `SUM(debits) > initial_balance` or creates 2 active resources when the plan limit is 1.
- **Crash or sanitizer trap:** A fuzzer or property test produces a deterministic minimal input seed that panics, hangs, or triggers AddressSanitizer (`ASan`).

## 5. Side Doors Leak More Often Than Front Doors
Engineers rarely forget authorization on `GET /api/projects/:id`. They routinely forget it on secondary views of the same data: global search (`GET /api/search?q=`), activity feeds and audit logs (`GET /api/issues/:id/history`), CSV/JSON exports, webhook payloads, batch mutation endpoints, and MCP tool handlers. Every tenant-isolation test must run a **differential surface oracle** across all read and write surfaces simultaneously.

## 6. Anti-Enumeration by Default (`404`, Never `403`, on Private Resources)
When an authenticated user (`User B`) requests or mutates a resource belonging to another tenant (`User A`), the backend must return the exact same HTTP status (`404 Not Found`), headers, and error body structure as when requesting a randomly generated UUID that does not exist in the database. Returning `403 Forbidden` leaks the existence, ID validity, and often the type of private cross-tenant resources.

## 7. Decompose Red-Teaming into Narrow Micro-Agents
Empirical benchmarks from 2025–2026 (BountyBench, CyberGym, XBOW) show that giving a single monolithic agent a whole repository and asking it to "find vulnerabilities" succeeds only ~12.5% of the time, whereas narrowing the task to a specific route, sink, and invariant hypothesis raises success to **67.5%–85%**. Always run Step 0 ([`2-discovery-and-attacker-methods/surface-and-sink-mapping.md`](../2-discovery-and-attacker-methods/surface-and-sink-mapping.md)) first, then dispatch fresh, isolated micro-agents—each testing one hypothesis on one route.

## 8. Use Stock Frontier or Open-Weight Models with White-Box Invariant Framing
You do not need community "abliterated" models (models with refusal directions surgically projected out of their residual stream) to defend your own applications. Empirical studies (2026) prove that abliteration degrades mathematical and formal reasoning by up to **26.5%** and increases multi-step agent loop derailments. Meanwhile, stock frontier models (`Claude`, `GPT`, `Grok`) and stock open-weight models (`DeepSeek V4.1`, `GLM-5.3`, `Qwen3`) exhibit **0% safety refusals** when framed around white-box invariant verification, property-based testing, and localhost canary capture (`flag{UUID}` on `127.0.0.1`).

## 9. Safety Lives in the Runtime Sandbox, Never in Model Weights
Whether an agent uses a frontier model or an uncensored open-weight model, model weights are never a security boundary. Never run an autonomous attacker agent against production, never pass production credentials into an agent harness, and enforce network, filesystem, and target allowlists outside the LLM in the execution harness.

## 10. Concurrency is a Security Surface
Sequential integration tests cannot catch Time-of-Check to Time-of-Use (TOCTOU) bugs. Any operation that checks a balance, quota, coupon, rate limit, invitation token, or revocation flag and then mutates state must be tested under a **barrier-synchronized parallel burst** (releasing 15–50 identical requests in the same sub-millisecond window) and written using single-statement atomic SQL (`UPDATE ... WHERE balance >= :cost RETURNING ...`).

## 11. Fail Closed at Boot on Misconfiguration
Production breaches frequently stem from development flags (`DEV_AUTH_BYPASS=1`), missing JWT audience pins, weak session secrets, or permissive host headers (`127.0.0.1.evil.com` passing a naive `.startsWith("127.0.0.1")` check) surviving into production. Every service must run a synchronous boot assertion that refuses to start if production environment invariants are violated.

## 12. Assume Upstream Packages and CI Tokens Will Be Compromised
Code review of your own repository does not stop a compromised PyPI wheel (`.pth` startup execution), a hijacked npm `postinstall` script, a mutated GitHub Action tag, or a backdoored binary release asset where release immutability was disabled. Lockfiles must be hash-pinned, container base images pinned by SHA-256 digest, GitHub Actions pinned to full 40-character commit SHAs, and secret rotation scripted so every credential can be rolled in minutes.
