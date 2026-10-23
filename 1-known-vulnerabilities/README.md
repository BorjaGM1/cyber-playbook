# Part 1: Known Vulnerability Classes & Codebase Audit Catalog

This directory is the **Map of Content (MOC)** for typical, known, and field-discovered vulnerabilities. It is structured so that:
- **Engineers** can read each atomic case note in 3 minutes to learn the exact mechanism of a bug, see realistic vulnerable vs. hardened code in TypeScript/Rust/SQL, and adopt the structural fix that eliminates the entire bug class.
- **AI coding and security agents** can systematically audit a codebase against every high-probability failure mode without relying on vague guesses.

---

## Standard Structure of Every Case Note

Every file in `1-known-vulnerabilities/` follows the same 7-section format, ordered so an engineer *predicts the bug before being told about it*:
1. **Attack Transcript:** A concrete `curl` / HTTP / event sequence showing what the attacker sends and what leaks or changes.
2. **Spot the Bug:** Realistic vulnerable code (TypeScript, Rust, SQL) with **no spoiler comments**. Find the flaw before reading on.
3. **Invariant Violated & Mechanism:** Which of the [Five Universal Invariants](../strategy/five-universal-invariants.md) fails, how the exploit works under the hood, where it hides, and why standard happy-path unit/E2E tests pass in green while the bug is live.
4. **Hardened Pattern:** The production pattern that restores the invariant.
5. **Residual Edge Cases:** Why the hardened version is still not enough (bypasses, operational gaps, things the pattern does not cover).
6. **How to Discover It Automatically:** Both the **static AST/grep/Semgrep query** to flag suspects and the **dynamic attacker test** that proves exploitability (see [`../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)).
7. **How to Eliminate the Bug Class by Construction:** The type-system capability, wrapper signature ([`../strategy/scoped-db.md`](../strategy/scoped-db.md)), AST lint rule, or boot assertion that makes the vulnerability impossible to reintroduce.

---

## Complete Catalog by Domain

### 1. Authentication & Sessions (`auth-and-sessions/`)
| Case Note | Invariant | Core Failure Mode |
|-----------|-----------|-------------------|
| [`jwt-and-edge-header-spoofing.md`](auth-and-sessions/jwt-and-edge-header-spoofing.md) | `I1` | Trusting `X-Forwarded-User` or `Cf-Access-Authenticated-User-Email` headers without verifying the signed JWT; `alg: none` or HMAC/RSA key confusion; unpinned `aud`/`iss`; unvalidated `kid`/`jku` headers. |
| [`cookie-purpose-confusion-and-oidc.md`](auth-and-sessions/cookie-purpose-confusion-and-oidc.md) | `I1` | Replaying a signed temporary cookie (`pending_login` / `oauth_state` / `mfa_challenge`) as a full `session` cookie because HMAC signing lacks a purpose prefix; linking OIDC accounts when `email_verified !== true`; missing CSRF `Origin` checks. |
| [`api-key-lifecycle-and-privilege-escalation.md`](auth-and-sessions/api-key-lifecycle-and-privilege-escalation.md) | `I1`, `I5` | Storing plaintext API keys instead of `SHA-256` hashes; allowing a machine API key to call `POST /api/keys` (minting keys that outlive rotation); failing to invalidate active keys/sessions immediately on user removal. |
| [`nextjs-and-edge-specifics.md`](auth-and-sessions/nextjs-and-edge-specifics.md) | `I1`, `I2`, `I5` | `CVE-2025-29927` middleware bypass, middleware matcher gaps, Server Actions as unauthenticated public endpoints, RSC prop leaks, `_next/image` SSRF, edge-vs-origin path differentials. |
| [`account-lifecycle-and-federation.md`](auth-and-sessions/account-lifecycle-and-federation.md) | `I1` | OAuth `state`/PKCE/`nonce`, open redirect in `next=`, SAML signature wrapping, Host-header reset poisoning, Unicode/case-fold identity collisions, email-change re-verification, enumeration oracles, refresh-token reuse races. |

### 2. Authorization & Multi-Tenancy (`authorization-and-tenancy/`)
| Case Note | Invariant | Core Failure Mode |
|-----------|-----------|-------------------|
| [`cross-tenant-idor-and-explicit-scoping.md`](authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md) | `I2` | Querying or mutating by resource ID (`WHERE id = $1`) without binding the authenticated `tenant_id`; why relying on database RLS fails in practice (forgotten on new tables, bypassed by roles/poolers); leaking resource existence via `403` instead of `404`. |
| [`side-door-data-leaks.md`](authorization-and-tenancy/side-door-data-leaks.md) | `I2` | Locking down primary CRUD (`GET /items/:id`) while leaking cross-tenant or restricted records through global search, activity history/audit logs, CSV exports, batch endpoints, count/sum aggregates, or MCP tools. |
| [`guest-boundaries-and-storage-blobs.md`](authorization-and-tenancy/guest-boundaries-and-storage-blobs.md) | `I2` | Project-scoped guests enumerating workspace-wide directories/teams; retaining read access to issues moved out of their project or after guest removal; serving S3/R2 attachments by key/UUID without checking parent-resource authorization. |
| [`async-jobs-and-scope-propagation.md`](authorization-and-tenancy/async-jobs-and-scope-propagation.md) | `I2` | Queues, cron, workflows, and Durable Objects that run with a service handle and only an ID in the payload (confused deputy); `TenantScope` lost at the serialization boundary. |
| [`cache-and-derived-data.md`](authorization-and-tenancy/cache-and-derived-data.md) | `I2` | Cache keys without tenant/actor, web cache deception, Workers/Node module-global mutable request state, semantic caches, RAG/vector namespaces, search-index lag, denormalized counts. |

### 3. State Machines, Concurrency & Economics (`state-and-economics/`)
| Case Note | Invariant | Core Failure Mode |
|-----------|-----------|-------------------|
| [`race-conditions-and-double-spend.md`](state-and-economics/race-conditions-and-double-spend.md) | `I3` | Time-of-Check to Time-of-Use (TOCTOU) in wallet balances, AI credits, plan quotas, single-use coupons, and invitation tokens caused by `SELECT`-then-`UPDATE` instead of atomic single-statement compare-and-swap SQL. |
| [`workflow-step-skipping-and-webhooks.md`](state-and-economics/workflow-step-skipping-and-webhooks.md) | `I3` | Jumping directly to final steps in multi-step flows; unverified or replayable Stripe/payment webhooks; mass assignment (`Object.assign` / spread into DB update) and full-model response over-fetching. |
| [`public-compute-and-denial-of-wallet.md`](state-and-economics/public-compute-and-denial-of-wallet.md) | `I3`, `I5` | Unauthenticated or weakly rate-limited routes triggering paid LLM/API calls, heavy PDF/video rendering, unbounded request bodies, or catastrophic backtracking regular expressions (ReDoS). |

### 4. Injection & Trust Boundaries (`injection-and-trust-boundaries/`)
| Case Note | Invariant | Core Failure Mode |
|-----------|-----------|-------------------|
| [`sql-and-query-construction.md`](injection-and-trust-boundaries/sql-and-query-construction.md) | `I4` | String interpolation inside SQL queries, dynamic `ORDER BY`/column names without an allowlist map, calling a tagged-template helper as a regular function (`sql("SELECT..." + x)`), `undefined` parameter binding traps, and ORM operator/filter injection (user JSON spread into `where`). |
| [`ssrf-file-uploads-and-path-traversal.md`](injection-and-trust-boundaries/ssrf-file-uploads-and-path-traversal.md) | `I4` | Server-side `fetch()` / webhook / preview generators hitting `127.0.0.1` or `169.254.169.254` (direct or via DNS rebinding); trusting `Content-Type` headers on file uploads without magic-byte verification and `Content-Disposition: attachment`; path traversal via user filenames. |
| [`terminal-paste-and-indirect-prompt-injection.md`](injection-and-trust-boundaries/terminal-paste-and-indirect-prompt-injection.md) | `I4` | Untrusted text injected into a PTY/terminal containing bracketed-paste close (`\x1b[201~`) + newline to execute shell commands immediately; untrusted web/database content steering an LLM agent into unauthorized tool calls. |
| [`browser-boundary.md`](injection-and-trust-boundaries/browser-boundary.md) | `I4` | XSS (DOM, markdown, SVG), CSP, CSRF, Cross-Site WebSocket Hijacking, credentialed CORS reflection, `postMessage`, clickjacking, user-content origin separation. |
| [`agentic-and-mcp-threats.md`](injection-and-trust-boundaries/agentic-and-mcp-threats.md) | `I2`, `I4`, `I5` | Confused-deputy agents, MCP tool poisoning/rug-pull, token passthrough, `.cursorrules`/`AGENTS.md` injection, markdown image exfiltration, sub-agent trust, memory/RAG poisoning, approval spoofing, cost loops. |

### 5. Infrastructure, Configuration & Supply Chain (`infra-and-supply-chain/`)
| Case Note | Invariant | Core Failure Mode |
|-----------|-----------|-------------------|
| [`dev-bypasses-and-boot-assertions.md`](infra-and-supply-chain/dev-bypasses-and-boot-assertions.md) | `I5` | Development auth bypass flags (`DEV_USER_EMAIL`, `SKIP_AUTH`) left enabled or reachable in production; naive loopback host checks (`host.startsWith("127.0.0.1")` matched by `127.0.0.1.attacker.com`); weak or default signing secrets. |
| [`surface-separation-and-destructive-gates.md`](infra-and-supply-chain/surface-separation-and-destructive-gates.md) | `I5` | Exposing admin/key-minting routes on machine worker domains; modifying already-applied SQL migrations; allowing automated pipelines or agents to execute `DROP TABLE` / `TRUNCATE` without an explicit human opt-in gate. |
| [`dependency-and-ci-supply-chain.md`](infra-and-supply-chain/dependency-and-ci-supply-chain.md) | `I5` | Unpinned Docker tags (`latest`), unpinned GitHub Actions (`@v4` instead of 40-char commit SHA), compromised PyPI `.pth` files or npm `postinstall` scripts, mutable GitHub releases, and secrets leaked into LLM proxy logs. |

---

## Agent Protocol: How to Run a Complete Part 1 Static Audit

When an agent is asked to review a repository using **Part 1**, it must follow these five steps in order:

1. **Build the Surface & Sink Map first** (follow [`../2-discovery-and-attacker-methods/surface-and-sink-mapping.md`](../2-discovery-and-attacker-methods/surface-and-sink-mapping.md)):
   - List every HTTP route / Server Action / RPC / CLI / MCP entry point and the exact middleware that runs before it.
   - List every database table and storage bucket and identify which column represents the tenant/owner boundary.
   - List every outbound network call (`fetch`, `axios`, `reqwest`), file read/write, shell spawn, and LLM tool call.
2. **Run the no-LLM deterministic sweep first** ([`../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)) so oracles cover 100% of routes cheaply and agents only review the residual.
3. **Audit each domain in `1-known-vulnerabilities/` against the map, using each note's `applies_to` row types (do not cross-multiply every note by every route):**
   - Do not sample 2 or 3 routes and assume the rest follow the same pattern. Check **100% of the mapped entry points and sinks** against the automated discovery queries in each case note.
4. **Check the OWASP ASVS v5.0.0 Level 1 Baseline** ([`../baselines/owasp-asvs-v5-level-1.md`](../baselines/owasp-asvs-v5-level-1.md)):
   - Verify the 4 documented security decisions (`V2.1.1`, `V6.1.1`, `V8.1.1`, `V15.1.1`) and all applicable Level 1 controls.
5. **Output Format (Zero Noise):**
   - Group findings by **Severity (`Critical`, `High`, `Medium`, `Low`)** and **Invariant (`I1`–`I5`)**.
   - Every finding must cite `path/to/file:line`, the exact case note or ASVS ID violated, a concrete request/payload that exploits it, and the structural code fix.
