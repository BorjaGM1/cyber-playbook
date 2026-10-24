# Cyber Playbook

A reusable, high-signal security engineering playbook designed for two readers simultaneously:
1. **Software engineers without a formal security team** who want to build deep security judgment (*criterio*), eliminate entire bug classes by construction in TypeScript, Rust, and SQL, and audit vendors or codebases without fluff.
2. **AI coding and security agents** tasked with auditing a repository for known vulnerability classes (**Part 1**) or standing up an isolated adversarial lab to discover unknown logic, concurrency, and cross-tenant bugs (**Part 2**).

This playbook treats security as **invariant-driven engineering paired with deterministic adversarial verification**. Instead of relying on static CVE checklists, unverified LLM code summaries, or hidden database policies that are easy to forget, every defense is expressed as an explicit code-level guarantee and verified from the outside by an attacker harness that demands a concrete Proof of Vulnerability (PoV).

---

## Repository Architecture

| Path | Purpose |
|------|---------|
| [`strategy/principles.md`](strategy/principles.md) | Core operating rules: invariant defense, why explicit application-layer scoping beats database RLS, deterministic PoVs over "CVE slop", and white-box agent framing |
| [`strategy/five-universal-invariants.md`](strategy/five-universal-invariants.md) | The 5 first-principles invariants (Identity, Tenancy, Conservation, Boundary Parse, Blast Radius) that cover both known and unknown vulnerabilities |
| [`strategy/scoped-db.md`](strategy/scoped-db.md) | **Keystone reference implementation:** `ScopedDb` / `TenantScope` / audited `SystemScope` in TypeScript and Rust, plus the CI schema-introspection test and SQL query-log tenant-predicate oracle that replace any database-level safety net |
| [`1-known-vulnerabilities/README.md`](1-known-vulnerabilities/README.md) | **Part 1 Index (MOC):** Systematic catalog of typical, known, and field-discovered vulnerability classes across 5 domains |
| [`1-known-vulnerabilities/auth-and-sessions/`](1-known-vulnerabilities/auth-and-sessions/) | JWT/edge header spoofing, cookie purpose confusion, OIDC `email_verified` traps, API key privilege escalation, Next.js/edge pitfalls (`CVE-2025-29927`), and account lifecycle/federation (OAuth, SAML, reset poisoning) |
| [`1-known-vulnerabilities/authorization-and-tenancy/`](1-known-vulnerabilities/authorization-and-tenancy/) | Cross-tenant IDOR/BOLA, explicit capability scoping vs. RLS pitfalls, side-door leaks (search/history/exports/MCP), guest revocation, and storage blobs |
| [`1-known-vulnerabilities/state-and-economics/`](1-known-vulnerabilities/state-and-economics/) | Parallel race conditions (TOCTOU double-spend), multi-step workflow skipping, webhook replay, and Denial-of-Wallet on compute/AI endpoints |
| [`1-known-vulnerabilities/injection-and-trust-boundaries/`](1-known-vulnerabilities/injection-and-trust-boundaries/) | SQL construction guards, SSRF and DNS rebinding, magic-byte file upload hardening, ORM operator injection, terminal bracketed-paste escapes (`\x1b[201~`), the browser boundary (XSS/CSRF/CSWSH/CORS), and agentic/MCP threats |
| [`1-known-vulnerabilities/infra-and-supply-chain/`](1-known-vulnerabilities/infra-and-supply-chain/) | Fail-closed boot assertions, loopback host-parsing traps, human vs. machine surface separation, destructive SQL gates, and CI/dependency supply-chain defense |
| [`2-discovery-and-attacker-methods/README.md`](2-discovery-and-attacker-methods/README.md) | **Part 2 Index (MOC):** How to set up an isolated environment and run an autonomous attacker to discover unknown edge cases |
| [`2-discovery-and-attacker-methods/surface-and-sink-mapping.md`](2-discovery-and-attacker-methods/surface-and-sink-mapping.md) | Step 0 before attacking: deterministic extraction of routes, actors, trust boundaries, and sensitive sinks |
| [`2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md) | Step 0.5: 3-pass fresh-context Attack Surface Reduction (ASR) & dangerous configuration interaction auditing (`OpenSSH 10.6` pattern) |
| [`2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](2-discovery-and-attacker-methods/deterministic-oracle-sweep.md) | Step 1.5: No-LLM sweep (token/ID mutation matrices, side-door parity, query-log tenant-predicate oracle, guard-mutation self-test) that covers 100% of routes before any LLM hunting |
| [`2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md`](2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md) | Step 1: Ephemeral target setup seeding Victim (`User A`) with cryptographic canaries (`flag{UUID}`) across DB, Blob, FS, and SSRF ports while giving Attacker (`User B`) only `SHA-256(flag)` |
| [`2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](2-discovery-and-attacker-methods/differential-and-side-door-oracles.md) | Step 2: Automated cross-surface parity testing (comparing main CRUD vs. search, history, exports, webhooks, and MCP tools) and `404` anti-enumeration oracles |
| [`2-discovery-and-attacker-methods/autonomous-micro-agent-red-teaming.md`](2-discovery-and-attacker-methods/autonomous-micro-agent-red-teaming.md) | Step 3: `XBOW` / `/goal` / `Nebu` micro-agent architecture: single-outcome decomposition, 1-sentence variant width, `agentcov` / `coverage.json`, and Two-Pass Cross-Model Judge Gauntlet |
| [`2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md) | Step 4: Single-packet / barrier-synchronized parallel HTTP bursts and deterministic thread permutation (`shuttle`/`loom`) |
| [`2-discovery-and-attacker-methods/stateful-property-and-fuzzing-harnesses.md`](2-discovery-and-attacker-methods/stateful-property-and-fuzzing-harnesses.md) | Step 5: Reference state machines (`proptest-state-machine`, `fast-check`), entry-point coverage fuzzing, and autonomous fuzz lab construction (`zlib` pattern) |
| [`2-discovery-and-attacker-methods/bounded-formal-verification.md`](2-discovery-and-attacker-methods/bounded-formal-verification.md) | Step 6: Symbolic model checking (`Kani` for Rust, `Alloy`/`TLA+` for state machines) on the critical 300 lines of auth, parsers, and ledgers |
| [`2-discovery-and-attacker-methods/models-and-refusal-free-framing.md`](2-discovery-and-attacker-methods/models-and-refusal-free-framing.md) | Empirical 2025–2026 guide to frontier vs. open-weight vs. abliterated models, role-parameterized model selection (`SWEEP`/`WALLBREAKER`/`JUDGE`), pipeline benchmarks, and zero-refusal white-box framing |
| [`baselines/owasp-asvs-v5-level-1.md`](baselines/owasp-asvs-v5-level-1.md) | Complete verifiable 70-item OWASP ASVS v5.0.0 Level 1 checklist + the 4 required security decision records |
| [`baselines/pre-deploy-security-pipeline.md`](baselines/pre-deploy-security-pipeline.md) | Deterministic `<30s` pre-deploy security gate, 3-part Zero-Slop reporting standard, and the Four-Arm Patch Proof (`patching-bugs` + `regression-hunt`) |
| [`observations/LOG.md`](observations/LOG.md) | Reverse-chronological log of dated benchmarks, empirical research, and production security lessons |

---

## How to Use This Playbook

### 1. As an Engineer Building or Reviewing a System
1. Read [`strategy/principles.md`](strategy/principles.md) and [`strategy/five-universal-invariants.md`](strategy/five-universal-invariants.md) to internalize the five invariants that every route, worker, and database transaction must preserve.
2. Before shipping a new feature or reviewing a PR, check the relevant domain in [`1-known-vulnerabilities/`](1-known-vulnerabilities/README.md). Every case note follows a strict 7-part structure (predict first, then learn):
   - **Attack Transcript** (concrete `curl`/HTTP)
   - **Spot the Bug** (vulnerable code, no spoiler comments)
   - **Invariant Violated & Mechanism** (+ where it hides)
   - **Hardened Pattern** (TypeScript, Rust, SQL, HTTP)
   - **Residual Edge Cases**
   - **How to Discover It Automatically**
   - **How to Eliminate the Bug Class by Construction**
3. Use [`baselines/owasp-asvs-v5-level-1.md`](baselines/owasp-asvs-v5-level-1.md) to establish your baseline and evaluate external security audits or vendor claims against concrete requirement IDs (`v5.0.0-X.Y.Z`).

### 2. With an AI Coding or Security Agent
Point your agent to this repository and instruct it to run one of two workflows:
- **Workflow A — Static Known-Vulnerability, ASR & Baseline Audit (`Part 1` + `Step 0.5` + `Baselines`):**
  1. Execute [`2-discovery-and-attacker-methods/surface-and-sink-mapping.md`](2-discovery-and-attacker-methods/surface-and-sink-mapping.md) to build the complete inventory of routes, actors, tables, and external sinks, and run the 3-pass fresh-context audit in [`2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md).
  2. Walk every item in [`1-known-vulnerabilities/README.md`](1-known-vulnerabilities/README.md) and [`baselines/owasp-asvs-v5-level-1.md`](baselines/owasp-asvs-v5-level-1.md) against that inventory, recording inspected spans in `coverage.json`.
  3. Report only verified findings with `file:line` evidence, concrete exploit scenarios, and structural fixes validated via the Four-Arm Proof in [`baselines/pre-deploy-security-pipeline.md`](baselines/pre-deploy-security-pipeline.md).
- **Workflow B — Active Adversarial Discovery (`Part 2`):**
  1. Stand up the application locally in an isolated environment and seed Victim (`User A`) and Attacker (`User B`) sessions with cryptographic canaries per [`2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md`](2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md).
  2. Run the no-LLM [`deterministic-oracle-sweep.md`](2-discovery-and-attacker-methods/deterministic-oracle-sweep.md) first, then the discovery methods in [`2-discovery-and-attacker-methods/`](2-discovery-and-attacker-methods/README.md) on the residual: micro-agent red teaming (`/goal` + Two-Pass Cross-Model Judge Gauntlet), differential side-door oracles, barrier-synchronized race bursts, and stateful property/fuzzing harnesses.
  3. Accept a finding as valid **only** when accompanied by a deterministic reproduction script (`repro.mjs` or test case) that captures the canary hash or violates a conservation assertion, and validate every candidate patch with the Four-Arm Proof and `regression-hunt`.

---

## Rules for Updating This Repository

1. **Zero private or project-specific references.** Keep every explanation, code snippet, and log entry 100% general and reusable across any codebase.
2. **Never invent numbers.** Every benchmark figure, CVE/advisory window, or empirical claim must carry a source, a date, and a link.
3. **Always pair detection with structural eradication.** Never document a bug without showing both how to catch it automatically from the outside and how to make the bug class unrepresentable in code.
4. **Log empirical findings in [`observations/LOG.md`](observations/LOG.md) first.** Promote patterns into `1-known-vulnerabilities/` or `2-discovery-and-attacker-methods/` once distilled into a general rule.
