# Baseline 2: Deterministic Pre-Deploy Security Pipeline, Reporting Standard & 3-Arm Patch Proof

A security playbook only compounds if its rules run automatically before every deploy without slowing down engineering velocity—and without introducing new regressions when an agent patches a vulnerability. This baseline defines:
1. **The Fast Pre-Deploy Gate (`< 30 seconds`):** Deterministic static, supply-chain, boot-assertion, and canary integration checks that run on every commit/deploy.
2. **The PR Diff Trigger & Coverage Manifest (`coverage.json`):** When to automatically trigger targeted micro-agent or property/race verification on a pull request, and how to prove no routes were skipped.
3. **The 3-Part "Zero-Slop" Vulnerability Reporting Standard:** What every agent-discovered vulnerability report must include before a human looks at it (validated by Anthropic's May–October 2026 Project Glasswing / OSS Scanner studies across 1,000+ repositories).
4. **The Three-Arm Patch Proof & Automated Regression Hunting (`patching-bugs` + `regression-hunt`):** How to prevent AI-generated security fixes from breaking production behavior (validated by Trail of Bits' October 21, 2026 audit of 130+ merged AI security PRs).

---

## 1. The 6-Stage Deterministic Pre-Deploy Gate (`< 30 Seconds`)

Wire these 6 checks into your repository's main `check` or `verify` script so no code can be deployed unless all 6 exit `0`:

| Stage | Target Runtime | What It Verifies | Fails Build If... |
|-------|----------------|------------------|-------------------|
| **1. Supply-Chain & Lockfile Gate** | `~2s` | `cargo deny check advisories bans licenses sources` / `npm audit --audit-level=high`, frozen lockfile, GitHub Action 40-char SHA check, `.pth` startup hook check. | Any unpinned Action tag, known advisory, or lockfile drift exists. |
| **2. Static AST & Boundary Lint** | `~2s` | Scans `src/` for forbidden patterns: plain-text edge header reads (`cf-access-authenticated-user-email`), `startsWith("127.0.0.1")`, raw SQL interpolation, `SELECT *`, or direct `db` imports inside route handlers. | Any route bypasses `TenantScope` or uses a banned sink directly. |
| **3. Migration History & Destructive SQL Gate** | `~1s` | Verifies SHA-256 checksums of all applied SQL migrations and scans pending migrations for `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, or `DELETE FROM`. | Historical migrations were edited or destructive SQL lacks explicit human opt-in. |
| **4. Fail-Closed Boot & Config Interaction Tests** | `~2s` | Unit tests that call `assertSafeBootConfig()` with production flags + `DEV_BYPASS`, weak secrets, or conflicting config pairs (Pass 3 of ASR). | The server fails to throw on an unsafe production config combination. |
| **5. Auth Spoofing & 404 Matrix (`I1` + `I2`)** | `~8s` | Fires the 8-case JWT/header/cookie purpose-confusion matrix (`401`) and the 6-actor cross-tenant + guest canary differential sweep (`404`, zero canary leaks). | Any spoofed token returns `!= 401`, any canary hash leaks, or any private ID returns `403` instead of `404`. |
| **6. Atomic Conservation & Race Smoke Test (`I3`)** | `~5s` | Fires a 20-request barrier burst against a credit/quota/coupon test endpoint and runs fast `proptest`/`fast-check` state-machine seeds. | More than 1 request succeeds against a balance of 1, or state invariants diverge. |

---

## 2. PR Diff Triggers & Mandatory Unaudited-Scope Tracking (`coverage.json` + `agentcov`)

Not every PR needs a 10-minute fuzzing run, but PRs that touch security boundaries must automatically trigger the corresponding **Part 2** discovery pass:

- **Diff touches `auth`, `session`, `jwt`, `oidc`, `cookies`, or `config`:**
  - Trigger **Attack Surface Reduction Passes 2 & 3** ([`../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md)) to verify no pre-auth parsing or fail-open config interaction was introduced.
- **Diff adds or modifies a route, search query, export, webhook, MCP tool, or SQL table:**
  - Update `SECURITY_SURFACE_MAP` ([`../2-discovery-and-attacker-methods/surface-and-sink-mapping.md`](../2-discovery-and-attacker-methods/surface-and-sink-mapping.md)), add the new resource/surface to the **Differential Surface Oracle** ([`../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md`](../2-discovery-and-attacker-methods/differential-and-side-door-oracles.md)), and run a scoped micro-agent against the new route.
- **Diff touches balances, credits, billing, coupons, quotas, or webhooks:**
  - Run the **Barrier-Synchronized Race Harness** ([`../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md)) against the modified endpoint.
- **Diff touches binary/frame decoders, terminal/PTY sequences, or crypto/math helpers:**
  - Run `cargo kani` bounded proofs ([`../2-discovery-and-attacker-methods/bounded-formal-verification.md`](../2-discovery-and-attacker-methods/bounded-formal-verification.md)) and entry-point fuzzing.

### Never Equate "0 Findings" with "100% Coverage" (`coverage.json` & `scan-manifest.json`)
Adopted from OpenAI `Codex Security` ([*Expanding Daybreak*, August 2026](https://openai.com/index/expanding-daybreak-as-the-cyber-defense-window-narrows/)) and Trail of Bits' `agentcov` ([*How We Use `/goal`*, July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)):
- Every automated or agentic security scan must emit **`coverage.json`** and **`scan-manifest.json`** built from objective tool-call transcripts (exact `file:startLine-endLine` spans opened and dynamic probes executed).
- `coverage.json` must explicitly list **every file, route, and hypothesis that was NOT inspected** (due to step limits, build skips, or scope filters) so reviewers never mistake an incomplete scan for a clean bill of health.

---

## 3. The 3-Part "Zero-Slop" Vulnerability Report Standard (`Project Glasswing`, May–Oct 2026)

Across May–October 2026, Anthropic's Frontier Red Team published the empirical results of **Project Glasswing** and its **OSS Vulnerability-Finding Service** ([*"Project Glasswing initial update"*](https://www.anthropic.com/research/glasswing-initial-update), [*"Evaluating exploit generation (`ExploitGym`)"*](https://www.anthropic.com/research/exploit-evals), May 2026; [*"Launching an opt-in vulnerability-finding service for open-source software"*](https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source), October 8, 2026):
- **Benchmark Progression (`CyberGym` & `ExploitGym`):** On UC Berkeley's `CyberGym`, frontier agents jumped from reproducing **<20% of vulnerabilities at the start of 2025 to >85% in 2026**. On `ExploitGym` (898 vulnerability tasks, May 2026), `Claude Mythos Preview` generated **157/898 full working exploits** and `GPT-5.5` (via Codex CLI) generated **120/898**.
- **Large-Scale Open-Source Precision (`1,000+` Repos):** Scanning **1,000+ open-source repositories** with `Claude Mythos Preview` achieved a **90.6% true-positive rate** across **1,587 of 1,752 independently audited findings**.
- **Expert Pentester & Maintainer Audit (`48` Projects):** When expert pentesters and maintainers of `wolfSSL` (where **72 of 74 raw model reports were valid**, yielding 5 CVEs), `PostgreSQL`, `OpenSSL`, `HotCRP`, and `curl` audited **97 critical/high-severity reports**, **85 of 97 (88%) met the coordinated vulnerability disclosure (CVD) bar**, **11 were real bugs (duplicates)**, and **only 1 out of 97 (~1%) was a false positive** (**96/97 = 99% real bugs**).

What separated those 90.6%–99% valid reports from the "AI CVE slop" that open-source maintainers reject was requiring **three mandatory artifacts** in every report. Every agent using this playbook must include all three before surfacing a finding:

1. **Self-Contained Deterministic Reproducer (`repro`):**
   - A standalone test case, HTTP script (`repro.mjs`), or fuzz seed that executes against the local build and deterministically demonstrates the invariant violation (canary capture, conservation breach, or crash).
2. **Root-Cause Trace & Git Bisection (`git bisect`):**
   - The exact `file:line` where the guard is missing or bypassed, the step-by-step data flow from entry point to sink, and—for regressions—the exact introducing commit SHA identified via `git log -S` or `git bisect run node repro.mjs`.
3. **Minimal Verified Candidate Patch (Validated by the Three-Arm Proof Below):**
   - A minimal diff that fixes the bug class at the trusted backend layer and passes both the existing test suite and the Three-Arm Proof + Regression Hunt below.

---

## 4. The Three-Arm Patch Proof & Automated Regression Hunting (`Trail of Bits`, October 21, 2026)

Finding a real vulnerability is only half the battle—an unverified AI-generated security patch can quietly break production behavior or introduce a new bug.

In [*"Your AI agent fixed the bug, but what else did it change?"*](https://blog.trailofbits.com/2026/10/21/your-ai-agent-fixed-the-bug-but-what-else-did-it-change/) (October 21, 2026), Trail of Bits audited **130+ AI-generated security patches** that had already been reviewed and merged into open-source repositories during *Patch the Planet*. They discovered that **21 of those merged security PRs (~16%) introduced real behavioral regressions**—because standard workflows only checked that the patch compiled and passed existing unit tests.

To eliminate patch regressions, every security fix generated under this playbook must pass Trail of Bits' two-stage verification workflow (**`patching-bugs`** + **`regression-hunt`**):

### Stage A: The Three-Arm Proof (`patching-bugs`) + Invariant-Guided Repair

Before proposing a security patch, the patching agent must:
1. **State the Structural Invariant (`Invariant-Guided Repair`):** Explicitly document which invariant from `THREAT_MODEL.md` / [`five-universal-invariants.md`](../strategy/five-universal-invariants.md) and `PATCHING_GUIDELINES.md` is being restored, ensuring the fix enforces the invariant across the whole trust boundary rather than merely blocklisting the specific payload in the PoC.
2. **Execute the Live Three-Arm Proof in the Exact Same Build Environment:**

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ ARM 1: Unpatched Baseline + PoC  ──► MUST FAIL (Reproduces the bug)     │
│        (Proves the PoC script actually triggers the vulnerability)      │
├─────────────────────────────────────────────────────────────────────────┤
│ ARM 2: Apply Patch + Rebuild + PoC ──► MUST PASS (Blocks the exploit)   │
│        (Proves the candidate patch stops the vulnerability)             │
├─────────────────────────────────────────────────────────────────────────┤
│ ARM 3: Revert Patch in Same Env + PoC ──► MUST FAIL AGAIN               │
│        (Proves Arm 2 passed because of the code diff—NOT because of     │
│         mutated DB state, a crashed background worker, or env drift)    │
└─────────────────────────────────────────────────────────────────────────┘
```

If **Arm 3** does not fail identically to **Arm 1** when the patch is reverted in-place, the proof is invalid and the patch is rejected immediately.

### Stage B: Fresh-Context Regression Hunting & Adjudication (`regression-hunt`)

Once a patch passes the Three-Arm Proof, do **not** ask the same agent that wrote the patch whether its code has side effects (it will rationalize its own diff). Instead, spawn a **fresh-context `regression-hunt` agent**:
1. **Trace the Diff Outward to Public Interfaces:** For every modified function, struct, SQL query, or error return in the `git diff`, trace all callers up to public API routes, CLI entry points, or exported library functions.
2. **Formulate & Replay Concrete Regression Hypotheses:** Test whether tightening the guard breaks legitimate callers—for example:
   - Does rejecting a header/parameter break legitimate edge/webhook clients or pagination cursors?
   - Does changing an early return skip cleanup, transaction rollback, or lock release?
   - Does changing a `403` to `404` or altering an SQL join drop valid rows for multi-project members?
3. **Independent Adjudication Gate (Cuts False Positives by 25%):** Pass any candidate regression with a live replay test to an **independent adjudication agent** (running with `THREAT_MODEL.md` and `PATCHING_GUIDELINES.md`) that separates intentional security tightening (e.g., rejecting previously accepted spoofed tokens) from genuine functional regressions—a step that reduced false-positive regression alerts by **25%** in Trail of Bits' evaluation.
