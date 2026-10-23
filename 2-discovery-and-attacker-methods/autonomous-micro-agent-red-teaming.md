# Step 3: Autonomous Micro-Agent Red Teaming (`XBOW`, `/goal`, `Nebu` & `Big Sleep` Patterns)

This step runs **after** the deterministic oracle sweep ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md)). The sweep decides everything a script can decide, over 100% of the surface, at near-zero token cost. Micro-agents are spent only on the **residual list**: the places where judgment, multi-step reasoning, or a new probe is needed. The evidence for why decomposition and deterministic gates matter is in Section 8.

---

## 1. Topology: Tiered, Not Top-K

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ GATE 0 (no LLM): authz-matrix.yaml + intended-exposures.yaml + THREAT_MODEL.md exist   │
│                  (human-confirmed). Without them the run STOPS (INTENT_AMBIGUOUS).     │
└───────────────────────────────────────┬────────────────────────────────────────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1 (no LLM, 100% of routes): Deterministic Oracle Sweep O1–O9                       │
│   -> findings (PoV) + RESIDUAL LIST [(route, invariant, reason)]                        │
└───────────────────────────────────────┬────────────────────────────────────────────────┘
                                        ▼  only residual items
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: Single-Outcome Micro-Agents (one per residual (route, invariant) cluster)       │
│   stable cached prefix + variable suffix; own lab clone; budget 12 steps / 60k tokens   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ TIER 2b: Chain Agent(s): consume the Capability Graph (surface map Table F) and        │
│   propose multi-step sequences; harness executes them with the full-surface oracle      │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ TIER 2c: Roamer: shared helpers, serializers, cross-module state; differential-coverage │
│   hints ("branches the owner suite hits and no attacker request ever has")              │
└───────────────────────────────────────┬────────────────────────────────────────────────┘
                                        ▼  every claim is a submitted PoV artifact
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ HARNESS (outside the agent sandbox): replays PoV in a fresh restored lab through the    │
│   credential-allowlist proxy; oracle scans the CAPTURE log, DB diff, mock egress, SSRF  │
│   hits. Verdict = VERIFIED | NOT_REPRODUCED | INVALID_POV. Agents never self-certify.   │
└───────────────────────────────────────┬────────────────────────────────────────────────┘
                                        ▼  only oracle-less classes (Section 6)
                          Judge 1 (impact/intent)  ->  Judge 2 (cross-model falsifier)
                                        ▼
                      Verified Vulnerability -> Patch Proof (baselines/pre-deploy-security-pipeline.md)
```

Patch pipeline: [`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md).

This resolves the earlier contradiction between "select the top 5 surfaces" and "`routesUnaudited.length === 0`": **100% of routes are covered by the deterministic tier**; LLM budget is concentrated where the deterministic tier is blind or cannot decide. A route is "audited" when every applicable `(route, invariant)` cell is in a terminal state (Section 5), whichever tier decided it.

**Model assignment.** Which model plays which role—stock frontier models for architecture and Judge 2, stock open-weight models for high-volume micro-agents, the `GLM-5.3` + `DeepSeek V4.1 Flash 1017` dual-model topologies for Tier 2 sweeps—is specified in [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md). Different model *families* for finder and Judge 2 is a hard rule here.

**Auditor threat.** The agents in this tier read untrusted repository text and execute untrusted build steps; they run only inside the auditor sandbox ([`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md), Auditor Sandboxing), never hold host secrets, and their prose is never evidence. Threat catalog: [`../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md).

**Data handling.** Source code and lab traffic sent to a third-party model API is a disclosure; follow the data-handling rule in [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md) before enabling any hosted model.

---

## 2. Stable Cached Prefix, Variable Suffix (Where Most Tokens Are Saved)

Without structure, every micro-agent re-reads the auth middleware, the database wrapper and the threat model before doing anything useful, and those reads dominate its 12 steps. Instead:

```text
┌───────────────────────────── STABLE PREFIX (byte-identical across agents; prompt-cached) ───────────────┐
│ 1. Role + rules (white-box lab, localhost-only framing, output contract)                                 │
│ 2. THREAT_MODEL.md                                                                                       │
│ 3. authz-matrix.yaml + intended-exposures.yaml                                                           │
│ 4. AUTH_DIGEST.md  (how identity, scope, middleware order and revocation work — from Step 0)             │
│ 5. SECURITY_SURFACE_MAP.json summary (route table, Table C tenant columns, capability graph)             │
│ 6. Tool descriptions (submit-pov, run-in-clone, read-file, run-script)                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌───────────────────────────── VARIABLE SUFFIX (per agent) ────────────────────────────────────────────────┐
│ route/hypothesis, handler span, residual reason, lab clone endpoint, attacker credentials, budget        │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Rules: keep the prefix free of timestamps, run IDs and anything per-agent (any change invalidates the cache); put the stable material first; regenerate the prefix only when `AUTH_DIGEST.md`, the matrix or the surface map changes. This is also what makes the ~99% prompt-cache-hit regime reported for the dual-model topologies reachable (figures in [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md)).

---

## 3. Hypothesis Queue (Residual Only)

Generate single-outcome hypotheses **only** for residual `(route, invariant)` items (plus the roamer and chain agents):

| Hypothesis Class | Residual Triggers | One-Sentence Risk Class & Question Given to the Micro-Agent |
|------------------|-------------------|--------------------------------------------------------------|
| **`H-I1-Spoof`** | `ORACLE_BLIND` on auth guards; non-standard verifiers; federation callbacks | *"Can an unauthenticated caller or `PendingAuth` cookie holder forge headers/tokens (`Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, `alg:none`, cross-cookie substitution, outer-vs-inner type mismatch) to obtain a `200` on `Route X`?"* |
| **`H-I2-CrossTenant`** | ID routes with `ORACLE_BLIND`, `TIMING_SUSPECT`, `NO_ORACLE_FOR_CLASS` | *"Using `User B`'s session (`Tenant B`), can you pass `Tenant A`'s resource UUID (`ID_A`) as a path param, query param, or foreign-key body field on `Route X` to extract a canary or mutate `Tenant A`'s state?"* |
| **`H-I2-GuestEscape`** | Search/History/Exports/Attachments/Move with partial oracle coverage | *"Using `Guest G`'s session (authorized ONLY for `Project Public`), can you extract a canary from `Project Secret` via `Route X`, including through pre-move comments and history?"* |
| **`H-I2-AsyncScope`** | Queue/cron/email/DO entry points | *"Can `User B` cause a background job on `Route X`'s queue to read or write `Tenant A` data by controlling an ID in the payload?"* |
| **`H-I3-RaceAndSkip`** | `NEEDS_MULTI_STEP_CHAIN`, new economic routes | *"Using `User B`'s session (balance = 1 unit), can a barrier burst or out-of-order state transition on `Route X` commit ≥ 2 units or skip payment verification?"* |
| **`H-I4-Boundary`** | URL fetchers, uploads, sort/filter objects, PTY, MCP/agent tools | *"Can `User B` reach the lab SSRF fixtures, upload an active payload, break SQL/ORM operator syntax, or steer the agent tool router on `Route X`?"* |
| **`H-Chain`** | Capability-graph sequences | *"Is there a sequence of ≤ 8 permission-changing operations from the capability graph after which `Actor G` can read, or `Actor M` can write, something the authorization matrix forbids?"* |

---

## 4. Exact Micro-Agent Prompt Template (White-Box + Submitted PoV)

```text
You are running an isolated white-box invariant verification test on a lab clone.
Target (reachable only through the lab proxy): {PROXY_URL}   # per-agent clone {AGENT_ID}; do not use any other host
Your workspace is /work/{AGENT_ID} (private). Do not use shared /tmp paths.

### SINGLE TARGET OUTCOME
- Route under test: {METHOD} {ROUTE_PATH}
- Handler source: {SOURCE_FILE_PATH}:{START_LINE}-{END_LINE}
- Why this is residual: {RESIDUAL_REASON}
- Invariant & risk class (1 sentence): {INVARIANT_ID} — {ONE_SENTENCE_RISK_CLASS}

### PROVIDED (the cached prefix above already contains THREAT_MODEL, authz matrix, AUTH_DIGEST, surface map)
- Attacker credentials (the ONLY credentials the proxy accepts): {ATTACKER_B_CREDENTIAL}, {GUEST_G_CREDENTIAL}, {REVOKED_CREDENTIAL}
- Victim resource IDs (simulating leaked/enumerated IDs): {JSON_VICTIM_UUIDS}
- Canary SHA-256 map (plaintext flags exist only inside the oracle process): {JSON_CANARY_SHA256_MAP}

### PROTOCOL (MAX 12 STEPS; the harness enforces it, you do not self-count)
1. Read the handler and only the helpers it calls that AUTH_DIGEST does not already explain.
2. Identify which of these the code path omits: tenant predicate, guest project-membership check, foreign-key ownership validation, state-transition guard, URL/path/SQL sanitization.
3. Write `/work/{AGENT_ID}/repro.mjs` that talks ONLY to {PROXY_URL} using the provided attacker credentials.
4. Call `submit-pov --route ... --invariant ... --claim claim.json repro.mjs`. The harness replays it in a freshly restored lab and returns only a verdict. You cannot see canaries, run the oracle, or read the database.
5. Return exactly one of:
   - `PoV_SUBMITTED` + the harness verdict (`VERIFIED` only if the harness says so) + root-cause `file:line` + minimal patch idea; or
   - `INVARIANT_HELD` + the exact `file:line` spans read + the NEGATIVE TESTS you executed (see below).
```

**`INVARIANT_HELD` must be discriminating.** An agent that sends one malformed request, gets a `404`, and declares the invariant held has shown nothing. A negative test counts only if the harness can show it would have **failed against a mutant** of the guard (guard deleted, predicate dropped—[`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md), O9). The harness re-runs the submitted negative tests against the route's mutant lab; tests that still pass on the mutant are recorded as `HELD_NON_DISCRIMINATING` and the cell stays open.

---

## 5. Coverage Is Executed Negative Tests, Not Lines Read

`agentcov`-style read tracking (Section 8) is necessary to catch agents that skip files, but **reading a line is not reasoning about it**; an agent can `cat` a file. Use four independent measures and report them side by side.

1. **The `(route, invariant)` matrix.** Every applicable cell must reach a terminal state:

   | State | Meaning |
   |-------|---------|
   | `VIOLATED` | A harness-verified PoV exists |
   | `HELD_DISCRIMINATING` | Negative tests exist that fail on the guard mutant |
   | `HELD_NON_DISCRIMINATING` | Tests passed on the mutant too — **not terminal** |
   | `ORACLE_BLIND` | A guard mutant survived the sweep — **not terminal** |
   | `UNTESTED` | No test executed — **not terminal** |
   | `OUT_OF_SCOPE` | Excluded by `THREAT_MODEL.md` with a reason |

2. **Application code coverage under attacker traffic.** Run the app in the lab with coverage on and drive only attacker credentials:
   ```bash
   # Node / TypeScript (V8 coverage)
   NODE_V8_COVERAGE=/capture/$RUN/v8-attacker node dist/server.js &   # then run sweep + agents
   npx c8 report --temp-directory /capture/$RUN/v8-attacker --reporter=json

   # Rust
   RUSTFLAGS="-C instrument-coverage" LLVM_PROFILE_FILE="/capture/$RUN/attacker-%p.profraw" cargo build
   cargo llvm-cov report --json --profile-data /capture/$RUN/*.profraw
   ```
3. **Differential coverage (the authz edges nobody attacked).** Compute `lines(owner happy-path suite) \ lines(attacker traffic)` restricted to guard functions (those listed in AUTH_DIGEST and the capability graph). Every such line is a branch the application takes for legitimate users and that no adversarial request has ever exercised: it goes to the roamer as a lead.
4. **Reads (`agentcov`/transcript parsing)** as a cheap sanity check against rationalized skipping.

`coverage.json` therefore reports cells and measured code coverage, never "0 findings":

```json
{
  "scanTimestamp": "2026-10-23T21:00:00Z",
  "routesTotal": 42,
  "cells": { "VIOLATED": 3, "HELD_DISCRIMINATING": 148, "HELD_NON_DISCRIMINATING": 6,
             "ORACLE_BLIND": 4, "UNTESTED": 5, "OUT_OF_SCOPE": 12 },
  "routesWithOpenCells": [
    { "route": "POST /api/webhooks/legacy-import", "file": "src/routes/legacy-import.ts:1-140",
      "openCells": ["I3:UNTESTED", "I4:ORACLE_BLIND"],
      "reason": "budget exhausted before submit-pov; mutant survived O9" }
  ],
  "appCodeCoverageUnderAttackerTraffic": { "guardFunctionsLinePct": 91.4, "overallLinePct": 63.0 },
  "differentialUncoveredGuardLines": ["src/auth/scope.ts:88-97", "src/routes/export.ts:140-152"],
  "filesReadCoveragePct": 92.8,
  "mutationKillRatio": { "tenantGuards": 0.94, "authGuards": 0.88 },
  "verifiedVulnerabilities": 0
}
```

Any route with non-terminal cells is re-queued (fresh context, rewritten hypothesis) or escalated per Section 7 until the budget is spent—at which point it remains **listed as unaudited**. Zero findings never equals full coverage.

---

## 6. Judge Gauntlet: Only Where There Is No Oracle

When a finding has a deterministic harness verdict (canary hit, DB diff, query-log violation, conservation breach, sanitizer crash), the validator already decides truth; two LLM judges add cost, latency and error without adding precision. Judges are reserved for:

- **Oracle-less classes:** logic flaws, authorization-intent questions, indirect-prompt-injection routing, severity assessment, and anything classified `NO_ORACLE_FOR_CLASS` in the residual list.
- **"Is this by spec?" decisions** when `authz-matrix.yaml` is silent (`INTENT_AMBIGUOUS`)—which should trigger a human question, not a model guess.

For those, run the **Two-Pass Cross-Model Judge Gauntlet**:
- **Judge 1 (Threat-Model & Severity Gate):** verifies that the candidate crosses a real trust boundary defined in `THREAT_MODEL.md`, and does not rely on impossible preconditions.
- **Judge 2 (Cross-Model Falsifier):** runs on a **different model family** than the finder (if `GPT/Codex` or `DeepSeek` found the bug, `Claude` acts as Judge 2, or vice versa). **Judge 2 receives the PoV artifact and the code, never the finder's narrative**, to avoid anchoring, and is instructed to try to disprove the finding.

---

## 7. Escalation Ladder, Budgets and Stopping Rules

"No bugs found" is an *intermediate* state in the sense that the strategy must change—but it cannot trigger unbounded spending. Per residual item:

| Level | Method | Budget | Exit |
|-------|--------|--------|------|
| L0 | Deterministic sweep (O1–O9) | wall-clock only | cell terminal, or residual |
| L1 | Single-route micro-agent | 12 steps / ~60k tokens | `VIOLATED` or discriminating `HELD` |
| L2 | Stateful property test + chain agent over the capability graph | 40 steps / ~200k tokens | counterexample (shrunk) or `HELD` over N sequences ([`stateful-property-and-fuzzing-harnesses.md`](stateful-property-and-fuzzing-harnesses.md)) |
| L3 | Targeted race / fuzz / bounded proof on the pure-logic core | per tool | counterexample or bounded proof ([`concurrency-and-race-attack-harnesses.md`](concurrency-and-race-attack-harnesses.md), [`bounded-formal-verification.md`](bounded-formal-verification.md)) |
| STOP | Report the cell as `HELD_*` or `UNTESTED` **with its reason** | — | never silently dropped |

Global rules: a hard per-route and per-run token cap set in the harness (not in the prompt); promote to the next level only if the previous level produced a *new lead* (a surviving mutant, an uncovered guard line, a TIMING_SUSPECT, a differential gap); stop a level after two consecutive agents return `HELD_DISCRIMINATING` for the same cell; stop the run when marginal new `VIOLATED` or new terminal cells per 100k tokens falls below the threshold set in the run config. Budget exhaustion produces an honest `UNTESTED`.

---

## 8. Evidence and Rules From the Field (2025–2026)

### 8.1 Why a Single Monolithic Agent Fails

If you spin up a single coding agent, hand it a 50,000-line codebase, and prompt it: *"Act as a red teamer and find all security vulnerabilities in this application"*, three failure modes occur almost immediately:
1. **Context Pollution & Shallow Skimming:** After reading 6 files and running 3 `curl` commands that return `401` or `404`, the agent concludes *"authorization appears properly enforced"* and stops—missing the subtle IDOR in the batch-update route or the purpose-confusion bug in the MFA cookie.
2. **Rationalized Coverage Shortcuts:** When Trail of Bits audited agent transcripts during *Patch the Planet* ([July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)), they found that agents instructed to "audit 100% of the repo" routinely skipped complex modules and rationalized in their final summary that those directories were "out of scope."
3. **Unverified Hallucinations ("CVE Slop"):** To look helpful, a monolithic agent writes a 10-item markdown report flagging theoretical issues that cannot actually be exploited because of upstream middleware or schema constraints it never tested.

### 8.2 Empirical Proof: Pipeline Orchestration > Model Generation (2025–2026)

Controlled benchmarks in 2026 proved that **how you decompose, orchestrate, and gate your security agents matters far more than which frontier model checkpoint you call**:
- **NebuSec Benchmark ([September 1, 2026](https://nebusec.ai/research/nebu-benchmark/)) & Context Studios Evaluation ([July–September 2026](https://www.contextstudios.ai/comparisons/codex-security-vs-claude-code-security-review)):** Tested against **76 real ground-truth vulnerabilities** in production codebases using the **exact same underlying model (`GPT-5.4`)**:
  - `OpenAI Codex Security (Standard scan)`: **24% detection**.
  - `OpenAI Codex Security (Deep mode)`: **43% detection**.
  - `Nebu` (multi-agent hypothesis decomposition + iterative tool orchestration using the **same `GPT-5.4` model**): **80% detection** (and **88%** at maximum compute—a **$3.3\times$ improvement** from pipeline architecture alone).
  - Similarly, in `Claude Security` (`Opus 5`), simply removing an internal orchestration cap that truncated output at the first 45 candidate findings increased real vulnerability coverage from **42% to 74%**.
- **XBOW & DARPA AIxCC CRS Systems ([arXiv:2603.08566](https://arxiv.org/abs/2603.08566)):** XBOW reached #1 on the US HackerOne leaderboard (1,060+ validated vulnerabilities across 137 benchmarks in ~4 hours per target) by decomposing every target into narrow `(EntryPoint, Invariant)` micro-agents gated by deterministic Proof-of-Vulnerability (`PoV`) validators.
- **Google Project Zero & DeepMind — *Project Naptime* & *Big Sleep* (2024–2025):** Replaced monolithic code-reading prompts with four specialized agent tools—a **Code Browser** (to navigate call graphs without flooding context), a **sandboxed Python interpreter** (so the agent computes buffer offsets and crafts inputs in code rather than doing mental math), a **Debugger / ASan oracle** (inspecting live crash state and registers), and a **Reporter gate**. This architecture found a pre-release stack buffer underflow in `SQLite` (Oct 2024) and pre-empted the in-the-wild `SQLite` integer truncation vulnerability **`CVE-2025-6965`** (Summer 2025).

### 8.3 The 3 Rules of `/goal` from Trail of Bits & OpenAI (*Patch the Planet*, July 2026)

In July 2026, Trail of Bits and OpenAI published field reports from **Patch the Planet** ([Part 1, July 2, 2026](https://blog.trailofbits.com/2026/07/02/field-reports-from-patch-the-planet/); [Part 2: How We Use `/goal`, July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)), detailing how their autonomous agents audited `curl`, `zlib`, `rust-lang/rust`, and `Keycloak`. Every multi-agent security run should enforce their three operational rules:

**Rule 1: Generate `THREAT_MODEL.md`, Let the Agent Self-Red-Team Its Goal Prompt, and Track Real Reads with `agentcov`.**
1. **Build `THREAT_MODEL.md` First:** Before searching for bugs, generate a concise threat model defining the repository's trust boundaries, attacker-controlled inputs, privileged actors, and explicit non-goals (so agents do not waste tokens reporting "bugs" that require an attacker to already have root or modify local config files). In this playbook it is accompanied by the human-confirmed `authz-matrix.yaml` and `intended-exposures.yaml` (Gate 0).
2. **Have the Agent Write and Red-Team Its Own `/goal` Prompt:** Ask the agent to draft its hunting prompt from `THREAT_MODEL.md`, then immediately ask a second prompt: *"Red-team this goal specification: how could a lazy agent satisfy the letter of this prompt while skipping the hardest code paths?"* Close every loophole before starting the run.
3. **Measure Objective File/Line Coverage (`agentcov` + `coverage.json`):** Never trust an agent's self-reported claim that it "reviewed all routes." Following Trail of Bits' **`agentcov`** (which parses agent tool transcripts to compute exact line-read coverage) and OpenAI `Codex Security`'s **`coverage.json` / `scan-manifest.json`** artifact, record every file and line range actually opened by a micro-agent and explicitly list **unaudited files and routes** in `coverage.json` (extended in Section 5 with executed negative tests, application code coverage and differential coverage).

**Rule 2: Define the Outcome (Not the Path) and Calibrate Variant-Search Width to One Sentence.**
1. **Treat `"No Bugs Found"` as an Intermediate State:** If a static code-reading pass returns 0 findings, the coordinator must treat that as an intermediate signal to switch strategies (e.g., spinning up a differential oracle, a concurrency burst, or a custom fuzz harness as `/goal` did on `zlib`), not as proof that the code is secure—bounded by the stopping rules in Section 7.
2. **The One-Sentence Rule for Variant Analysis (`rust-lang/rust` & `Keycloak`):**
   - When Trail of Bits gave `/goal` the **exact stack trace and function names** of a historical Rust standard-library CVE (`CVE-2022-21658`, TOCTOU race in `std::fs::remove_dir_all`) and asked for variants, the agent anchored too narrowly and found **0 bugs**.
   - When they abstracted the historical CVE into a **single sentence describing the underlying risk class** (*"Find race conditions, logic bugs, or input handling flaws in the Rust standard library and compiler that violate memory safety or soundness guarantees"*), the agent discovered **9 real bugs in `rust-lang/rust`**—including a **compiler soundness hole patched in Rust 1.98**—and **2 SAML privilege-escalation vulnerabilities in `Keycloak`** (abstracted from `CVE-2024-10492`).
   - **Takeaway:** When hunting variants of a past bug or a Part 1 case note, pass the micro-agent a **one-sentence description of the invariant violation class**, never a brittle regex tied to yesterday's variable names.

**Rule 3: Strictly One Outcome Per Agent + Cross-Model Judging Where No Oracle Exists.**
1. **Never Mix Competing Objectives in One Agent:** If you instruct one agent to *"achieve 80% code coverage AND find critical vulnerabilities,"* it will optimize the easier metric (skimming files to bump coverage) and find nothing.
2. **The `1 Mapper -> 5 Surface Agents + 1 Roamer` Topology** (Trail of Bits) is subsumed here by the tiered model: the deterministic sweep plays the mapper over all routes, residual clusters become the dedicated single-outcome agents, and the roamer follows weird cross-cutting leads (shared utility helpers, serializer quirks, cross-module state) that fall between surface boundaries.
3. **Two-Pass Cross-Model False-Positive Gauntlet:** Judge 1 (threat-model & severity) then Judge 2 (a different model family, demands a reproducible PoC and tries to disprove it) — applied per Section 6.
