# Part 2: Vulnerability Discovery & Autonomous Attacker Methods

When engineers ask:
> *"Checking a list of typical vulnerabilities is fine for known patterns—but how do we catch every possible exploit, including obscure edge cases, multi-step business logic flaws, and race conditions when we don't know in advance what to look for?"*

The answer is **Part 2 of this playbook**: instead of reading code hoping to spot a bug on a checklist, you **stand up an isolated local instance of the application, seed cryptographic canaries and conservation invariants, and run systematic attacker harnesses against every entry point**.

---

## Why This Architecture Works (2025–2026 Empirical Reality)

1. **Narrow Micro-Tasks & Multi-Agent Pipelines Beat Monolithic Scans by $3.3\times$–$5.4\times$:**
   - In BountyBench ([NeurIPS 2025, arXiv:2505.15216](https://arxiv.org/abs/2505.15216)), asking a frontier agent to *Detect* an unknown vulnerability across a repository succeeded only **12.5%** of the time, whereas scoping the agent to a concrete target locus and exploit hypothesis succeeded **67.5%** of the time ($5.4\times$).
   - In the NebuSec Benchmark ([September 1, 2026](https://nebusec.ai/research/nebu-benchmark/)) across 76 real ground-truth vulnerabilities, the **exact same `GPT-5.4` model** scored **24%** in `Codex Security (Standard)` and **43%** in `Codex Security (Deep)`, while switching to a decomposed multi-agent orchestration pipeline (`Nebu`) jumped detection to **80%** (**88%** at max compute).
2. **Deterministic Oracles & Cross-Model Judges Eliminate "CVE Slop":** Autonomous systems that reached human-tier performance in 2025–2026—such as **XBOW** (1,060+ validated vulnerabilities across 137 benchmarks), **Trail of Bits + OpenAI's `/goal`** (*Patch the Planet*, July–October 2026), **Anthropic's Project Glasswing** (**90.6% true-positive rate** across 1,587/1,752 audited findings in 1,000+ OSS repos and **88% CVD-grade** in 48-project pentester review), and **Google Project Zero's *Big Sleep*** (`CVE-2025-6965`)—never accept a single agent's prose opinion that a bug exists. Every finding must survive a **Two-Pass Cross-Model Judge Gauntlet** and pass a **deterministic validator** (capturing a `flag{UUID}` canary hash, triggering a database conservation invariant violation, or producing a sanitizer crash).
3. **White-Box Invariant Framing Gives 0% Refusals on Frontier Models:** As detailed in [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md), framing the attacker harness around localhost canary verification (`127.0.0.1`) and property-based invariant checks completely avoids safety refusals on stock frontier models (`Claude`, `GPT`, `Grok`) and stock open-weight models (`DeepSeek V4.1`, `GLM-5.3`) while avoiding the **up to -26.5% formal reasoning degradation** measured on community-abliterated weights ([Young, Jan 2026, arXiv:2512.13655v2](https://arxiv.org/abs/2512.13655)).

---

## The 9 Discovery & Attacker Methods (Execution Order)

| Step | Method File | Invariants Tested | What Unknown Bugs It Discovers |
|------|-------------|-------------------|-------------------------------|
| **Step 0** | [`surface-and-sink-mapping.md`](surface-and-sink-mapping.md) | `I1`–`I5` | Extracts the complete table of routes, actors, database tables, foreign keys, and sensitive sinks so zero endpoints or side doors are missed. |
| **Step 0.5** | [`attack-surface-and-config-interaction-audit.md`](attack-surface-and-config-interaction-audit.md) | `I1`, `I4`, `I5` | Runs Anthropic's 3-pass fresh-context Attack Surface Reduction (ASR) protocol to sever unnecessary pre-auth reachability (`OpenSSH 10.6` pattern) and catch fail-open configuration interactions. |
| **Step 1** | [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md) | `I1`, `I2`, `I4` | Spins up an ephemeral local target (`127.0.0.1`), creates Victim (`User A`) with `flag{UUID}` canaries across DB rows, S3/R2 blobs, local files, and an internal SSRF listener, and hands Attacker (`User B`) only `SHA-256(flag)`. |
| **Step 2** | [`differential-and-side-door-oracles.md`](differential-and-side-door-oracles.md) | `I2` | Automatically compares what `Owner`, `Member`, `ProjectGuest`, `Stranger`, and `Revoked` actors can see across primary CRUD vs. search, activity history, exports, aggregates, webhooks, and MCP tools, plus verifies `404` anti-enumeration. |
| **Step 3** | [`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md) | `I1`, `I2`, `I4`, `I5` | Dispatches isolated single-outcome micro-agents (`/goal` + `XBOW` + `Nebu` architecture) with 1-sentence variant calibration, `agentcov` / `coverage.json` tracking, and a Two-Pass Cross-Model Judge + PoV Validator gate. |
| **Step 4** | [`concurrency-and-race-attack-harnesses.md`](concurrency-and-race-attack-harnesses.md) | `I3` | Fires barrier-synchronized parallel HTTP bursts (25+ requests in the same millisecond) and deterministic thread permutations (`shuttle`/`loom`) against balances, credits, coupons, quotas, and token revocations. |
| **Step 5** | [`stateful-property-and-fuzzing-harnesses.md`](stateful-property-and-fuzzing-harnesses.md) | `I2`, `I3`, `I4` | Generates thousands of random multi-step command sequences (`proptest-state-machine`, `fast-check`) against a reference model, runs entry-point coverage fuzzing, and constructs custom compile-variant/backpressure fuzz labs (`zlib` pattern). |
| **Step 6** | [`bounded-formal-verification.md`](bounded-formal-verification.md) | `I1`, `I3`, `I4` | Uses symbolic model checking (`Kani` in Rust, `Alloy`/`TLA+` for state machines) on the most critical ~300 lines of auth, token parsing, and ledger math to prove zero panics/bypasses across **all** possible inputs. |
| **Reference** | [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md) | All | Empirical 2025–2026 benchmark analysis (Vals AI, CyberGym, ExploitGym, Glasswing, NebuSec, BountyBench, abliteration evals) and exact prompt templates for zero-refusal white-box security testing. |

---

## Decision Tree: Which Method Catches Which Unknown Bug?

```text
Do you want to verify that...
│
├─► "Can pre-auth callers reach disabled/complex parsers, or do two config flags silently disable a guard?"
│     └── Run the 3-Pass Fresh-Context ASR & Config-Interaction Audit -> `attack-surface-and-config-interaction-audit.md`
│
├─► "Can any unauthorized user/guest EVER read or mutate another user's data across any endpoint?"
│     ├── 1. Plant DB + Blob canaries in User A -> `isolated-lab-and-canary-setup.md`
│     ├── 2. Run automated cross-surface parity & 404 oracle -> `differential-and-side-door-oracles.md`
│     └── 3. Dispatch per-route white-box micro-agents -> `autonomous-micro-agent-red-teaming.md`
│
├─► "Can a weird 6-step sequence of invites, project moves, role changes, and revocations leave stale access?"
│     └── Build a Reference State Machine (`fast-check` / `proptest`) -> `stateful-property-and-fuzzing-harnesses.md`
│
├─► "Can parallel requests double-spend credits, redeem a coupon twice, or exceed plan limits?"
│     └── Fire barrier-synchronized bursts & `shuttle` thread permutations -> `concurrency-and-race-attack-harnesses.md`
│
├─► "Can any malformed byte stream panic our parser, escape terminal bracketed paste, or spoof our JWT verifier?"
│     ├── 1. Entry-point & compile-variant fuzzing (`cargo-fuzz` / `zlib` lab) -> `stateful-property-and-fuzzing-harnesses.md`
│     └── 2. Bounded symbolic proof (`cargo kani`) -> `bounded-formal-verification.md`
│
└─► "Did someone add a new route or table and forget a guard, or did an AI security patch introduce a regression?"
      ├── 1. Run deterministic Surface & Sink Mapping + `coverage.json` -> `surface-and-sink-mapping.md`
      └── 2. Enforce the Three-Arm Patch Proof & `regression-hunt` -> `../baselines/pre-deploy-security-pipeline.md`
```
