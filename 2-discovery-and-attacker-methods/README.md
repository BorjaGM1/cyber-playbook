# Part 2: Vulnerability Discovery & Autonomous Attacker Methods

When engineers ask:
> *"Checking a list of typical vulnerabilities is fine for known patterns—but how do we catch every possible exploit, including obscure edge cases, multi-step business logic flaws, and race conditions when we don't know in advance what to look for?"*

The answer is **Part 2 of this playbook**: instead of reading code hoping to spot a bug on a checklist, you **stand up an isolated instance of the application, seed canaries and conservation invariants, run a deterministic (no-LLM) oracle sweep over every entry point, and spend model tokens only on what scripts cannot decide**. Every claim is a PoV that the *harness* replays; no agent certifies its own result.

---

## Why This Architecture Works (2025–2026 Empirical Reality)

The full figures, sources and dates live in one place each; this page only summarizes.

1. **Narrow micro-tasks and orchestrated pipelines beat monolithic scans.** Scoping to a concrete locus took BountyBench ([NeurIPS 2025, arXiv:2505.15216](https://arxiv.org/abs/2505.15216)) from 12.5% (`Detect`) to 67.5% (`Exploit`), a 5.4× gain; the same `GPT-5.4` model went from 24%/43% to 80%/88% on the NebuSec Benchmark ([Sep 1, 2026](https://nebusec.ai/research/nebu-benchmark/)) purely by changing the orchestration pipeline (3.3×). → [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md) §2C, [`../observations/LOG.md`](../observations/LOG.md) entries 4 and 8, [`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md) §8.
2. **Deterministic oracles and cross-model judges eliminate "CVE slop".** XBOW, Trail of Bits + OpenAI `/goal` (*Patch the Planet*), Anthropic's Project Glasswing (90.6% true-positive across 1,587/1,752 audited findings, 88% CVD-grade in a 48-project expert review) and Google Project Zero's *Big Sleep* (`CVE-2025-6965`) all gate findings on a validator rather than a model's prose. → [`../observations/LOG.md`](../observations/LOG.md) entries 1, 3 and 8, [`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md).
3. **Pipeline design includes the models.** Stock frontier and open-weight models, including the `GLM-5.3` + `DeepSeek V4.1 Flash 1017` dual-model topologies and the Artificial Analysis Cyber Index results, are covered—together with how to *measure* refusal rate instead of assuming it—in [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md). Community-abliterated weights degrade reasoning by up to -26.5% (Young, Jan 2026, [arXiv:2512.13655v2](https://arxiv.org/abs/2512.13655)).
4. **The auditor is itself a target.** The audited repository is untrusted input to the agent (build scripts, injected comments). Sandbox rules: [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md) (Auditor Sandboxing) and [`../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md).

---

## Gate 0: Human-Confirmed Specification (Before Anything Runs)

Oracles and agents can only report violations of a *specified* behavior. Before Step 1.5, a human confirms (once per application):
- `THREAT_MODEL.md` — trust boundaries, attacker inputs, non-goals.
- `authz-matrix.yaml` — expected status per `(actor, route)` (ASVS `v5.0.0-8.1.1`, [`../baselines/owasp-asvs-v5-level-1.md`](../baselines/owasp-asvs-v5-level-1.md)).
- `intended-exposures.yaml` — by-design cross-actor visibility (public links, org directory).

Missing spec means the correct output is a question to the human (`INTENT_AMBIGUOUS`), not a model guess.

---

## The Discovery & Attacker Methods (Execution Order)

| Step | Method File | Invariants Tested | What It Does |
|------|-------------|-------------------|--------------|
| **Step 0** | [`surface-and-sink-mapping.md`](surface-and-sink-mapping.md) | `I1`–`I5` | Runtime-and-static route enumeration with a diff, actors, tenant-column tables, sinks, config/flag graph, capability graph, and `AUTH_DIGEST.md` |
| **Step 0.5** | [`attack-surface-and-config-interaction-audit.md`](attack-surface-and-config-interaction-audit.md) | `I1`, `I4`, `I5` | 3-pass fresh-context Attack Surface Reduction (ASR), web-app pre-auth surface list, pruned config-interaction audit (`OpenSSH 10.6` pattern) |
| **Step 1** | [`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md) | `I1`, `I2`, `I4` | Network- and process-isolated lab: attacker sandbox with no DB/oracle access, credential-allowlist proxy, harness-run PoV replay, per-agent clones, production-engine race labs, SSRF fixtures (loopback, metadata, RFC1918, redirect, rebinding), plain/fragment/metadata/count canaries, DB-diff + mock-egress integrity oracles, and auditor sandboxing |
| **Step 1.5** | [`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md) | `I1`–`I4` | **No-LLM sweep over 100% of routes:** token mutation matrix, ID-substitution/indistinguishability, side-door parity, mass-assignment/step-skip, race bursts, **SQL query-log tenant-predicate oracle**, `ScopedDb` schema introspection, SSRF battery, **guard-mutation self-test**; emits findings + the *residual list* |
| **Step 2** | [`differential-and-side-door-oracles.md`](differential-and-side-door-oracles.md) | `I2` | The real subset computation (`ReferencedIDs ⊆ PrimaryIDs`), body/header/timing indistinguishability, deleted-resource, revoked-actor and vertical-escalation oracles |
| **Step 3** | [`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md) | `I1`, `I2`, `I4`, `I5` | Tiered micro-agents on the **residual only**: cached prefix, chain agent, roamer, budgets and stopping rules, discriminating `INVARIANT_HELD`, coverage = executed negative tests + code coverage + differential coverage; judges only for oracle-less classes |
| **Step 4** | [`concurrency-and-race-attack-harnesses.md`](concurrency-and-race-attack-harnesses.md) | `I3` | Last-byte (HTTP/1.1) and single-packet (HTTP/2) bursts, real-engine SQL races, multi-instance races, `shuttle` for in-process stores with a positive control |
| **Step 5** | [`stateful-property-and-fuzzing-harnesses.md`](stateful-property-and-fuzzing-harnesses.md) | `I2`, `I3`, `I4` | Reference-model state machines over every read surface (comments, history, search, export), command alphabet generated from the capability graph, entry-point coverage fuzzing, fuzz-lab construction (`zlib` pattern) |
| **Step 6** | [`bounded-formal-verification.md`](bounded-formal-verification.md) | `I1`, `I3`, `I4` | `Kani` over the **production** decision function with an independent spec and positive control; `Alloy` check that must refute the vulnerable predicate |
| **Reference** | [`models-and-refusal-free-framing.md`](models-and-refusal-free-framing.md) | All | 2025–2026 benchmarks, dual-model orchestration topologies, refusal-rate measurement, third-party API data-handling rule |

---

## Decision Tree: Which Method Catches Which Unknown Bug?

```text
Do you want to verify that...
│
├─► "Can pre-auth callers reach disabled/complex parsers, or do two config flags silently disable a guard?"
│     └── 3-Pass Fresh-Context ASR & Config-Interaction Audit -> `attack-surface-and-config-interaction-audit.md`
│
├─► "Can any unauthorized user/guest EVER read or mutate another user's data across any endpoint?"
│     ├── 1. Isolated lab + canaries (attacker cannot see the oracle) -> `isolated-lab-and-canary-setup.md`
│     ├── 2. No-LLM oracle sweep incl. SQL query-log tenant-predicate oracle -> `deterministic-oracle-sweep.md`
│     ├── 3. Cross-surface parity & indistinguishability -> `differential-and-side-door-oracles.md`
│     └── 4. LLM micro-agents on the RESIDUAL only -> `autonomous-micro-agent-red-teaming.md`
│
├─► "Do my oracles actually fail when a guard is removed?"
│     └── Guard-mutation self-test + positive controls -> `deterministic-oracle-sweep.md` (O9)
│
├─► "Can a weird 6-step sequence of invites, project moves, role changes, and revocations leave stale access?"
│     └── Reference state machine over all surfaces, generated command alphabet -> `stateful-property-and-fuzzing-harnesses.md`
│
├─► "Can parallel requests double-spend credits, redeem a coupon twice, or exceed plan limits?"
│     └── Barrier bursts on the production engine, >=2 instances; `shuttle` for in-process stores -> `concurrency-and-race-attack-harnesses.md`
│
├─► "Can any malformed byte stream panic our parser, escape terminal bracketed paste, or spoof our JWT verifier?"
│     ├── 1. Entry-point & compile-variant fuzzing (`cargo-fuzz` / `zlib` lab) -> `stateful-property-and-fuzzing-harnesses.md`
│     └── 2. Bounded symbolic proof of the production function (`cargo kani`) -> `bounded-formal-verification.md`
│
├─► "Could the audit itself be compromised by the repo under audit?"
│     └── Auditor sandboxing -> `isolated-lab-and-canary-setup.md` and `../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md`
│
└─► "Did someone add a route or table and forget a guard, or did an AI security patch introduce a regression?"
      ├── 1. Regenerate the map + static-vs-runtime diff + schema-introspection `ScopedDb` test -> `surface-and-sink-mapping.md`, `../strategy/scoped-db.md`
      └── 2. Four-Arm Patch Proof, golden-traffic diff, regression-hunt -> `../baselines/pre-deploy-security-pipeline.md`
```

---

## Related Part 1 Notes Referenced by Part 2

| Topic | Note |
|-------|------|
| Scoped data access (the construction the query-log oracle checks) | [`../strategy/scoped-db.md`](../strategy/scoped-db.md) |
| Background jobs that lose scope | [`../1-known-vulnerabilities/authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../1-known-vulnerabilities/authorization-and-tenancy/async-jobs-and-scope-propagation.md) |
| Caches, derived data, module-global state, RAG namespaces | [`../1-known-vulnerabilities/authorization-and-tenancy/cache-and-derived-data.md`](../1-known-vulnerabilities/authorization-and-tenancy/cache-and-derived-data.md) |
| Next.js / edge specifics | [`../1-known-vulnerabilities/auth-and-sessions/nextjs-and-edge-specifics.md`](../1-known-vulnerabilities/auth-and-sessions/nextjs-and-edge-specifics.md) |
| Account lifecycle and federation | [`../1-known-vulnerabilities/auth-and-sessions/account-lifecycle-and-federation.md`](../1-known-vulnerabilities/auth-and-sessions/account-lifecycle-and-federation.md) |
| Browser boundary (XSS, CSRF, CSWSH, CORS) | [`../1-known-vulnerabilities/injection-and-trust-boundaries/browser-boundary.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/browser-boundary.md) |
| Agentic and MCP threats (including the auditor) | [`../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md) |
