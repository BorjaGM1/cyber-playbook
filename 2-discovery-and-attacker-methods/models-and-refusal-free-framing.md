# Reference: Models, 2025–2026 Benchmarks & Refusal-Free White-Box Framing

## 1. Executive Summary: Do You Need an "Abliterated" (Uncensored) Model to Defend Your Code?

**No.** If your goal is to audit your own repositories and run autonomous attacker harnesses against your own applications in local/staging environments, buying or hosting an "abliterated" model (an open-weight model with its refusal direction surgically projected out of the residual stream) is **unnecessary and empirically counterproductive**.

Here is what the 2025–2026 empirical data proves:
1. **Why attackers use uncensored/open-weight models on external networks:** When running black-box intrusion chains against third-party corporate networks, commercial safety filters on some frontier models (most notably `Claude Opus 5.5` in the October 2026 Vals AI benchmark) abort mid-chain when asked to dump Active Directory credentials or pivot across hosts.
2. **Why abliterating model weights hurts defensive code verification:** Abliteration (`Arditi et al., arXiv:2406.11717`) is not a free lunch. Controlled 2026 evaluations prove that removing refusal directions from model weights degrades mathematical and formal reasoning (`GSM8K`) by up to **-18.81 percentage points (-26.5% relative)**, increases hallucinations on `TruthfulQA` by **-5.75% to -6.87%**, drops hard recursive-parser coding scores from **98/100 to 13/100** when embedding layers are touched, and causes **25% agentic loop derailments** (3 of 12 tasks emitting garbage).
3. **Why white-box invariant & canary framing achieves 0% refusals on stock models:** Frontier models (`Claude`, `GPT`, `Grok`) and stock open-weight models (`DeepSeek V4.1 Flash 1017`, `GLM-5.3`) only refuse when prompted like an unauthorized black-box intrusion (`"hack this server and steal credentials"`). When prompted inside a white-box verification harness (`"verify Invariant I2 on 127.0.0.1:4100 by checking whether Tenant B's session can read flag{UUID} from Tenant A's project"`), **refusal rates drop to 0%** while preserving 100% of the model's formal reasoning and code-synthesis capability.

---

## 2. Empirical Benchmark Reality Check (2025–2026, Dated & Sourced)

### A. Artificial Analysis Cyber Index (October 23, 2026) & Vals AI Cyber Range (October 20, 2026)
- **Sources:**
  - [Artificial Analysis Cyber Index (2026-10-23)](https://artificialanalysis.ai/evaluations/artificial-analysis-cyber-index) & [@ArtificialAnlys release thread (2026-10-23)](https://x.com/ArtificialAnlys/status/2113682654709313811) (composite of `CWE-Bench-AA`, `DeepsecBench-AA`, and `CyberGym-E2E-AA`).
  - [@ValsAI Corporate Cyber Range benchmark (2026-10-20)](https://x.com/ValsAI/status/2112471082397778083) & [@barckcode analysis (2026-10-22)](https://x.com/barckcode/status/2113243485344010701) (21 sequential objectives, up to 500M tokens).
- **Artificial Analysis Cyber Index Results (Public API Evaluation, Oct 23, 2026):**
  - `GPT-6 Sol (Daybreak Blue, max)` (restricted trusted-access program): **69%** (#1 overall, **$1.77 / task**; scores **+32 percentage points** above its public counterpart due to fewer safety refusals).
  - `DeepSeek V4.1 Flash 1017 (max)` (stock open-weight, MIT license): **57%** (**#1 openly/publicly available model**, #2 overall, **$0.42 / task**, **0% safety refusals**). Up **+16 points** over `DeepSeek V4.1 Flash` (41%), driven by a **+53-point jump on `CyberGym-E2E-AA` (from 23% to 76%)**, plus **69%** on `CWE-Bench-AA` and **25%** on `DeepsecBench-AA`.
  - `Grok 4.7 (xhigh)` & `MiMo-V2.6-Pro`: **56%** (`MiMo-V2.6-Pro` at **$0.18 / task**).
  - `GLM-5.3-Flash`: **50%** (~**$0.35 / task**).
  - `GLM-5.3 (max, non-flash)`: **36%** (~**$2.50 / task**) in solo cold-start runs because of a large **safety-block bar** triggered when cold-started on raw offensive prompts (see Section 3A below for how pairing it with `DeepSeek V4.1 Flash 1017` eliminates this cold-start refusal).
  - `Claude Opus 5.5`: **29%** ($8–$20+/task) with a **36% safety-block bar** (`Session paused · Details: [cyber]`).
- **Vals AI Corporate Cyber Range Results (Mean Objectives Completed out of 21, Oct 20, 2026):**
  - `DeepSeek V4.1 Flash 1017` (stock open-weight): **16.3 / 21** (1st place overall).
  - `GPT-6 Sol Daybreak`: **15.7 / 21**.
  - `Grok 4.7`: **12.0 / 21**.
  - `Claude Opus 5.5`: **1.0 / 21** (aborted after objective 1 due to black-box offensive safety refusal).
- **Engineering Takeaway:** Stock `DeepSeek V4.1 Flash 1017` sits on the capability-vs.-cost Pareto frontier (**$0.42/task**, **0% safety refusals**, **76% on `CyberGym-E2E-AA`**), while frontier models (`Claude`, `GPT`) require white-box invariant framing (Section 4) and `GLM-5.3` (non-flash) requires dual-model orchestration or context-warming (Section 3A) to avoid cold-start refusals.

### B. CyberGym (`arXiv:2506.02548`), `ExploitGym` (May 2026) & Project Glasswing (May–Oct 2026)
- **Sources:** UC Berkeley CyberGym ([arXiv:2506.02548](https://arxiv.org/abs/2506.02548), 1,507 real-world vulnerabilities across 188 OSS C/C++ projects); Anthropic [*"Evaluating exploit generation (`ExploitGym`)"* (May 2026)](https://www.anthropic.com/research/exploit-evals); Anthropic [*"Project Glasswing initial update"*](https://www.anthropic.com/research/glasswing-initial-update) & [*"Launching an opt-in vulnerability-finding service"* (Oct 8, 2026)](https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source); [Z.ai GLM-5.3 technical report (2026-08-14)](https://z.ai/blog/glm-5.3).
- **Measured Results:**
  - Early 2025 single-pass agents achieved **11.9% (`pass@1`, <20%)** on reproducing real `CyberGym` crashes and discovered **15 previously unknown zero-days** + **26 incomplete patches** when combined with fuzzing.
  - By mid-to-late 2026, iterative agent harnesses pushed `CyberGym` vulnerability reproduction to **>85%** (**85.6%** on `GPT-5.5`, **84.5%** on stock open-weight `GLM-5.3`, **83.3%** on `DeepSeek V4`).
  - On **`ExploitGym`** (Anthropic, May 2026: turning real vulnerabilities into full end-to-end exploits), `Claude Mythos Preview` produced **157 / 898** full exploits and `GPT-5.5` (via Codex CLI) produced **120 / 898** (with later 2-hour 869-task runs reaching **216** on `GPT-5.6 Sol` and **181** on `Mythos 5` vs. **105** on `GLM-5.3`).
  - Across **1,000+ open-source repositories** in Project Glasswing, `Claude Mythos Preview` achieved a **90.6% true-positive rate** (**1,587 / 1,752** independently audited findings) and an **88% CVD-grade rate** (**85 / 97** CVD-bar, 11 duplicates, 1 false positive; **72 / 74** valid in `wolfSSL`).

### C. Pipeline Orchestration Beats Raw Model Checkpoint (`NebuSec`, `BountyBench` & `Context Studios`, 2025–2026)
- **Sources:** NebuSec Benchmark ([2026-09-01](https://nebusec.ai/research/nebu-benchmark/)); Context Studios ([July–September 2026](https://www.contextstudios.ai/comparisons/codex-security-vs-claude-code-security-review)); OpenAI [*"Expanding Daybreak"* (August 2026)](https://openai.com/index/expanding-daybreak-as-the-cyber-defense-window-narrows/); Stanford BountyBench ([arXiv:2505.15216](https://arxiv.org/abs/2505.15216), NeurIPS 2025).
- **Measured Results:**
  - **NebuSec Benchmark (76 real ground-truth bugs, same `GPT-5.4` model):** `Codex Security (Standard)` detected **24%**, `Codex Security (Deep)` detected **43%**, and changing only the multi-agent orchestration pipeline (`Nebu`) detected **80%** (**88%** at max compute). Removing `Claude Security`'s internal 45-report output truncation jumped coverage from **42% to 74%**.
  - **BountyBench (40 real bug-bounty vulnerabilities across 25 systems):** Open-ended `Detect` succeeded only **12.5%**, whereas scoped `Exploit` (given a concrete target locus/hypothesis) jumped to **67.5%** ($5.4\times$ higher), and **90.0%** on `Patch`.
- **Engineering Takeaway:** Never run an agent in open-ended "Detect" mode. Always run **Step 0 ([`surface-and-sink-mapping.md`](surface-and-sink-mapping.md))** first, decompose into single-outcome micro-agents with a Two-Pass Cross-Model Judge Gauntlet ([`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md)), and emit `coverage.json` so unaudited routes are never hidden.

### D. Empirical Cost of Abliterating Model Weights (2026 Studies)
1. **Young (January 2026, [`arXiv:2512.13655v2`](https://arxiv.org/abs/2512.13655)) — *Comparative Empirical Study of Abliteration Across 16 Models (`0.6B` to `30B+`)*:**
   - Evaluated `MMLU`, `GSM8K`, and `HumanEval` before and after standard single-direction refusal ablation vs. multi-direction optimization (`Heretic`).
   - **Mathematical & formal reasoning (`GSM8K`) suffered the steepest degradation**, dropping up to **-18.81 percentage points (-26.5% relative)** (e.g., `Llama-3.1-8B` dropped from `85.14%` to `66.33%`; `Qwen3-4B` dropped `-4.47 pp`).
2. **Layer-Sensitivity & Agentic Derailment Eval ([`sipratt-p/refusal-ablation-eval`](https://github.com/sipratt-p/refusal-ablation-eval), 2026):**
   - Naive abliteration that modifies `embed_tokens` alongside attention/MLP layers dropped hard programming scores from **489/500 to 400/500** (`-18%`), collapsing recursive-descent parser synthesis from **98/100 to 13/100**.
   - On a 12-task agentic benchmark (`DeepSeek-V4-Flash`), a community-abliterated checkpoint **completely derailed on 3 of 12 tasks (25%)**, emitting repetitive token garbage on multi-file debugging tasks where the stock model scored **0 derailments**.
3. **Truthfulness Degradation ([`chris544460/abliteration-experiments`](https://github.com/chris544460/abliteration-experiments), 2026):**
   - On `Qwen3.5-27B`, removing refusal vectors reduced `TruthfulQA` by **-5.75% to -6.87%**, increasing confident hallucinations—the exact opposite of what you want when auditing code.
4. **Operational & Data-Privacy Risks of Hosted "Uncensored" APIs:**
   - As documented in community audits of hosted abliterated APIs (August–October 2026), anonymous "zero-retention uncensored cyber APIs" expose proprietary source code to unverified operators, publish base-model benchmarks without re-measuring post-abliteration degradation, and still run hidden server-side classifiers.

---

## 3. Which Models to Use for Each Defensive Task & Dual-Model Orchestration (`GLM-5.3` + `DeepSeek V4.1 Flash 1017`)

| Task in This Playbook | Recommended Primary Models | Why |
|-----------------------|----------------------------|-----|
| **Deep Architecture Audit, State-Machine Synthesis (`fast-check`/`proptest`) & Kani Proofs** | Stock Frontier Reasoning Models (`Claude Opus/Sonnet`, `GPT-5.6/6`, `Grok 4.7`) | Highest formal reasoning and multi-file code understanding; **0% refusal** when prompted to write `proptest`/`fast-check`/`Kani` harnesses or audit source code against ASVS `v5.0.0`. |
| **High-Volume Per-Route Micro-Agent Red Teaming (`Step 3` Canary Loop)** | Stock `GLM-5.3` (non-flash) + Stock `DeepSeek V4.1 Flash 1017` Dual-Model Combo (or Frontier models with white-box framing) | Combines `GLM-5.3` (non-flash) lateral exploit creativity with `DeepSeek V4.1 Flash 1017`'s speed, low cost ($0.42/task, 99% cache hits), and 0% refusal profile—without weight-ablation reasoning loss. |
| **Cross-Model Judge 2 & Patch Regression Hunting (`regression-hunt`)** | Different model family from the Finder/Patcher (e.g., `Claude` judging `DeepSeek`/`GLM` or `GPT/Codex`) | Breaks shared model family blind spots; enforces the Four-Arm Proof and cuts regression false positives by 25%. |

### A. Operational Pattern: The `GLM-5.3 (non-flash)` + `DeepSeek V4.1 Flash 1017` Dual-Model Pairing
- **Sources:** Field architecture documented by [@bedros_p (2026-10-23)](https://x.com/bedros_p/status/2113641853874483203) ([ inverted topology](https://x.com/bedros_p/status/2113642797265772672), [lead-closer rule](https://x.com/bedros_p/status/2113683139302408369), [cold-start refusal mechanism](https://x.com/bedros_p/status/2113686579357303093)) and reproduced by [@cheatyyyy (2026-10-23)](https://x.com/cheatyyyy/status/2113657749943001521) inside [`omp` (`can1357/oh-my-pi`)](https://github.com/can1357/oh-my-pi) and `OpenCode`.
- **Why these two stock models complement each other:**
  1. **`DeepSeek V4.1 Flash 1017` (`0%` refusals, `76%` on `CyberGym-E2E-AA`, `$0.42/task`)** is methodical, fast (`40–100 tok/s` across 4–20 concurrent subagents), loops far less than earlier checkpoints, and never triggers cold-start safety refusals during attack-surface recon or PoC scripting. However, as a Flash model, it can miss non-obvious lateral pivots or complex multi-bug chains.
  2. **`GLM-5.3` (non-flash, `high` reasoning — *not* `GLM-5.3-Flash`)** has substantially stronger lateral creativity for non-obvious vulnerability angles and exploit chains than `GLM-5.3-Flash` or `DeepSeek V4.1 Flash` alone, but has two drawbacks if used solo: **(a) higher token cost (~$2.50/task)** and **(b) a surface-level turn-1 refusal** because when cold-started on a raw target, `GLM-5.3` immediately attempts aggressive offensive escalation in turn 1 and trips its own surface refusal filter.
  3. **Why pairing them eliminates `GLM-5.3`'s refusal on stock weights:** When `DeepSeek V4.1 Flash 1017` maps the attack surface first (populating structured `.md`/`.tsv` workspace notes) or executes subagent tasks while `GLM-5.3` operates on established technical context, `GLM-5.3`'s turn-1 surface refusal is never triggered.
- **Two Proven Multi-Agent Topologies (in `omp` / `oh-my-pi` or `OpenCode`):**
  - **Topology 1 — `GLM-5.3 (high)` Orchestrator + `DeepSeek V4.1 Flash 1017` Subagents:**
    - Configure `GLM-5.3` (non-flash, `high` effort) as the main orchestrator agent and `DeepSeek V4.1 Flash 1017` (e.g., via Fireworks AI or official API) as the worker subagent model (`Low` reasoning for recon/scouting, `High` reasoning for PoC verification).
    - In `omp` (`can1357/oh-my-pi`), a 4-subagent run over **369K tokens** with **99% prompt-cache hits** runs at **~39.3 tok/s** and costs **$0.39 total**. Instruct subagents to coordinate over `omp`'s built-in IRC channel (`hub`) so workers broadcast discovered sinks/primitives instead of working in isolated silos.
  - **Topology 2 — Inverted "Wall-Breaker / Lead-Closer" Escalation (`DeepSeek` Lead + On-Demand `GLM-5.3` Subagent):**
    - Run `DeepSeek V4.1 Flash 1017` as both the orchestrator and primary subagents (`Low` for recon, `High` for PoCs), and instruct subagents to **spawn a `GLM-5.3` (non-flash) reviewer subagent at two mandatory checkpoints**:
      1. **Before closing any lead ("Wall-Breaker"):** Whenever a `DeepSeek` subagent hits a wall or is about to mark a lead closed (with or without findings), spawn `GLM-5.3` to review the accumulated `.md`/`.tsv` evidence and either propose new angles/pivots or confirm the lead is exhausted.
      2. **Upon confirming a bug ("Chain Escalator"):** Spawn `GLM-5.3` on any confirmed PoC to identify higher-impact primitives or multi-bug chains.
    - Each on-demand `GLM-5.3` review costs **~$0.03–$0.10** while capturing nearly all of solo `GLM-5.3`'s lateral insight. When a long-running sweep hits diminishing returns, **swap the orchestrator and subagent roles** between `GLM-5.3` and `DeepSeek V4.1 Flash 1017` to break tunnel vision.
- **Recursive Harness Optimization (`google-research/harness2`, October 2026):**
  - Rather than hand-tuning prompt rules when subagents suffer tunnel vision or duplicate discovery across large note trees, Google Research's open-source [**Harness² (`google-research/harness2`, `arXiv:2610.14224`)**](https://github.com/google-research/harness2) applies **Propose–Probe–Compose** task-level and harnessing-level recursion to optimize an `OpenCode` or `Codex` harness's prompts, skills, memory layout, and cross-agent coordination without ground-truth labels (improving `GLM-5` and `Gemini 3.5 Flash` by up to **+11.5 points on WorkBuddy-Bench** and **+11.8 pp on LAB**). Always run `harness2` inside an OS sandbox (`Firejail` / container), as it has no built-in sandboxing.

### B. Parametrize Models by **Role**, Not by Brand (Environment / Skill Variables)

The dual-model pairing in Section 3A is one instance of a more general pattern. Brand names (and their leaderboard positions) rotate monthly; **roles** do not. Wire your harness and skills to three role variables, pin a concrete checkpoint per role for a given run, and re-measure refusal rate and recall per role (Section 5) whenever you change a pin. The current best public picks are dated **Oct 23–24, 2026** and will drift — the role contract will not.

#### `SWEEP_MODEL` — Scout / Workhorse
Cheap, fast (`70–100+ tok/s`), `0%` refusals; carries high-volume route/oracle **residual** hunting (Step 1.5 → Step 3) and initial PoCs. Runs as the many parallel subagents.
- **`DeepSeek V4.1 Flash 1017`** (stock open-weight) — **$0.42/task**, **57%** Artificial Analysis Cyber Index (**#1 openly-available**), **85.7%** on Moonshot `xdev-bench-hard` (reported in the Kimi K3.1 Pro comparison set), **0%** safety refusals, strong agentic coding (DeepSWE ~77%). **Default Scout pick.**
- **`MiMo-V2.6-Pro`** — **$0.18/task**, **56%** Cyber Index; the cheapest viable Scout.
- **Do not reach for older `DeepSeek V4 Pro` (`deepseek-v4-pro-0813`, ~$0.66/M input) as the Scout:** `V4.1 Flash 1017` is faster, cheaper, and stronger on agentic coding; a `V4.1 Pro` tier is not released as of this writing; and running a same-family model as both Scout *and* Wall-Breaker shares blind spots (defeating the cross-family Judge rationale below).

#### `WALLBREAKER_MODEL` — Wall-Breaker / Chain Escalator
A larger, more creative model invoked **only** when the Scout hits a wall before closing a lead, or when a confirmed PoC needs deeper chaining. Interchangeable by family — pick per budget and per the kind of lead:
- **`Kimi K3.1 Pro`** (Moonshot, released **2026-10-23**; open weights by **Nov 4, 2026**) — best today for **large-repo logic and long-horizon chains**: **1M-token context**, top-ranked open-weight on **Terminal-Bench 4.0 (~65.7%)**. Moonshot deliberately **removed cyber-related data at both mid-training and RL** before the open-weight release, which dropped its internal `xdev-bench-hard` from **90.5% → 81.0%** pass@3 (still well above `GLM-5.3`'s reported 57.1% on that bench); practitioner-cited `ExploitBench` **74.7%** vs `GLM-5.3` **54.4%**, and a far lower hallucination-bench score (**5.4** vs `GLM-5.3` **14.8**). Use it for architecture/logic reasoning rather than raw offensive payloads. Cite: [Kimi K3.1 Pro blog](https://www.kimi.ai/blog/kimi-k3-1-pro), [@ArtificialAnlys](https://x.com/ArtificialAnlys/status/2113688083145314416), [@_gaurav_pathak_](https://x.com/_gaurav_pathak_/status/2113724482636366322), [@cheatyyyy](https://x.com/cheatyyyy/status/2113683629713027473).
- **`Grok 4.7 (xhigh)`** — **56%** Cyber Index, low refusal, strong general reasoning. Expensive as a Scout, fine as an on-demand Wall-Breaker.
- **`GLM-5.3` (non-flash — *not* `GLM-5.3-Flash`)** — Zhipu did **not** strip offensive post-training, so it stays more daring on memory-corruption / RCE chains than cyber-cut open weights; its only obstacle is the **turn-1 cold-start refusal** that the Scout's workspace warmup bypasses (mechanism and field reports in Section 3A and the cited `@bedros_p` / `@cheatyyyy` threads).
- **`Claude Sonnet 5.5` / `GPT-6 Astra`** — best when the "wall" is **patch design, regression-hunt, or business-logic audit**; a defensive white-box framing (Section 4) avoids the Opus-style `[cyber]` session pause.

**Optional dual Wall-Breaker:** nothing forces a single family. Running two — e.g. **`Kimi K3.1 Pro`** for architecture/logic chains **+** **`GLM-5.3`** (or **`Grok 4.7`**) for offensive payload construction — covers both the "what's the chain?" and the "can we actually land it?" failure modes, at the cost of a second on-demand endpoint.

#### `JUDGE_MODEL` — Cross-Model Falsification Gate
Must be a **different model family** from whatever found/patched the bug (the Two-Pass Cross-Model Judge Gauntlet in [`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md) §2 and the Four-Arm Proof in [`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md)). If `DeepSeek`/`GLM` found it, judge with `Claude`/`GPT`, and vice versa. This is exactly why the Scout and Wall-Breaker should not both be the same family.

#### Accessing the Roles Without N Vendor Accounts
You do **not** need a separate account per brand. A single **OpenRouter** or **Fireworks AI** API key behind an **OpenAI-compatible SDK** exposes all of the above as `provider/model` strings, so the three role variables resolve to one client with per-agent model overrides (as `omp` / `oh-my-pi` and `OpenCode` already do). When any role will see **proprietary source**, require an endpoint offering **Zero Data Retention (ZDR)** and read its retention/training terms first (Section 6); Kimi, for example, documents ZDR for API customers.

#### Topology Mapping (Section 3A, Restated by Role)
- **Topology 1 — `WALLBREAKER_MODEL` as orchestrator + `SWEEP_MODEL` as subagents.** The large model plans and the cheap fast fleet executes recon (`Low`) and PoCs (`High`). This is the `omp` screenshot setup with `GLM-5.3 (high)` orchestrating `DeepSeek V4.1 Flash 1017` workers.
- **Topology 2 (recommended daily driver) — `SWEEP_MODEL` orchestrator + on-demand `WALLBREAKER_MODEL`.** The Scout runs the sweep and spawns the Wall-Breaker only **at lead-close** (find new pivots or confirm exhaustion) and **at bug-confirm** (chain impact), at ~$0.03–$0.10 per review.
- **Role-swap when sweeps stagnate.** On diminishing returns, swap which family holds `SWEEP_MODEL` vs `WALLBREAKER_MODEL` to break tunnel vision (Section 3A).

---

## 4. Refusal-Free White-Box Framing Patterns (How to Get 0% Refusals on Every Model)

Safety classifiers on frontier models trigger on **intent ambiguity and external target appearance** (e.g., *"Pentest `https://prod-company.com` and dump the `users` table"*). In reported practice they do not trigger when the prompt establishes the following (measure this for your own pipeline: Section 5):
1. **Localhost / Ephemeral Test Target (`http://127.0.0.1:${PORT}` or in-memory test store).**
2. **Explicit Invariant Verification Objective (`I1`–`I5` or `OWASP ASVS v5.0.0-X.Y.Z`).**
3. **Synthetic Canary Oracle (`flag{CANARY_UUID}` seeded by the test runner).**

### Comparison: Refusal-Prone Prompt vs. Zero-Refusal White-Box Prompt

| ❌ Refusal-Prone "Black-Box Hacker" Framing | ✅ Zero-Refusal "White-Box Invariant & Canary" Framing |
|---------------------------------------------|--------------------------------------------------------|
| *"Act as an elite black-hat attacker. Break into this web server, bypass authentication, and steal another customer's private files."* | *"Run an integration security test for Invariant `I2` (Strict Tenancy Isolation, ASVS `v5.0.0-8.2.2`) against the local test server at `http://127.0.0.1:4100`. Verify whether `test_user_b`'s session can read the synthetic test fixture `flag{CANARY_...}` owned by `test_user_a` in `src/routes/issues.ts`, and output a regression test if the `404` boundary fails."* |
| *"Write an exploit to DoS and drain the wallet balance on `/api/spend`."* | *"Write a barrier-synchronized concurrency test (`race-harness.mjs`) against `http://127.0.0.1:4100/api/spend` to verify Invariant `I3` (Conservation of Balance): when `test_user_b` has `balance = 10` and sends 25 parallel requests of `cost = 10`, assert whether `final_balance >= 0` holds or if a TOCTOU race occurs."* |

---

## 5. Measure the Refusal Rate; Do Not Assume It

The "0% refusals" figures quoted above (Artificial Analysis Cyber Index, practitioner reports, the framing patterns in Section 4) are externally reported or practitioner-observed numbers for *their* prompts, tasks and checkpoints. They do not transfer automatically to your harness, your prompts or next month's model version. Treat refusal behavior as a **measured property of your pipeline**:

| Metric | Definition | Where measured |
|--------|-----------|----------------|
| **Refusal rate** | Fraction of agent runs (per model, per hypothesis class) that end in a safety refusal, a "session paused" block, or a non-actionable policy message instead of an attempt | Eval suite runs in `evals/` (Phase 2); per-run transcript classifier |
| **Cold-start refusal rate** | Refusals on turn 1 versus after the workspace holds mapped context (the `GLM-5.3` cold-start effect in Section 3A) | Same, split by turn index |
| **Refusal-adjusted recall** | Planted-bug recall counting a refused run as a miss | Same |
| **Framing sensitivity** | Refusal-rate delta between the black-box and white-box framings in Section 4 | A/B per model |

Log the model name, version/date and framing used with every run, and re-measure when a model checkpoint changes. A model that refuses 36% of the time is not a free replacement for one that refuses 0%, however good its raw score; conversely, a high refusal rate under white-box framing on a localhost canary lab is itself a finding about the model, not a license to switch to abliterated weights (Section 2D).

---

## 6. Data-Handling Rule for Sending Proprietary Source to Third-Party Model APIs

Auditing a private repository with a hosted model discloses that source code (and lab traffic, schema, and configuration) to the API operator. Cheap hosted endpoints and anonymous "zero-retention" cyber APIs (Section 2D, item 4) make this easy to do carelessly. Before pointing any hosted model at a repository:

1. **Classify the repository** (public OSS / internal / customer-data-adjacent / regulated). Only the first two may go to a third-party API without written approval.
2. **Use an operator with contractual terms** you have read: retention period, training use, sub-processors, region, and incident notification. Prefer self-hosted stock open-weight models (Section 3) for regulated code.
3. **Never send secrets.** The auditor sandbox mounts no host secrets ([`isolated-lab-and-canary-setup.md`](isolated-lab-and-canary-setup.md), Auditor Sandboxing), and the harness redacts keys and tokens from prompts and tool results before any model call (the redaction patterns in [`../1-known-vulnerabilities/infra-and-supply-chain/dependency-and-ci-supply-chain.md`](../1-known-vulnerabilities/infra-and-supply-chain/dependency-and-ci-supply-chain.md)).
4. **Send the minimum:** the stable prefix and the handler span, not the whole repository; never production data—lab data only.
5. **Record it:** the model operator, endpoint, date, and tree hash go into `scan-manifest.json`.
6. **Treat model output as untrusted input**: findings are accepted only from the harness oracle ([`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md)), and the auditor itself is a prompt-injection target ([`../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/agentic-and-mcp-threats.md)).
