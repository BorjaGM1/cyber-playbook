# Step 3: Autonomous Micro-Agent Red Teaming (`XBOW`, `/goal`, `Nebu` & `Big Sleep` Patterns)

## 1. Mental Model (Why Pipeline Architecture Beats Raw Model Size by $3.3\times$)

If you spin up a single coding agent, hand it a 50,000-line codebase, and prompt it: *"Act as a red teamer and find all security vulnerabilities in this application"*, three failure modes occur almost immediately:
1. **Context Pollution & Shallow Skimming:** After reading 6 files and running 3 `curl` commands that return `401` or `404`, the agent concludes *"authorization appears properly enforced"* and stops—missing the subtle IDOR in the batch-update route or the purpose-confusion bug in the MFA cookie.
2. **Rationalized Coverage Shortcuts:** When Trail of Bits audited agent transcripts during *Patch the Planet* ([July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)), they found that agents instructed to "audit 100% of the repo" routinely skipped complex modules and rationalized in their final summary that those directories were "out of scope."
3. **Unverified Hallucinations ("CVE Slop"):** To look helpful, a monolithic agent writes a 10-item markdown report flagging theoretical issues that cannot actually be exploited because of upstream middleware or schema constraints it never tested.

### Empirical Proof: Pipeline Orchestration > Model Generation (2025–2026)

Controlled benchmarks in 2026 proved that **how you decompose, orchestrate, and gate your security agents matters far more than which frontier model checkpoint you call**:
- **NebuSec Benchmark ([September 1, 2026](https://nebusec.ai/research/nebu-benchmark/)) & Context Studios Evaluation ([July–September 2026](https://www.contextstudios.ai/comparisons/codex-security-vs-claude-code-security-review)):** Tested against **76 real ground-truth vulnerabilities** in production codebases using the **exact same underlying model (`GPT-5.4`)**:
  - `OpenAI Codex Security (Standard scan)`: **24% detection**.
  - `OpenAI Codex Security (Deep mode)`: **43% detection**.
  - `Nebu` (multi-agent hypothesis decomposition + iterative tool orchestration using the **same `GPT-5.4` model**): **80% detection** (and **88%** at maximum compute—a **$3.3\times$ improvement** from pipeline architecture alone).
  - Similarly, in `Claude Security` (`Opus 5`), simply removing an internal orchestration cap that truncated output at the first 45 candidate findings increased real vulnerability coverage from **42% to 74%**.
- **XBOW & DARPA AIxCC CRS Systems ([arXiv:2603.08566](https://arxiv.org/abs/2603.08566)):** XBOW reached #1 on the US HackerOne leaderboard (1,060+ validated vulnerabilities across 137 benchmarks in ~4 hours per target) by decomposing every target into narrow `(EntryPoint, Invariant)` micro-agents gated by deterministic Proof-of-Vulnerability (`PoV`) validators.
- **Google Project Zero & DeepMind — *Project Naptime* & *Big Sleep* (2024–2025):** Replaced monolithic code-reading prompts with four specialized agent tools—a **Code Browser** (to navigate call graphs without flooding context), a **sandboxed Python interpreter** (so the agent computes buffer offsets and crafts inputs in code rather than doing mental math), a **Debugger / ASan oracle** (inspecting live crash state and registers), and a **Reporter gate**. This architecture found a pre-release stack buffer underflow in `SQLite` (Oct 2024) and pre-empted the in-the-wild `SQLite` integer truncation vulnerability **`CVE-2025-6965`** (Summer 2025).

---

## 2. The 3 Rules of `/goal` from Trail of Bits & OpenAI (*Patch the Planet*, July 2026)

In July 2026, Trail of Bits and OpenAI published field reports from **Patch the Planet** ([Part 1, July 2, 2026](https://blog.trailofbits.com/2026/07/02/field-reports-from-patch-the-planet/); [Part 2: How We Use `/goal`, July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)), detailing how their autonomous agents audited `curl`, `zlib`, `rust-lang/rust`, and `Keycloak`. Every multi-agent security run should enforce their three operational rules:

### Rule 1: Generate `THREAT_MODEL.md`, Let the Agent Self-Red-Team Its Goal Prompt, and Track Real Reads with `agentcov`
1. **Build `THREAT_MODEL.md` First:** Before searching for bugs, generate a concise threat model defining the repository's trust boundaries, attacker-controlled inputs, privileged actors, and explicit non-goals (so agents do not waste tokens reporting "bugs" that require an attacker to already have root or modify local config files).
2. **Have the Agent Write and Red-Team Its Own `/goal` Prompt:** Ask the agent to draft its hunting prompt from `THREAT_MODEL.md`, then immediately ask a second prompt: *"Red-team this goal specification: how could a lazy agent satisfy the letter of this prompt while skipping the hardest code paths?"* Close every loophole before starting the run.
3. **Measure Objective File/Line Coverage (`agentcov` + `coverage.json`):** Never trust an agent's self-reported claim that it "reviewed all routes." Following Trail of Bits' **`agentcov`** (which parses agent tool transcripts to compute exact line-read coverage) and OpenAI `Codex Security`'s **`coverage.json` / `scan-manifest.json`** artifact, record every file and line range actually opened by a micro-agent and explicitly list **unaudited files and routes** in `coverage.json`.

### Rule 2: Define the Outcome (Not the Path) and Calibrate Variant-Search Width to One Sentence
1. **Treat `"No Bugs Found"` as an Intermediate State:** If a static code-reading pass returns 0 findings, the coordinator must treat that as an intermediate signal to switch strategies (e.g., spinning up a differential oracle, a concurrency burst, or a custom fuzz harness as `/goal` did on `zlib`), not as proof that the code is secure.
2. **The One-Sentence Rule for Variant Analysis (`rust-lang/rust` & `Keycloak`):**
   - When Trail of Bits gave `/goal` the **exact stack trace and function names** of a historical Rust standard-library CVE (`CVE-2022-21658`, TOCTOU race in `std::fs::remove_dir_all`) and asked for variants, the agent anchored too narrowly and found **0 bugs**.
   - When they abstracted the historical CVE into a **single sentence describing the underlying risk class** (*"Find race conditions, logic bugs, or input handling flaws in the Rust standard library and compiler that violate memory safety or soundness guarantees"*), the agent discovered **9 real bugs in `rust-lang/rust`**—including a **compiler soundness hole patched in Rust 1.98**—and **2 SAML privilege-escalation vulnerabilities in `Keycloak`** (abstracted from `CVE-2024-10492`).
   - **Takeaway:** When hunting variants of a past bug or a Part 1 case note, pass the micro-agent a **one-sentence description of the invariant violation class**, never a brittle regex tied to yesterday's variable names.

### Rule 3: Strictly One Outcome Per Agent + Two-Pass Cross-Model Judge Gauntlet
1. **Never Mix Competing Objectives in One Agent:** If you instruct one agent to *"achieve 80% code coverage AND find critical vulnerabilities,"* it will optimize the easier metric (skimming files to bump coverage) and find nothing.
2. **The `1 Mapper -> 5 Surface Agents + 1 Roamer` Topology:**
   - **1 Discovery Mapper Agent** reads `SECURITY_SURFACE_MAP` + `THREAT_MODEL.md` and selects the top $K$ (e.g., 5) highest-risk attack surfaces or `(Route, Invariant)` clusters.
   - **$K$ Dedicated Single-Outcome Micro-Agents** each attack exactly one surface/hypothesis to completion.
   - **1 Unconstrained "Roamer" Agent** is given freedom to follow weird cross-cutting leads (e.g., shared utility helpers, serializer quirks, or cross-module state) that fall between surface boundaries.
3. **Two-Pass Cross-Model False-Positive Gauntlet:** Every candidate bug must survive two sequential judge agents before surfacing:
   - **Judge 1 (Threat-Model & Severity Gate):** Verifies that the candidate crosses a real trust boundary defined in `THREAT_MODEL.md` and does not rely on impossible preconditions.
   - **Judge 2 (Cross-Model PoV & Falsification Gate):** Runs on a **different model family** than the finder agent (e.g., if `GPT/Codex` or `DeepSeek` found the bug, `Claude` acts as Judge 2, or vice versa) so shared model blind spots cannot rubber-stamp a hallucination. Judge 2 actively tries to **disprove** the finding and requires a deterministic PoV execution (`validate-pov.mjs` exit `0`).

---

## 3. Micro-Agent Coordinator, Coverage Ledger & Validator Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. SURFACE MAPPER (Step 0) + THREAT_MODEL.md + CANARY LAB (Step 1)      │
│    Produces: Routes [R1..Rn], Sessions [UserB, GuestG, Anon],           │
│              Target UUIDs [ID_A], Canary Hashes [SHA256(flag_1..k)]     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ 1 Mapper selects Top Surfaces + 1 Roamer
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│ Micro-Agent #1..N   │   │ Micro-Agent #K      │   │ Roamer Agent #R     │
│ Single Outcome:     │   │ Single Outcome:     │   │ Follows cross-module│
│ Route X × Invar I2  │   │ Route Y × Invar I4  │   │ state & 1-sentence  │
│ Budget: 12 steps    │   │ Budget: 12 steps    │   │ variant risk class  │
└─────────┬───────────┘   └─────────┬───────────┘   └─────────┬───────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. AGENTCOV & COVERAGE MANIFEST (`coverage.json` + `scan-manifest.json`)│
│    Logs exact `file:startLine-endLine` spans read by tool calls and     │
│    explicitly flags unaudited routes/files (0 findings != 100% audited) │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. TWO-PASS CROSS-MODEL JUDGE + DETERMINISTIC PoV GATE                  │
│    - Pass 1 (Judge 1): Violates `THREAT_MODEL.md` trust boundary?       │
│    - Pass 2 (Judge 2, Different Model Family + `validate-pov.mjs`):     │
│      * Did clean subshell stdout match `SHA-256(flag{...})`?            │
│      * Did `ssrfCanaryServer.hits.length` increase?                     │
│      * Did Victim `Tenant A` state snapshot hash change illegally?      │
│      * Did a conservation invariant (`balance < 0`) or ASan crash fire? │
│    ONLY IF BOTH PASS -> Promote to Verified Vulnerability + 3-Arm Patch │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Generating the Hypothesis Queue

For every entry point in `SECURITY_SURFACE_MAP`, generate targeted single-outcome hypotheses from this matrix:

| Hypothesis Class | Target Routes | One-Sentence Risk Class & Specific Question Given to the Micro-Agent |
|------------------|---------------|----------------------------------------------------------------------|
| **`H-I1-Spoof`** | Auth middlewares, OIDC callbacks, JWT/Edge verifiers | *"Can an unauthenticated caller or `PendingAuth` cookie holder forge headers/tokens (`Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, `alg:none`, cross-cookie substitution) to obtain a `200` on `Route X`?"* |
| **`H-I2-CrossTenant`** | Every `GET`/`POST`/`PUT`/`PATCH`/`DELETE` taking an ID or FK | *"Using `User B`'s session (`Tenant B`), can you pass `Tenant A`'s resource UUID (`ID_A`) as a path param, query param, or foreign-key body field (`projectId`, `parentId`, `attachmentId`) on `Route X` to extract `CANARY_TENANT_A` or mutate `Tenant A`'s row?"* |
| **`H-I2-GuestEscape`** | Search, History, Exports, Attachments, Issue Move, Team/Member lists | *"Using `Guest G`'s session (authorized ONLY for `Project Public` in `Tenant A`), can you extract `CANARY_SECRET_PROJECT` or `CANARY_ATTACHMENT_BLOB` from `Project Secret` via `Route X`?"* |
| **`H-I3-RaceAndSkip`** | Credits, Coupons, Quotas, Checkout, Invites, Webhooks | *"Using `User B`'s session (seeded with balance = 1 unit), can a 25-request barrier burst or out-of-order state transition on `Route X` commit $\ge 2$ units or skip payment verification?"* |
| **`H-I4-Boundary`** | URL fetchers, File uploads, Dynamic SQL sorts, PTY paste, MCP tools | *"Can `User B` trigger a connection to the local SSRF listener `127.0.0.1:${ssrfPort}`, upload an active HTML/SVG/path-traversal payload, or break SQL/PTY syntax on `Route X`?"* |

---

## 5. Exact Micro-Agent Prompt Template (White-Box + Canary Oracle)

Use this exact prompt structure when spawning a micro-agent so it stays laser-focused on a single outcome, uses a Python/Node script sandbox instead of mental math, and never triggers safety refusals:

```text
You are running an isolated white-box invariant verification test on a local development server at http://127.0.0.1:4100.

### SINGLE TARGET OUTCOME
- Route under test: {METHOD} {ROUTE_PATH}
- Handler source file: {SOURCE_FILE_PATH}:{START_LINE}-{END_LINE}
- Threat Model Boundary: {THREAT_MODEL_TRUST_ZONE}
- Invariant & Risk Class (1 Sentence): {INVARIANT_ID} — {ONE_SENTENCE_RISK_CLASS}

### PROVIDED LAB CREDENTIALS & TARGET IDENTIFIERS
- Victim Resource IDs in Tenant A (Protected): {JSON_VICTIM_UUIDS}
- Attacker Session (Tenant B Owner): Cookie / Bearer = {ATTACKER_B_CREDENTIAL}
- Restricted Guest Session (Tenant A, authorized ONLY for Project {PUBLIC_PROJECT_ID}, forbidden from Project {SECRET_PROJECT_ID}): {GUEST_G_CREDENTIAL}
- Internal SSRF Canary Listener URL: {SSRF_LISTENER_URL}
- Target Canary SHA-256 Hashes (plaintext flags are hidden inside Victim's resources):
  {JSON_CANARY_SHA256_MAP}

### YOUR PROTOCOL (MAX 12 STEPS)
1. Read `{SOURCE_FILE_PATH}` and any repository/helper functions it calls. Trace every input parameter (path, query, headers, JSON body fields, foreign keys) from request parsing down to the database query or sink.
2. Identify whether any code path omits a `tenant_id` check, omits a `ProjectGuest` project-membership check, trusts a client-supplied foreign key (`projectId`, `issueId`, `attachmentId`), allows mass assignment, or fetches an unvalidated URL.
3. Write a standalone reproduction script `/tmp/repro_{HYPOTHESIS_ID}.mjs` that sends the crafted HTTP request(s) to `http://127.0.0.1:4100` and prints any extracted data or post-request state check.
4. Run the deterministic validator: `node scripts/validate-pov.mjs /tmp/repro_{HYPOTHESIS_ID}.mjs`.
5. Return ONLY:
   - `VERIFIED_VULNERABILITY` (if and only if `validate-pov.mjs` exits 0 with a matched canary SHA-256, SSRF hit, or state-integrity violation, along with the exact `file:line` root cause and minimal patch), OR
   - `INVARIANT_HELD` (listing the exact `file:line` spans read for `coverage.json` and the negative test cases executed).
```

---

## 6. Emitting `coverage.json` (Never Equate "0 Findings" with "100% Audited")

At the end of every micro-agent sweep, the coordinator aggregates `agentcov` read logs against `SECURITY_SURFACE_MAP` and writes `coverage.json`:

```json
{
  "scanTimestamp": "2026-10-23T21:00:00Z",
  "routesTotal": 42,
  "routesAuditedWithDynamicProbes": 39,
  "routesUnaudited": [
    {
      "route": "POST /api/webhooks/legacy-import",
      "file": "src/routes/legacy-import.ts:1-140",
      "reason": "Micro-agent #38 hit 12-step budget before executing validate-pov.mjs"
    }
  ],
  "filesReadCoveragePct": 92.8,
  "verifiedVulnerabilities": 0
}
```

Any route listed in `routesUnaudited` automatically fails CI coverage gates or is re-queued with a fresh context window until `routesUnaudited.length === 0`.
