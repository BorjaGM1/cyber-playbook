# Step 0.5: Attack Surface Reduction (ASR) & Config-Interaction Auditing

## 1. Mental Model (Reducing the Severity of Unknown Bugs You Haven't Found Yet)

Finding individual vulnerabilities one by one scales poorly: fixing bug #1 tells you nothing about how many unknown bugs remain in the same codebase. **Attack Surface Reduction (ASR)** attacks the problem from the opposite side: instead of trying to spot every bug inside complex code, you **move complex code behind hard security gates** so an unauthenticated or untrusted caller can never reach it in the first place.

As demonstrated by Anthropic's Frontier Red Team study (*["Using Claude to reduce the attack surface of code"](https://www.anthropic.com/research/attack-surface-reduction)*, Chris Rohlf, October 20, 2026):
- Every line of code reachable **pre-authentication**, **0-click**, **in the default configuration**, or **in the first message of a protocol** turns any memory/logic bug inside that code into a critical unauthenticated exploit.
- Moving that same code behind a hard gate (`pre-auth` $\to$ `post-auth`, `on-by-default` $\to$ `opt-in`, `parse-before-allowlist` $\to$ `allowlist-before-parse`) immediately eliminates or downgrades the severity of **every unknown vulnerability** inside that code path simultaneously.

---

## 2. Empirical Results: What the 3-Pass ASR Method Finds in Production Code (Oct 2026)

When Anthropic ran a structured 3-pass Attack Surface Reduction workflow across **25 open-source projects** (`>5 million LOC`, `17,000+` total configuration options, `3,842` security-relevant options), it uncovered **493 actionable attack-surface issues**:

1. **Across the 11 Gated (Authentication-Boundary) Projects:**
   - **93 unnecessary pre-auth surfaces** exposed in the default configuration.
   - **37 places where complex code executed or state was recorded before authentication completed.**
   - **61 configuration combinations that silently weakened a pre-authentication control.**
2. **Across All 25 Projects (Configuration Interaction Bugs):**
   - **162 dangerous configuration interactions** accepted with **zero warning or boot error**:
     - **94 combinations silently disabled an active security control.**
     - **68 combinations caused dangerous runtime inconsistencies.**
   - *Classic recurring fail-open pattern (found independently in 4 unrelated projects):* An access-control list configured with hostname or wildcard deny rules (`deny = *.evil.com`) combined with `reverse_dns_lookup = false`. Because the server never resolves the client IP to a hostname and an IP string (`203.0.113.5`) never matches the string pattern `*.evil.com`, **every hostname deny rule silently fails open**.
   - *Config namespace/alias mismatch:* A shorter configuration alias accepted by the parser failed to propagate to a sub-module's TLS check, silently ignoring client-certificate requirements on specific endpoints.

### Case Study: Removing ~20% of OpenSSH's Pre-Auth Attack Surface (`OpenSSH 10.4` $\to$ `10.6`)

In `OpenSSH 10.4`, experimental post-quantum `ML-DSA-44` signature code (~4,500 lines of complex math and parsing—roughly **16%–20% of OpenSSH's entire pre-authentication surface**) was disabled by default in configuration (`PubkeyAcceptedAlgorithms`). However:
1. **Parse-Before-Check (`OpenSSH 10.4`):** During pre-auth public-key packets, `sshd` deserialized the untrusted key blob—and for SSH certificates, **cryptographically verified the embedded CA signature**—*before* checking whether the algorithm was enabled in `PubkeyAcceptedAlgorithms`. An unauthenticated attacker could force `sshd` to execute ~4,500 lines of disabled post-quantum verification code using a self-signed certificate.
2. **Header-vs-Payload Type Confusion (`OpenSSH 10.5` incomplete fix):** `OpenSSH 10.5` added an early check against the algorithm name advertised in the outer SSH packet header, but `sshkey_from_blob()` dispatched its parser using the **inner key type string embedded inside the binary key blob**. Sending an outer header of `"ssh-ed25519"` wrapping an inner `"ssh-mldsa44"` key blob bypassed the 10.5 gate completely.
3. **Hardened Fix (`OpenSSH 10.6`):** Moving the algorithm allowlist check **inside the key parser before blob deserialization and before CA signature verification**—and asserting that the outer packet algorithm matches the inner blob type—completely severed pre-authentication reachability to the disabled code.

---

## 3. The 3-Pass Fresh-Context ASR Protocol

A critical engineering lesson from Anthropic's ASR architecture is **context isolation**:
> Do **not** run all three passes in a single long agent conversation. Run **three separate passes**, where **each pass starts in a fresh, empty context window** and receives only the `SECURITY_SURFACE_MAP` (from [Step 0](surface-and-sink-mapping.md)) plus a concise handoff summary.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ PASS 1 (Fresh Context Window): Default-Configuration Reachability       │
│ Goal: Identify features/parsers/routes reachable in the default config  │
│       that are not required by core default functionality.              │
│ Action: Gate behind explicit opt-in config + verify 100% of existing    │
│         unit/E2E/black-box tests pass unchanged.                        │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PASS 2 (Fresh Context Window): Early / Pre-Gate Reachability            │
│ Goal: Find complex parsing, DB writes, crypto verification, or memory   │
│       allocation happening BEFORE hard gates (Auth, Allowlist, Quota).  │
│ Action: Hoist the gate (Auth / Algorithm Allowlist / Outer==Inner type) │
│         ahead of parsing, deserialization, and state recording.         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PASS 3 (Fresh Context Window): Configuration Interaction & Fail-Open    │
│ Goal: Enumerate pairs/tuples of config flags/env vars where Setting A   │
│       silently neuters Security Control B or causes a fail-open check.  │
│ Action: Fail closed at boot (`assertSafeBootConfig`) when conflicting   │
│         options are combined, or enforce strict security precedence.    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Detailed Execution Checklist for Each Pass

### Pass 1: Default-Configuration Reachability Audit
1. **Enumerate all entry points active when the app boots with default settings:**
   - Debug, profiling, metrics, GraphQL introspection, playground, or migration routes.
   - Optional webhook receivers, legacy API versions (`/api/v1/*`), or experimental file-format parsers (e.g., XML/SVG/archive unpackers, experimental auth providers).
2. **Check the ASR Invariant:** *If a deployment does not explicitly configure Feature $X$, can an external request still reach Feature $X$'s parser or handler?*
3. **Verify:** Place an early guard at the router/dispatcher boundary (`if (!config.enableFeatureX) return notFound()`) and verify via dynamic call tracing and the existing test suite that default behavior is 100% preserved.
4. **Breaking-change note for applications (not just libraries):** In the Anthropic study the targets were network daemons and libraries, where "default configuration" is a well-defined artifact that most deployments inherit. For a deployed web application there is no shared default: the *production configuration* is the default. Turning an on-by-default feature into opt-in changes live behavior for real users, so (a) classify every Pass 1 gate as **breaking** (a route or capability users rely on) or **non-breaking** (dead code, debug/test routes, unused parsers); (b) apply non-breaking gates immediately; (c) ship breaking gates behind an explicit deprecation/opt-in plan with traffic evidence (access logs showing the route is unused); and (d) never claim "100% of tests pass unchanged" as proof of safety—the test suite rarely covers a legacy route, which is exactly why it is attack surface. Use the runtime-vs-static route diff ([`surface-and-sink-mapping.md`](surface-and-sink-mapping.md), Section 4) to find the mounted-but-undocumented candidates first.

### Pass 2: Early / Pre-Gate Reachability Audit (The `OpenSSH 10.6` Rule)
For every route, WebSocket handler, webhook receiver, and token verifier, trace the exact chronological order of operations on untrusted input before the hard gate (`Authentication`, `TenantScope`, `HMAC Verification`, `Rate-Limit Lease`) completes:

1. **Check 1 — Deserialization / Parsing Before Authentication or Allowlist:**
   - Does the server parse a multipart file upload, decompress a `gzip`/`zip` stream, parse a huge JSON/XML body, or verify a client-supplied cryptographic key/certificate **before** verifying the caller's session/API key or checking the algorithm allowlist?
2. **Check 2 — Outer Envelope vs. Inner Payload Type Mismatch:**
   - Just like `OpenSSH 10.5` checked the outer packet's `alg` string while the parser dispatched on the inner blob's `alg` string, check whether your middleware validates a header/query parameter (`Content-Type`, `X-Event-Type`, URL `:orgId`, JWT header `kid`) while the downstream handler dispatches on a different field inside the parsed body (`body.type`, `body.orgId`, inner JWK `alg`).
3. **Check 3 — Pre-Auth State Mutation:**
   - Does an unauthenticated request insert rows into the database, allocate persistent session rows, write temporary files to disk, or evict bounded caches before authentication succeeds?

#### Vulnerable vs. Hardened Pattern (Pre-Gate Parsing & Envelope Mismatch)

```typescript
// VULNERABLE (OpenSSH 10.4 / 10.5 pattern in a Web API):
// 1. Parses and validates a heavy payload / embedded key BEFORE checking if the feature/alg is enabled.
// 2. Checks the outer header `x-token-alg`, while `parseAndVerifyBlob` dispatches on `blob.innerAlg`!
export async function handleSignedEnvelopeVulnerable(req: Request, config: AppConfig) {
  const advertisedAlg = req.headers.get("x-token-alg") ?? "";
  const rawBody = await req.json(); // Unbounded JSON parse before auth/gate!

  // Heavy parser dispatches on `rawBody.innerAlg` and runs expensive crypto BEFORE checking allowlist:
  const parsed = await parseAndVerifyComplexEnvelope(rawBody);

  if (!config.allowedAlgorithms.includes(advertisedAlg)) {
    return new Response("Algorithm disabled", { status: 403 });
  }
  return processVerifiedEnvelope(parsed);
}
```

```typescript
// HARDENED (OpenSSH 10.6 pattern):
// 1.Enforce byte limit + authentication/allowlist gate FIRST.
// 2. Verify allowlist inside the parser BEFORE deserializing algorithm-specific structures.
// 3. Assert `advertisedAlg === innerAlg` (zero envelope-vs-payload confusion).
export async function handleSignedEnvelopeHardened(
  req: Request,
  config: { allowedAlgorithms: ReadonlySet<string> }
) {
  const advertisedAlg = req.headers.get("x-token-alg")?.trim() ?? "";

  // Gate 1: Reject disallowed algorithm before reading or parsing the body at all:
  if (!config.allowedAlgorithms.has(advertisedAlg)) {
    return new Response(JSON.stringify({ error: "UNSUPPORTED_ALGORITHM" }), { status: 400 });
  }

  // Gate 2: Bounded body read (max 16 KiB):
  const envelope = await readBoundedJson<{ innerAlg: string; payloadB64: string }>(req, 16 * 1024);

  // Gate 3: Enforce strict equality between outer advertised algorithm and inner payload algorithm:
  if (envelope.innerAlg !== advertisedAlg || !config.allowedAlgorithms.has(envelope.innerAlg)) {
    return new Response(JSON.stringify({ error: "ALGORITHM_ENVELOPE_MISMATCH" }), { status: 400 });
  }

  // Only now is the allowed algorithm's parser reachable:
  const verified = await parseAndVerifyAllowedEnvelope(envelope.innerAlg, envelope.payloadB64);
  return processVerifiedEnvelope(verified);
}
```

### Pass 3: Configuration Interaction & Silent Control Degradation Audit
1. **Extract all security-relevant configuration flags and environment variables** (auth mode, proxy trust, CORS origins, rate limiting, TLS/mTLS, IP/hostname allowlists, cookie flags, webhook verification).
2. **Prune before you pair.** Enumerating all $C_i \times C_j$ is infeasible (Anthropic's study covered 17,000+ options, 3,842 of them security-relevant; the 3,842 security-relevant options alone give about 7 million unordered pairs). Use the flag graph (Table E in [`surface-and-sink-mapping.md`](surface-and-sink-mapping.md)):
   - Keep only **security-relevant** flags (those whose read sites sit inside an authentication, authorization, tenancy, CORS, cookie, rate-limit, proxy-trust, TLS, allowlist or webhook-verification code path).
   - Build a **guards-read-flags** relation: for each security guard, collect every flag that appears in the guard's *condition* (not just the flag that enables it). Candidate pairs are exactly `(flag that enables guard G, any other flag read in G's condition or in code that G's inputs flow through)`—tens of pairs, not millions.
   - Add pairs where two flags can set the same underlying value (global vs per-route, long vs short alias). Those are precedence-shadowing candidates.
   - For each candidate pair, **execute** it: boot the lab with the pair set in the dangerous combination and run the relevant oracle slice ([`deterministic-oracle-sweep.md`](deterministic-oracle-sweep.md)); a combination that turns a previously failing forged request into a `200` is a deterministic finding.
3. **Test pairwise interactions for silent degradation (over the pruned set):**
   - **Rule Depends on Disabled Resolver:** Does an access-control rule (e.g., hostname deny-list, geo-IP block, or `X-Forwarded-For` IP check) depend on another setting (`reverse_dns`, `trust_proxy`, edge header injection) that can be turned off, causing the rule to evaluate against `null` or a raw IP and **fail open**?
   - **Alias / Precedence Shadowing:** If a setting can be configured in two places (e.g., global config vs. per-route config, or `AUTH_REQUIRED` vs. `PUBLIC_MODE`), which one wins? Does a permissive shorthand override a strict security flag without warning?
4. **Fix by Failing Closed at Boot:** Add pairwise conflict assertions to `assertSafeBootConfig()` (see [`../1-known-vulnerabilities/infra-and-supply-chain/dev-bypasses-and-boot-assertions.md`](../1-known-vulnerabilities/infra-and-supply-chain/dev-bypasses-and-boot-assertions.md)) so any configuration combination that weakens a security control immediately aborts startup with an explicit error message.

---

## 5. Web-Application Adaptation: What "Pre-Auth Surface" Means for a Deployed App

The Anthropic study targeted daemons and libraries; the same three questions apply to a web application, but the inventory differs. Enumerate every item below from the runtime route dump ([`surface-and-sink-mapping.md`](surface-and-sink-mapping.md)) and, for each, ask *"what complex code runs before the hard gate, and is it needed in the default deployment?"*

| Pre-auth surface in a web app | What runs before authentication | Typical gate (Pass 2 hoisting) |
|-------------------------------|----------------------------------|--------------------------------|
| Unauthenticated routes (landing, health, status, docs) | Handlers, template rendering | Remove unused; no data access |
| Body parsers mounted globally | JSON/multipart/zip/XML parsing of attacker bytes | Parse after auth; byte ceilings before parse |
| File upload and image/PDF processing (`sharp`, `ImageMagick`, headless browser) | Decoders, renderers | Authenticate and quota first; sandbox the decoder |
| Markdown / rich-text rendering of public content | Parsers, sanitizers | Allowlist sanitizer; no raw HTML |
| OAuth/OIDC callbacks, magic-link and password-reset endpoints | State/nonce handling, email sends, user lookups | Rate limit; constant-shape responses; no enumeration |
| Email/SMS senders reachable by anonymous callers | Third-party API spend | Pre-call atomic budget ([`../1-known-vulnerabilities/state-and-economics/public-compute-and-denial-of-wallet.md`](../1-known-vulnerabilities/state-and-economics/public-compute-and-denial-of-wallet.md)) |
| Public share links and embeds | Token lookup, data rendering | Unguessable tokens, expiry, revocation, scoped projection |
| Webhook receivers | Body read, HMAC, JSON parse, event dispatch | Raw-body HMAC and timestamp **before** parse; dedupe |
| WebSocket / SSE upgrade endpoints | Handshake, subscription setup | Origin check and auth in the upgrade handler ([`../1-known-vulnerabilities/injection-and-trust-boundaries/browser-boundary.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/browser-boundary.md)) |
| Debug, metrics, profiling, OpenAPI/Swagger, GraphQL introspection/playground | Introspection, stack traces, heap data | Disable by default; boot-assert in production |
| Source maps, build artifacts, `.git`, `.env` | Static file serving | Not deployed; 404 |
| Framework internals (`/_next/data`, `/_next/image`, RSC endpoints, middleware matchers) | Image fetch/transform, data routes outside matcher | Match all data/route variants; allowlist remote image hosts ([`../1-known-vulnerabilities/auth-and-sessions/nextjs-and-edge-specifics.md`](../1-known-vulnerabilities/auth-and-sessions/nextjs-and-edge-specifics.md)) |
| Legacy API versions (`/api/v1/*`) and compatibility shims | Old handlers without new guards | Remove or place behind the same gate |
| Edge path-normalization differences | Edge ACL evaluates a different path than the origin | Normalize once; verify edge JWT in the origin |

Record each as an ASR lead with: surface, current gate, proposed gate, breaking/non-breaking classification (Pass 1, item 4), and the oracle that will prove the gate holds.
