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
2. **Test pairwise interactions ($C_i \times C_j$) for silent degradation:**
   - **Rule Depends on Disabled Resolver:** Does an access-control rule (e.g., hostname deny-list, geo-IP block, or `X-Forwarded-For` IP check) depend on another setting (`reverse_dns`, `trust_proxy`, edge header injection) that can be turned off, causing the rule to evaluate against `null` or a raw IP and **fail open**?
   - **Alias / Precedence Shadowing:** If a setting can be configured in two places (e.g., global config vs. per-route config, or `AUTH_REQUIRED` vs. `PUBLIC_MODE`), which one wins? Does a permissive shorthand override a strict security flag without warning?
3. **Fix by Failing Closed at Boot:** Add pairwise conflict assertions to `assertSafeBootConfig()` (see [`../1-known-vulnerabilities/infra-and-supply-chain/dev-bypasses-and-boot-assertions.md`](../1-known-vulnerabilities/infra-and-supply-chain/dev-bypasses-and-boot-assertions.md)) so any configuration combination that weakens a security control immediately aborts startup with an explicit error message.
