# Baseline 1: OWASP ASVS v5.0.0 Level 1 Verifiable Checklist

## Why OWASP ASVS v5.0.0 Level 1 is Our Baseline Floor

- **Why ASVS beats the OWASP Top 10:** The OWASP Top 10 is an awareness list of high-level failure categories (*what can go wrong*). The **OWASP Application Security Verification Standard (ASVS)** is a pass/fail engineering standard of positive, testable `MUST` requirements (*what the application must do*).
- **Version check (`v5.0.0`, released May 2025, current in 2026):** Unlike legacy `v4.0.3` (2021, which had 128 L1 items restricted to black-box checks), **ASVS v5.0.0** reorganized the standard into **17 chapters with 345 requirements** and redesigned **Level 1 (`70 requirements`, 20.3% of the standard)** as the pragmatic **first layer of defense** against attacks that require no other vulnerabilities or preconditions to exploit.
- **Provenance of this checklist (regenerate, do not trust):** The 70 items below are a hand-maintained paraphrase. Requirement IDs, wording, level assignments and counts must be **regenerated from the official ASVS machine-readable release pinned to a specific commit** of the OWASP ASVS repository, so the list cannot drift from the standard and each item can carry a verbatim-source link.
  > **TODO (maintainers): pin the official ASVS v5.0.0 data file by commit SHA, add a generator script that emits this checklist from it, and fail CI if the committed Markdown differs from the generated output. Commit SHA: _not yet pinned_ (do not guess one).**
  Until that is done, treat any requirement ID cited from this file as "to be verified against the official source" before quoting it in an external audit report.
- **Explicit Scope:** ASVS covers the application and its HTTP edge (WAF/reverse proxy). It **excludes CI/CD pipeline hardening and dependency supply-chain locks**, which are covered in [`../1-known-vulnerabilities/infra-and-supply-chain/dependency-and-ci-supply-chain.md`](../1-known-vulnerabilities/infra-and-supply-chain/dependency-and-ci-supply-chain.md) and [`pre-deploy-security-pipeline.md`](pre-deploy-security-pipeline.md).
- **Pruning Irrelevant Chapters ("Forking the ASVS"):** Per official OWASP guidance, strip sections that do not apply to a given service (e.g., skip `V10.4` if you are not operating an OAuth Authorization Server; skip `V4.4.1` if you do not use WebSockets; skip `V3` for a pure machine-to-machine CLI/API).

---

## Step 1: The 4 Mandatory Documented Security Decisions (`V2.1.1`, `V6.1.1`, `V8.1.1`, `V15.1.1`)

ASVS v5.0.0 Level 1 requires four short, explicit engineering specs in every repository (stored in `SECURITY.md` or enforced directly in shared middleware) because neither a human nor an LLM agent can verify authorization or validation without knowing the intended rules:

| Requirement ID | Decision Record Required | What Must Be Specified |
|----------------|--------------------------|------------------------|
| **`v5.0.0-2.1.1`** | **Input Validation Schema Policy** | Expected types, byte/character length ceilings, numeric bounds (positive integers for currency/credits), and format schemas for all business-critical inputs. |
| **`v5.0.0-6.1.1`** | **Anti-Automation & Brute-Force Policy** | How rate limiting and sliding-window budgets stop credential stuffing, OTP guessing, and compute abuse **without** allowing an attacker to mass-lock legitimate user accounts. |
| **`v5.0.0-8.1.1`** | **Authorization & Tenancy Matrix** | Function-level and object-level (IDOR/BOLA) access rules per actor tier (`Owner`, `Member`, `ProjectGuest`, `MachineApiKey`, `Anonymous`) and resource attribute (`tenant_id`, `project_id`). |
| **`v5.0.0-15.1.1`** | **Dependency Remediation SLA** | Maximum time window to patch or mitigate third-party dependencies with disclosed vulnerabilities by severity (e.g., Critical: `<24h`, High: `<7d`). |

---

## Step 2: Complete 70-Requirement OWASP ASVS v5.0.0 Level 1 Checklist

### Chapter V1 — Encoding and Sanitization (8 L1 Requirements)
- [ ] **`v5.0.0-1.2.1`:** Perform context-appropriate output encoding for HTTP responses, HTML elements, HTML attributes, comments, CSS, and HTTP headers.
- [ ] **`v5.0.0-1.2.2`:** Apply context-aware URL encoding (`base64url` / percent-encoding) when constructing dynamic URLs, and strictly allowlist safe schemes (`https:`, `http:`, `mailto:`), blocking `javascript:` and `data:`.
- [ ] **`v5.0.0-1.2.3`:** Perform output encoding/escaping when dynamically building JavaScript or JSON content.
- [ ] **`v5.0.0-1.2.4`:** Use parameterized queries, prepared statements, or validated tagged templates for all SQL, HQL, NoSQL, Cypher, and stored-procedure queries (see [`sql-and-query-construction.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/sql-and-query-construction.md)).
- [ ] **`v5.0.0-1.2.5`:** Use parameterized OS command execution APIs (`execFile` / `Command::new` with argument arrays, never shell string concatenation) to prevent OS command injection.
- [ ] **`v5.0.0-1.3.1`:** Sanitize untrusted HTML input (WYSIWYG / Markdown HTML) with a battle-tested library (e.g., DOMPurify) before rendering.
- [ ] **`v5.0.0-1.3.2`:** Avoid `eval()`, `new Function()`, and dynamic expression evaluation entirely.
- [ ] **`v5.0.0-1.5.1`:** Disable XML external entity resolution (`XXE`) and DTD fetching in all XML parsers.

### Chapter V2 — Validation and Business Logic (4 L1 Requirements)
- [ ] **`v5.0.0-2.1.1`:** Document input validation rules and schemas (see Step 1 above).
- [ ] **`v5.0.0-2.2.1`:** Enforce positive input validation (strict allowlists, regexes, integer ranges, `.strict()` object schemas) on all inputs used in business or security decisions.
- [ ] **`v5.0.0-2.2.2`:** Enforce all input validation at a trusted backend service layer (never rely on client-side browser validation).
- [ ] **`v5.0.0-2.3.1`:** Enforce sequential step order in multi-step business workflows so callers cannot skip intermediate steps such as payment or verification (see [`workflow-step-skipping-and-webhooks.md`](../1-known-vulnerabilities/state-and-economics/workflow-step-skipping-and-webhooks.md)).

### Chapter V3 — Web Frontend Security (8 L1 Requirements)
- [ ] **`v5.0.0-3.2.1`:** Prevent browsers from rendering API responses or user-uploaded files in an unintended execution context (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`).
- [ ] **`v5.0.0-3.2.2`:** Render untrusted text using safe DOM APIs (`textContent`, `createTextNode`, React default JSX escaping), never raw HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`).
- [ ] **`v5.0.0-3.3.1`:** Mark session/auth cookies `Secure` and prefix cookie names with `__Host-` (preferred: `Secure; Path=/; no Domain`) or `__Secure-`.
- [ ] **`v5.0.0-3.4.1`:** Send `Strict-Transport-Security` (HSTS) on all responses with `max-age >= 31536000` (1 year).
- [ ] **`v5.0.0-3.4.2`:** Use a fixed `Access-Control-Allow-Origin` or validate `Origin` against an explicit allowlist; never return authenticated/sensitive data with `Access-Control-Allow-Origin: *`.
- [ ] **`v5.0.0-3.5.1`:** Protect cookie-authenticated state-changing requests against CSRF via anti-forgery tokens, `Origin` verification, or custom non-CORS-safelisted headers.
- [ ] **`v5.0.0-3.5.2`:** Where CORS preflight is relied upon, ensure endpoints reject simple (non-preflighted) cross-origin requests by checking `Origin` and `Content-Type`.
- [ ] **`v5.0.0-3.5.3`:** Never perform sensitive state mutations on HTTP `GET`, `HEAD`, or `OPTIONS` requests.

### Chapter V4 — API and Web Service (2 L1 Requirements)
- [ ] **`v5.0.0-4.1.1`:** Set an accurate `Content-Type` and `charset` header (e.g., `application/json; charset=utf-8`) on every HTTP response containing a body.
- [ ] **`v5.0.0-4.4.1`:** *(If using WebSockets)* Use encrypted `wss://` over TLS for all WebSocket connections.

### Chapter V5 — File Handling (4 L1 Requirements)
- [ ] **`v5.0.0-5.2.1`:** Enforce strict file upload and request body byte-size ceilings before buffering into memory.
- [ ] **`v5.0.0-5.2.2`:** Validate uploaded files (including archives) by both file extension allowlist and actual file content / magic bytes.
- [ ] **`v5.0.0-5.3.1`:** Never allow user-uploaded files stored in public or static directories to execute as server-side code or active same-origin HTML/SVG.
- [ ] **`v5.0.0-5.3.2`:** Construct storage file paths strictly from internal UUIDs (`tenants/{tenant_uuid}/blobs/{blob_uuid}`), never raw user filenames (see [`ssrf-file-uploads-and-path-traversal.md`](../1-known-vulnerabilities/injection-and-trust-boundaries/ssrf-file-uploads-and-path-traversal.md)).

### Chapter V6 — Authentication (13 L1 Requirements)
- [ ] **`v5.0.0-6.1.1`:** Document anti-brute-force and anti-automation controls (see Step 1).
- [ ] **`v5.0.0-6.2.1`:** Require passwords to be at least 8 characters (`15+` recommended).
- [ ] **`v5.0.0-6.2.2`:** Allow users to change their password.
- [ ] **`v5.0.0-6.2.3`:** Require both the current password and new password when changing a password.
- [ ] **`v5.0.0-6.2.4`:** Reject passwords found in at least the top 3,000 most common/breached passwords.
- [ ] **`v5.0.0-6.2.5`:** **Do not impose arbitrary password composition rules** (do not force special/uppercase/number combinations).
- [ ] **`v5.0.0-6.2.6`:** Mask password inputs (`type="password"`) with an optional user-controlled reveal toggle.
- [ ] **`v5.0.0-6.2.7`:** **Allow pasting into password fields** and compatibility with password managers.
- [ ] **`v5.0.0-6.2.8`:** Verify passwords verbatim as received without silent truncation or case-folding.
- [ ] **`v5.0.0-6.3.1`:** Implement anti-brute-force controls that prevent credential stuffing without enabling mass lockout of legitimate users.
- [ ] **`v5.0.0-6.3.2`:** Disable or remove all default/hardcoded accounts (`admin`, `root`, `dev`, `test`) in production.
- [ ] **`v5.0.0-6.4.1`:** Generate initial activation and password-reset codes using a CSPRNG with a short expiration TTL.
- [ ] **`v5.0.0-6.4.2`:** **Never use password hints or knowledge-based "secret questions".**

### Chapter V7 — Session Management (6 L1 Requirements)
- [ ] **`v5.0.0-7.2.1`:** Verify all session tokens at a trusted backend service layer.
- [ ] **`v5.0.0-7.2.2`:** Use dynamic session tokens for interactive users rather than static API keys.
- [ ] **`v5.0.0-7.2.3`:** Generate session identifiers using an approved CSPRNG with at least 128 bits of entropy.
- [ ] **`v5.0.0-7.2.4`:** Rotate/generate a new session token upon authentication or privilege change and invalidate the previous token (and bind token purpose—see [`cookie-purpose-confusion-and-oidc.md`](../1-known-vulnerabilities/auth-and-sessions/cookie-purpose-confusion-and-oidc.md)).
- [ ] **`v5.0.0-7.4.1`:** Invalidate session tokens on the backend upon user logout or expiration.
- [ ] **`v5.0.0-7.4.2`:** Immediately terminate all active sessions and API keys when a user account or organization membership is disabled, removed, or deleted.

### Chapter V8 — Authorization (4 L1 Requirements)
- [ ] **`v5.0.0-8.1.1`:** Document function-level and data/object-level authorization rules (see Step 1).
- [ ] **`v5.0.0-8.2.1`:** Verify function-level authorization for every route/action before execution.
- [ ] **`v5.0.0-8.2.2`:** Verify data/object-level authorization (IDOR/BOLA) explicitly for every requested or mutated record and foreign key (see [`cross-tenant-idor-and-explicit-scoping.md`](../1-known-vulnerabilities/authorization-and-tenancy/cross-tenant-idor-and-explicit-scoping.md)).
- [ ] **`v5.0.0-8.3.1`:** Enforce all authorization checks at a trusted backend layer (never rely on UI element hiding).

### Chapter V9 — Self-Contained Tokens / JWTs (4 L1 Requirements)
- [ ] **`v5.0.0-9.1.1`:** Validate token digital signatures or MACs before reading or trusting any payload claim.
- [ ] **`v5.0.0-9.1.2`:** Enforce an explicit algorithm allowlist (`RS256`, `ES256`, etc.) and reject `alg: none` or symmetric/asymmetric key confusion.
- [ ] **`v5.0.0-9.1.3`:** Trust only pre-configured key sources (pinned JWKS URL / keys) and never fetch unallowlisted `jku`, `x5u`, or `jwk` header parameters.
- [ ] **`v5.0.0-9.2.1`:** Validate token expiration (`exp`) and not-before (`nbf`) claims (plus `iss` and `aud`—see [`jwt-and-edge-header-spoofing.md`](../1-known-vulnerabilities/auth-and-sessions/jwt-and-edge-header-spoofing.md)).

### Chapter V10 — OAuth and OIDC (5 L1 Requirements — *Only if Operating an OAuth Authorization Server*)
- [ ] **`v5.0.0-10.4.1`:** Validate `redirect_uri` using exact byte-for-byte string matching against a pre-registered allowlist.
- [ ] **`v5.0.0-10.4.2`:** Enforce single-use authorization codes and revoke issued tokens if an authorization code is replayed.
- [ ] **`v5.0.0-10.4.3`:** Restrict authorization code lifetime to $\le 10$ minutes.
- [ ] **`v5.0.0-10.4.4`:** Forbid deprecated Implicit (`response_type=token`) and Resource Owner Password Credentials (`password`) grants.
- [ ] **`v5.0.0-10.4.5`:** Mitigate refresh-token replay on public clients via refresh token rotation or sender-constrained tokens (`DPoP` / `mTLS`).

### Chapters V11–V15 — Cryptography, TLS, Configuration, Data Protection & Architecture (12 L1 Requirements)
- [ ] **`v5.0.0-11.3.1`:** Forbid insecure block modes (`ECB`) and weak padding (`PKCS#1 v1.5` encryption).
- [ ] **`v5.0.0-11.3.2`:** Use approved authenticated encryption modes (`AES-GCM`, `ChaCha20-Poly1305`).
- [ ] **`v5.0.0-11.4.1`:** Forbid weak hashes (`MD5`, `SHA-1`) for any cryptographic, signature, or password purpose.
- [ ] **`v5.0.0-12.1.1`:** Enable only `TLS 1.2` and `TLS 1.3` (preferring `TLS 1.3`).
- [ ] **`v5.0.0-12.2.1`:** Require HTTPS for all external client connections with no plaintext HTTP fallback.
- [ ] **`v5.0.0-12.2.2`:** Use publicly trusted TLS certificates on external endpoints.
- [ ] **`v5.0.0-13.4.1`:** Never deploy or expose `.git` or `.svn` folders externally or inside production web roots.
- [ ] **`v5.0.0-14.2.1`:** Never transmit API keys, session tokens, or sensitive credentials in URL paths or query parameters (`?token=...`).
- [ ] **`v5.0.0-14.3.1`:** Clear authenticated data and tokens from client DOM and browser storage upon logout/session termination.
- [ ] **`v5.0.0-15.1.1`:** Document dependency vulnerability remediation SLAs (see Step 1).
- [ ] **`v5.0.0-15.2.1`:** Remediate third-party dependencies with disclosed vulnerabilities within the documented SLA.
- [ ] **`v5.0.0-15.3.1`:** Return only the explicit required subset of fields from data objects in API responses rather than serializing full database models (`SELECT *`).
