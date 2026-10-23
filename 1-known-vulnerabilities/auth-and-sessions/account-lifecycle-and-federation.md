# Account Lifecycle & Federation (OAuth/OIDC Flows, SAML, Reset Links, Identifier Collisions, MFA, Refresh Tokens)

> **Invariants:** `I1 — Authentic Identity & Purpose Binding`, `I3 — State-Machine & Economic Conservation` (OWASP ASVS `v5.0.0-6.3.1`, `6.4.1`, `7.2.4`, `7.4.2`, `10.4.1`–`10.4.5`, `1.2.2`).
> Related: [`cookie-purpose-confusion-and-oidc.md`](cookie-purpose-confusion-and-oidc.md) · [`api-key-lifecycle-and-privilege-escalation.md`](api-key-lifecycle-and-privilege-escalation.md) · [`../state-and-economics/race-conditions-and-double-spend.md`](../state-and-economics/race-conditions-and-double-spend.md) · [`../injection-and-trust-boundaries/browser-boundary.md`](../injection-and-trust-boundaries/browser-boundary.md) · [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)

Authentication bugs rarely live in the password check. They live in the flows around it: how an account is created, linked, recovered, re-verified and kept alive.

---

## 1. Attack Transcript

**1a. Reset-link poisoning via `Host`.** The reset email is built from the request's `Host`. The attacker triggers a reset for the victim with their own host.

```http
POST /api/auth/forgot-password HTTP/1.1
Host: attacker.example
X-Forwarded-Host: attacker.example
Content-Type: application/json

{"email":"victim@company.com"}

HTTP/1.1 200 OK
```

The victim receives "Reset your password: https://attacker.example/reset?token=7c1f...". Their click, or a mail scanner's prefetch, delivers the token.

**1b. Open redirect after login.**

```http
GET /login?next=//evil.example/phish HTTP/1.1
...after successful login...
HTTP/1.1 302 Found
Location: //evil.example/phish
```

Chained with an OAuth `redirect_uri` that is a prefix match, the authorization code or token goes to the attacker.

**1c. Refresh-token reuse race.** A stolen refresh token and the legitimate client refresh in the same instant; both succeed, producing two live token families.

```bash
$ seq 2 | xargs -P2 -I{} curl -s -X POST https://api.example.com/oauth/token \
    -d 'grant_type=refresh_token&refresh_token=rt_AAA...'
{"access_token":"at_1","refresh_token":"rt_BBB"}
{"access_token":"at_2","refresh_token":"rt_CCC"}
```

**1d. Identifier collision.** The attacker registers `ADMIN@company.com` or a Unicode lookalike that normalizes to the same canonical email as a victim at the mail provider but is distinct in the app's table.

---

## 2. Spot the Bug

Find five problems.

```typescript
app.post("/api/auth/forgot-password", async (req) => {
  const { email } = await req.json();
  const user = await db.queryOne("SELECT id FROM users WHERE email = $1", [email]);
  if (!user) return Response.json({ error: "No such user" }, { status: 404 });
  const token = Math.random().toString(36).slice(2);
  await db.execute("INSERT INTO resets (user_id, token) VALUES ($1, $2)", [user.id, token]);
  const url = `${new URL(req.url).origin}/reset?token=${token}`;
  await sendEmail(email, `Reset: ${url}`);
  return Response.json({ ok: true });
});

app.get("/login/callback", async (req) => {
  const u = new URL(req.url);
  const code = u.searchParams.get("code")!;
  const tokens = await exchangeCode(code);
  const claims = decodeIdToken(tokens.id_token);
  const session = await loginByEmail(claims.email);
  return Response.redirect(u.searchParams.get("next") ?? "/", 302);
});

app.post("/api/auth/refresh", async (req) => {
  const { refresh_token } = await req.json();
  const row = await db.queryOne("SELECT user_id FROM refresh_tokens WHERE token = $1", [refresh_token]);
  if (!row) return new Response("bad", { status: 401 });
  return Response.json(await issueTokens(row.user_id));
});

app.post("/api/auth/verify-otp", async (req) => {
  const { userId, code } = await req.json();
  const ok = await checkOtp(userId, code);
  return ok ? Response.json(await grantSession(userId)) : new Response("bad", { status: 401 });
});
```

---

## 3. Invariant Violated & Mechanism

1. **OAuth/OIDC state, PKCE, nonce.** Without `state` bound to the initiating browser, a login CSRF lets an attacker log the victim into the attacker's account (or complete a linking flow). Without PKCE (S256), a stolen authorization code is redeemable by anyone. Without `nonce` checked in the ID token, a token minted for another session can be replayed. `redirect_uri` must match a registered value by exact string (ASVS `10.4.1`); `id_token` signature, `iss`, `aud`, `exp` must be verified, not `decode`d.
2. **Open redirects (`next=`, `returnTo`, `redirect`)** are the oracle that steals codes, tokens and reset links: `//evil.example`, `/\evil.example`, `https:evil.example`, `javascript:` and tab/newline-embedded schemes all defeat naive `startsWith("/")` checks.
3. **SAML signature wrapping (XSW).** The signature is valid over *one* element while the application reads attributes from *another*. Typical flaws: verifying "a" signature then selecting the assertion by XPath/first-match, accepting multiple assertions, processing unsigned assertions inside a signed response, XML comment injection in `NameID` (`admin@co.com<!---->.evil.com`), no check of `Audience`, `Recipient`, `InResponseTo`, `NotOnOrAfter`, no replay cache of assertion IDs, and XML parsers with DTD/XXE enabled (ASVS `1.5.1`).
4. **`email_verified` is not enough.** A verified email at an IdP that is not authoritative for the domain does not prove control of the mailbox the local account was created with. Link by `(iss, sub)`; see [`cookie-purpose-confusion-and-oidc.md`](cookie-purpose-confusion-and-oidc.md).
5. **Reset-link poisoning.** Building absolute URLs from `Host`/`X-Forwarded-Host` lets the requester choose where the victim's token is delivered. Predictable tokens (`Math.random`), non-expiring tokens, multi-use tokens and tokens stored in plaintext compound it (ASVS `6.4.1`).
6. **User enumeration.** Different status, body, timing or email behavior between known and unknown accounts on login, reset, signup and OTP endpoints.
7. **Unicode/case-fold identifier collisions.** `Admin` vs `admin`, `ǅ`/`DŽ`, fullwidth forms, trailing dots/spaces, plus-addressing and dot-insensitive providers, and email local-part parsing differentials (`a@b.com@evil.com`, quoted local parts). Uniqueness is enforced on one representation, authorization or mail delivery on another.
8. **Email change without re-verification** converts a session theft into permanent takeover: the attacker changes the email, then resets the password.
9. **OTP/MFA brute force and race.** A 6-digit code has 10^6 values; without an atomic per-user attempt counter, parallel guesses beat the limit (check-then-increment). Recovery codes and "remember this device" cookies need the same treatment.
10. **Refresh-token rotation without reuse detection** gives a thief a persistent session; rotation without an atomic consume lets two requests both succeed.

Why happy-path tests pass: the sign-in flow is exercised once, in order, by one browser. Tests never alter `state`, replay a code, use `Host: attacker.example`, send two concurrent refreshes, or register a lookalike.

Where it hides: auth libraries configured loosely; custom "login with X" callbacks; password-reset and invite emails; "link account" settings pages; mobile/CLI device flows; SCIM/provisioning; background session refresh.

---

## 4. Hardened Pattern

### 4.1 OAuth/OIDC start and callback: state + PKCE + nonce bound to the browser

```typescript
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const b64url = (b: Buffer) => b.toString("base64url");

export function newPkcePair() {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export async function startOidc(deps: {
  providerAuthUrl: string; clientId: string; redirectUri: string; // registered, exact
  store: { put(id: string, rec: { verifier: string; nonce: string; next: string }, ttlSec: number): Promise<void> };
}, nextRaw: string | null): Promise<{ redirectTo: string; setCookie: string }> {
  const state = b64url(randomBytes(32));
  const nonce = b64url(randomBytes(32));
  const { verifier, challenge } = newPkcePair();
  await deps.store.put(state, { verifier, nonce, next: safeNextPath(nextRaw) }, 600);

  const u = new URL(deps.providerAuthUrl);
  u.search = new URLSearchParams({
    response_type: "code",
    client_id: deps.clientId,
    redirect_uri: deps.redirectUri,
    scope: "openid email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();

  // Bind the flow to THIS browser: a leaked authorize URL cannot be completed elsewhere.
  const bind = createHash("sha256").update(state).digest("base64url");
  return { redirectTo: u.toString(), setCookie: `__Host-oauth_bind=${bind}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax` };
}

export async function finishOidc(deps: {
  store: { take(id: string): Promise<{ verifier: string; nonce: string; next: string } | null> }; // atomic get-and-delete
  exchange(code: string, verifier: string): Promise<{ id_token: string }>;
  verifyIdToken(idToken: string, expect: { nonce: string }): Promise<OidcClaims>; // signature, iss, aud, exp, nonce
}, params: URLSearchParams, bindCookie: string | null) {
  const state = params.get("state");
  const code = params.get("code");
  if (!state || !code || !bindCookie) throw new Error("OAUTH_BAD_REQUEST");

  const expectedBind = createHash("sha256").update(state).digest("base64url");
  const a = Buffer.from(bindCookie);
  const b = Buffer.from(expectedBind);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("OAUTH_STATE_NOT_BOUND");

  const rec = await deps.store.take(state); // single use
  if (!rec) throw new Error("OAUTH_STATE_UNKNOWN_OR_REPLAYED");

  const { id_token } = await deps.exchange(code, rec.verifier);
  const claims = await deps.verifyIdToken(id_token, { nonce: rec.nonce });
  return { claims, next: rec.next };
}
```

### 4.2 Redirect targets: relative same-site paths only

```typescript
export function safeNextPath(raw: string | null | undefined): string {
  if (!raw) return "/";
  // Reject control chars (tab/newline are stripped by URL parsers), backslashes, and protocol-relative forms.
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//")) return "/";
  try {
    const u = new URL(raw, "https://placeholder.invalid");
    if (u.origin !== "https://placeholder.invalid") return "/";
    return u.pathname + u.search;
  } catch {
    return "/";
  }
}
```

### 4.3 Reset: configured base URL, CSPRNG, hashed at rest, single use, no enumeration

```typescript
import { createHash, randomBytes } from "node:crypto";

export async function forgotPassword(
  deps: { db: Db; sendEmail(to: string, body: string): Promise<void>; baseUrl: string; rateLimit(key: string): Promise<boolean> },
  rawEmail: string,
  clientKey: string
): Promise<Response> {
  const generic = Response.json({ ok: true }); // identical for every outcome
  if (!(await deps.rateLimit(`reset:${clientKey}`)) ) return generic;

  const email = canonicalizeEmail(rawEmail);
  if (!email) return generic;
  const user = await deps.db.queryOne("SELECT id FROM users WHERE email_canonical = $1 AND disabled_at IS NULL", [email]);
  if (user) {
    const token = randomBytes(32).toString("base64url");
    const hash = createHash("sha256").update(token).digest("hex");
    await deps.db.execute(
      "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '30 minutes')",
      [user.id, hash]
    );
    // Absolute URL from CONFIGURATION, never from Host / X-Forwarded-Host.
    const url = `${deps.baseUrl}/reset#token=${token}`; // fragment: not sent to servers, proxies or Referer
    queueMicrotask(() => void deps.sendEmail(email, `Reset your password: ${url}`)); // async: send latency must not reveal existence
  }
  return generic;
}

/** Consume atomically: single use, unexpired. Then revoke all sessions and refresh families for the user. */
export const CONSUME_RESET_SQL = `
  UPDATE password_resets
     SET used_at = now()
   WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
  RETURNING user_id`;
```

### 4.4 Canonical identifiers

```typescript
export function canonicalizeEmail(raw: string): string | null {
  const s = raw.normalize("NFKC").trim().toLowerCase();
  if (s.length > 254 || /[\s<>()[\],;:\\"]/.test(s)) return null; // no quoted local parts, comments, multiple @ forms
  const at = s.indexOf("@");
  if (at <= 0 || at !== s.lastIndexOf("@")) return null;
  const domain = s.slice(at + 1).replace(/\.$/, "");
  if (!/^[a-z0-9.-]+$/.test(domain)) return null; // ASCII only: IDN domains must arrive as punycode (xn--)
  return `${s.slice(0, at)}@${domain}`;
}

export function canonicalizeUsername(raw: string): string | null {
  const s = raw.normalize("NFKC").toLowerCase().trim();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(s)) return null; // ASCII allow-list after normalization removes lookalikes
  return s;
}
```

Enforce uniqueness on the canonical column (`UNIQUE (email_canonical)`), and deliver mail to the address as entered only after canonicalization passes. Block reserved names (`admin`, `root`, `support`) on the canonical form.

### 4.5 Email change requires proof of both mailboxes and recent auth

Send a confirmation to the **new** address, a notice (with undo) to the **old** one, require fresh password/MFA, and apply the change only on consume of a single-use token. Revoke other sessions on completion.

### 4.6 OTP/MFA: atomic attempt budget

```sql
-- Count the attempt BEFORE comparing, in one statement. Locks out after 5, per user, per window.
UPDATE mfa_challenges
   SET attempts = attempts + 1
 WHERE id = $1 AND user_id = $2 AND attempts < 5 AND expires_at > now() AND consumed_at IS NULL
RETURNING code_hash, attempts;
```

Compare `code_hash` in constant time after the increment; on success, `UPDATE ... SET consumed_at = now() WHERE consumed_at IS NULL RETURNING 1`. Rate-limit by account *and* IP, and avoid enabling mass lockout of a victim (use progressive delay, not a hard permanent lock).

### 4.7 Refresh-token rotation with reuse detection (atomic)

```typescript
export async function rotateRefresh(db: Db, presented: string) {
  const hash = sha256Hex(presented);
  return db.transaction(async (tx) => {
    const row = await tx.queryOne<{ id: string; family_id: string; user_id: string }>(
      `UPDATE refresh_tokens
          SET used_at = now()
        WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
        RETURNING id, family_id, user_id`,
      [hash]
    );
    if (!row) {
      // Either unknown, expired, or ALREADY USED. If already used, treat as theft: revoke the whole family.
      const reused = await tx.queryOne<{ family_id: string }>(
        "SELECT family_id FROM refresh_tokens WHERE token_hash = $1 AND used_at IS NOT NULL",
        [hash]
      );
      if (reused) {
        await tx.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL", [reused.family_id]);
      }
      return null;
    }
    const next = newOpaqueToken();
    await tx.execute(
      `INSERT INTO refresh_tokens (id, family_id, user_id, token_hash, expires_at)
       VALUES (gen_random_uuid(), $1, $2, $3, now() + interval '30 days')`,
      [row.family_id, row.user_id, sha256Hex(next)]
    );
    return { refreshToken: next, userId: row.user_id };
  });
}
```

### 4.8 SAML: use a maintained library and consume only the verified node

```typescript
export async function consumeSamlResponse(
  lib: { verify(xml: string, opts: { idpCerts: string[]; audience: string; recipient: string; inResponseTo: string }): Promise<VerifiedAssertion> },
  xml: string,
  ctx: { idpCerts: string[]; audience: string; recipient: string; inResponseTo: string },
  replay: { markSeen(assertionId: string, ttlSec: number): Promise<boolean> } // atomic insert-if-absent
) {
  if (xml.length > 256 * 1024) throw new Error("SAML_TOO_LARGE");
  // The library MUST return data extracted from the exact element covered by the verified signature,
  // fail on multiple assertions, reject DTD/entities, and enforce NotBefore/NotOnOrAfter.
  const assertion = await lib.verify(xml, ctx);
  if (!(await replay.markSeen(assertion.id, 600))) throw new Error("SAML_ASSERTION_REPLAYED");
  return { subject: assertion.nameId, attributes: assertion.attributes, issuer: assertion.issuer };
}
```

Key point: never re-query the XML document for attributes after verification; use only what the verifier returned.

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **Fragments are not magic.** Putting the reset token in the URL fragment keeps it out of server logs, but the reset page's own scripts, analytics and extensions can read it; strip it with `history.replaceState` immediately and send it via `POST`.
- **Mail scanners prefetch links.** A single-use token consumed on `GET` is burned by the scanner. Make the `GET` render a confirmation page and consume on `POST`.
- **Rotation grace.** Two tabs refreshing at once look like reuse. Mitigate with a very short grace (seconds) that returns the same successor, or with sender-constrained tokens (DPoP/mTLS, ASVS `10.4.5`), rather than disabling reuse detection.
- **Enumeration by timing and side channels.** Uniform bodies are not enough; the existing-user path does DB writes and an email enqueue. Do the work asynchronously and measure with the timing oracle in the sweep. Signup, "email already registered" messages and invite flows leak the same fact.
- **Canonicalization is a policy choice.** NFKC and ASCII allow-lists reject legitimate international names. If you accept them, reject mixed-script confusables and keep a separate display name. Provider-specific rules (plus-addressing, dot-insensitivity) must never be used to *merge* accounts, only to detect duplicates for human review.
- **SAML libraries differ widely in XSW resistance.** Pin versions, include an XSW corpus in tests, and prefer OIDC where the IdP supports it.
- **IdP-initiated flows** have no `InResponseTo` and no `state`. Disable them, or compensate with strict audience/recipient checks, short validity and assertion replay caches.
- **Account linking via a second IdP** can reopen takeover; require re-authentication at the existing account before attaching a new federated identity.
- **Open redirect allow-list parsing differs across browsers.** Prefer opaque server-side redirect IDs (`?next=<id>` resolved from a table) over free-form paths for high-value flows.
- **Device and CLI flows** (device code, magic links) need their own rate limits, short expiries and clear user-code display to prevent phishing.

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. OAuth callbacks: state / nonce / PKCE / signature verification present?
rg -n -C 6 'state|nonce|code_verifier|code_challenge|decodeIdToken|jwt\.decode' src/ | rg -v test

# 2. Absolute URLs built from request-controlled values:
rg -n 'new URL\(req\.url\)\.origin|headers\.get\(["\x27](host|x-forwarded-host|origin)["\x27]\)' src/

# 3. Redirects driven by query parameters:
rg -n -C 3 'redirect\(|Response\.redirect|Location' src/ | rg -i 'next|returnTo|redirect|url'

# 4. Weak randomness in tokens and codes:
rg -n 'Math\.random|Date\.now\(\)\.toString\(36\)|uuid\(\)' src/

# 5. Refresh/reset/OTP lookups by raw token or without atomic consume:
rg -n -i 'FROM (refresh_tokens|resets|password_resets|otp)' src/
```

```yaml
rules:
  - id: absolute-url-from-request
    languages: [typescript]
    severity: ERROR
    message: Build emailed or redirected absolute URLs from configuration, not from the request.
    pattern-either:
      - pattern: new URL($REQ.url).origin
      - pattern: $REQ.headers.get("host")
      - pattern: $REQ.headers.get("x-forwarded-host")
  - id: id-token-decode-without-verify
    languages: [typescript]
    severity: ERROR
    message: ID tokens must be verified (signature, iss, aud, exp, nonce), not decoded.
    pattern-either:
      - pattern: decodeIdToken(...)
      - pattern: jwt.decode(...)
```

### B. Dynamic (all run against the local lab with a mock IdP, mock SMTP and a mock SAML IdP)
1. **State/PKCE/nonce mutation:** missing state, another browser's state, replayed state, wrong `code_verifier`, `nonce` mismatch, `redirect_uri` with a suffix/prefix/extra path. All fail.
2. **Open-redirect corpus:** `//evil`, `/\evil`, `\\evil`, `/%09/evil`, `https:evil`, `javascript:alert(1)`, `/%2f/evil`, and a path with embedded newline. Assert a relative same-origin result.
3. **Reset poisoning:** `Host: attacker.example` and `X-Forwarded-Host` on `forgot-password`; read the captured mail and assert the link host equals the configured base.
4. **Enumeration oracle:** compare status, body hash, response headers and timing distribution (≥200 samples) between existing, unknown, disabled and differently-cased emails on login, reset, signup, OTP.
5. **Race harness (barrier-synchronized):** 20× concurrent refresh with one token; 30× concurrent OTP guesses; 20× concurrent reset consume. Exactly one success; reuse of a consumed refresh revokes the family. See [`../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md`](../../2-discovery-and-attacker-methods/concurrency-and-race-attack-harnesses.md).
6. **Collision registration:** register `Admin@x.com`, `admin@x.com `, fullwidth and combining-mark variants; assert one canonical account and rejection of the rest.
7. **Email-change takeover:** change email without re-auth, and apply the change without confirming the new address. Assert both fail; assert old sessions are revoked after a reset.
8. **SAML XSW corpus:** wrapped assertions, duplicate assertions, comment-split `NameID`, unsigned inner assertion, expired and replayed IDs, wrong audience/recipient, DTD payload. All rejected.

---

## 7. How to Eliminate the Bug Class by Construction

1. **One auth-flow module** owns state/nonce/PKCE, redirect validation, token issuance and rotation; routes cannot construct session tokens themselves (private constructors, see [`cookie-purpose-confusion-and-oidc.md`](cookie-purpose-confusion-and-oidc.md)).
2. **Config-only absolute URLs.** A lint bans `Host`, `X-Forwarded-Host` and `req.url` origin from URL construction in mail and redirect code.
3. **Canonical identifier columns with `UNIQUE`** constraints and a single `canonicalize*` function used at every write and lookup.
4. **Atomic single-statement consumes** for reset tokens, OTP attempts, magic links and refresh tokens; families revoked on reuse.
5. **Uniform-response helpers** for enumeration-prone endpoints plus a timing oracle in CI.
6. **Federation by `(iss, sub)`;** email is an attribute, never a join key, and SAML/OIDC verification returns only data from the verified node.
