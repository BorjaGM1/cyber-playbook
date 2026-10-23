# Cookie Purpose Confusion, OIDC Unverified Emails & CSRF

> **Invariant:** `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-3.3.1`, `3.5.1`, `3.5.2`, `7.2.4`, `7.4.1`).
> Related: [`account-lifecycle-and-federation.md`](account-lifecycle-and-federation.md) · [`../injection-and-trust-boundaries/browser-boundary.md`](../injection-and-trust-boundaries/browser-boundary.md) · [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)

---

## 1. Attack Transcript

Step 1 of an MFA login is completed with only a password. The server sets a short-lived "pending" cookie. The attacker pastes that value into the `session` cookie and skips step 2.

```http
POST /api/auth/login/start HTTP/1.1
Host: app.example.com
Content-Type: application/json

{"email":"victim@example.com","password":"<known from credential stuffing>"}

HTTP/1.1 200 OK
Set-Cookie: pending_mfa=eyJ1c2VySWQiOiJ1XzQyIiwiZXhwIjoxNzYxMzAwMDAwfQ.q3J1Zy0...; Path=/; HttpOnly
{"next":"mfa_challenge"}
```

```http
GET /api/me HTTP/1.1
Host: app.example.com
Cookie: session=eyJ1c2VySWQiOiJ1XzQyIiwiZXhwIjoxNzYxMzAwMDAwfQ.q3J1Zy0...

HTTP/1.1 200 OK
{"id":"u_42","email":"victim@example.com","role":"owner"}
```

MFA never ran. Second transcript, OIDC takeover: the attacker registers `victim@example.com` on a permissive IdP without verifying it, logs in, and the callback links to the existing account.

```http
GET /api/auth/callback/permissive-idp?code=abc&state=xyz HTTP/1.1
Cookie: __Host-oauth_state=...

HTTP/1.1 302 Found
Set-Cookie: session=<token for existing user victim@example.com>
Location: /dashboard
```

---

## 2. Spot the Bug

Find the flaw(s) before reading on. Three things are wrong across the two snippets.

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

export function signToken(payload: object, secret: string): string {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

export function verifyToken(raw: string, secret: string): any | null {
  const [data, sig] = raw.split(".");
  const expected = createHmac("sha256", secret).update(data).digest("base64url");
  if (sig.length !== expected.length) return null;
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
  return payload.exp > Date.now() / 1000 ? payload : null;
}

export async function handleOidcCallback(oidcProfile: { sub: string; email: string }) {
  const existingUser = await db.findUserByEmail(oidcProfile.email);
  if (existingUser) {
    return signToken({ userId: existingUser.id, exp: Math.floor(Date.now() / 1000) + 3600 }, process.env.SESSION_SECRET!);
  }
}
```

---

## 3. Invariant Violated & Mechanism

- **Purpose confusion:** Multi-step flows (OIDC login, magic links, passkey enrolment, MFA, account linking) issue temporary signed cookies (`pending_auth`, `mfa_pending`, `oauth_state`) with the same `SESSION_SECRET` and helper as the full `session` cookie. The MAC covers `{ userId, exp }` but not the cookie name or purpose, so a value minted for step 1 verifies as a session.
- **Stateless means unrevocable:** A pure-HMAC session has no server-side record. Logout, role change, member removal and "revoke all sessions" cannot take effect until `exp` (ASVS `7.4.1`, `7.4.2`). `jti` claims that nobody checks are decoration.
- **OIDC unverified-email takeover:** Linking by `claims.email` without `email_verified === true` is the classic flaw. Even with `email_verified === true`, the IdP may not be *authoritative* for that domain: any tenant of a multi-tenant IdP, or any provider that lets users verify an address at a domain they do not control, can assert `victim@company.com`. Link by `(iss, sub)`; link to an existing local account by email only when the issuer is authoritative for that domain or the user proves control of the local account first.
- **Why happy-path tests pass:** tests send a valid `session` cookie and expect `200`, and no cookie and expect `401`. They never replay a cookie from flow A into slot B, and never log out and then replay the old cookie.
- **Where it hides:** generic `signCookie`/`verifyCookie` utilities shared across cookies; OIDC callbacks that run `SELECT * FROM users WHERE email = $1`; cookie setters without `__Host-`; cookie-authenticated mutations without Origin verification; mutations on `GET`.

---

## 4. Hardened Pattern

### 4.1 Purpose-bound tokens with per-purpose keys and a server-side record

Derive a subkey per purpose (so a token cannot verify under another purpose even if claims are edited), bind the purpose into the claims, and check a server-side `auth_tokens` row (`jti`) on every use. The row also carries single-use semantics for pending flows and the revocation state for sessions.

```typescript
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";

export type TokenPurpose =
  | "session:v1"
  | "oidc_state:v1"
  | "pending_mfa:v1"
  | "pending_passkey_enroll:v1";

export interface PurposeBoundClaims<P extends TokenPurpose> {
  readonly purpose: P;
  readonly sub: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

const MAX_TOKEN_BYTES = 1024;

function subkey(purpose: TokenPurpose, secret: string): Buffer {
  return createHmac("sha256", secret).update(`cookie-key:${purpose}`).digest();
}

export function signPurposeBoundToken<P extends TokenPurpose>(
  purpose: P,
  claims: Omit<PurposeBoundClaims<P>, "purpose">,
  secret: string
): string {
  const full: PurposeBoundClaims<P> = { ...claims, purpose };
  const payloadB64 = Buffer.from(JSON.stringify(full), "utf8").toString("base64url");
  const mac = createHmac("sha256", subkey(purpose, secret))
    .update(`${purpose}.${payloadB64}`)
    .digest("base64url");
  return `${payloadB64}.${mac}`;
}

/** Server-side record store. `consume` is atomic: UPDATE ... SET used_at = now() WHERE used_at IS NULL AND revoked_at IS NULL RETURNING 1 */
export interface TokenStore {
  isActive(jti: string, purpose: TokenPurpose, sub: string): Promise<boolean>;
  consume(jti: string, purpose: TokenPurpose, sub: string): Promise<boolean>;
}

export async function verifyPurposeBoundToken<P extends TokenPurpose>(
  expectedPurpose: P,
  rawToken: string,
  secret: string,
  store: TokenStore,
  opts: { singleUse: boolean; nowEpochSeconds?: number } = { singleUse: false }
): Promise<PurposeBoundClaims<P> | null> {
  if (rawToken.length === 0 || Buffer.byteLength(rawToken) > MAX_TOKEN_BYTES) return null;
  const parts = rawToken.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, providedMac] = parts;

  const expectedMac = createHmac("sha256", subkey(expectedPurpose, secret))
    .update(`${expectedPurpose}.${payloadB64}`)
    .digest("base64url");
  const a = Buffer.from(providedMac, "utf8");
  const b = Buffer.from(expectedMac, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  const now = opts.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  let parsed: PurposeBoundClaims<P>;
  try {
    parsed = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (parsed.purpose !== expectedPurpose) return null;
  if (typeof parsed.exp !== "number" || parsed.exp <= now) return null;
  if (typeof parsed.sub !== "string" || parsed.sub.length === 0) return null;
  if (typeof parsed.jti !== "string" || parsed.jti.length === 0) return null;

  // The MAC proves we issued it. Only the store proves it is still valid.
  const ok = opts.singleUse
    ? await store.consume(parsed.jti, expectedPurpose, parsed.sub)
    : await store.isActive(parsed.jti, expectedPurpose, parsed.sub);
  return ok ? parsed : null;
}

export function newJti(): string {
  return randomUUID();
}

export function buildHostSessionCookie(token: string, maxAgeSeconds: number): string {
  return `__Host-session=${token}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
```

For interactive sessions, prefer an opaque random 256-bit session ID stored as `SHA-256(id)` in a `sessions` table joined to `users.disabled_at IS NULL` and the live membership row (same join shape as the API-key query in [`api-key-lifecycle-and-privilege-escalation.md`](api-key-lifecycle-and-privilege-escalation.md)). Signed tokens remain appropriate for short-lived pending-flow artifacts, always with a store row.

### 4.2 OIDC: link by `(iss, sub)`; email linking only for authoritative issuers

```typescript
export interface OidcClaims {
  iss: string;
  sub: string;
  email?: string;
  email_verified?: boolean;
  hd?: string; // hosted-domain claim on some providers; informative only, never sufficient alone
}

/** Per-issuer policy configured by operators, never derived from the token. */
export interface IssuerPolicy {
  /** Domains this issuer is authoritative for (the issuer itself controls mailbox ownership). */
  authoritativeEmailDomains: ReadonlySet<string>;
  /** Issuer verifies mailbox ownership for arbitrary addresses (e.g. a consumer mailbox provider's own domains). */
  isMailboxProviderForOwnDomainsOnly: boolean;
}

export function assertLinkableOidcEmail(
  claims: OidcClaims,
  policies: ReadonlyMap<string, IssuerPolicy>
): { email: string } {
  const policy = policies.get(claims.iss);
  if (!policy) throw new Error("OIDC_ISSUER_NOT_CONFIGURED");
  if (!claims.email || claims.email_verified !== true) {
    throw new Error("OIDC_EMAIL_NOT_VERIFIED");
  }
  const email = claims.email.trim().toLowerCase();
  const at = email.lastIndexOf("@");
  if (at <= 0) throw new Error("OIDC_EMAIL_MALFORMED");
  const domain = email.slice(at + 1);
  if (!policy.authoritativeEmailDomains.has(domain)) {
    // Verified by an IdP that is not authoritative for this domain: do NOT auto-link to a local account.
    throw new Error("OIDC_ISSUER_NOT_AUTHORITATIVE_FOR_DOMAIN");
  }
  return { email };
}

export async function resolveOidcLogin(
  claims: OidcClaims,
  policies: ReadonlyMap<string, IssuerPolicy>,
  db: { findByFederatedIdentity(iss: string, sub: string): Promise<{ userId: string } | null> }
): Promise<{ userId: string } | { requiresLocalProof: { email: string } } | { newUser: true }> {
  const existing = await db.findByFederatedIdentity(claims.iss, claims.sub);
  if (existing) return existing; // (iss, sub) is the identity, email is only an attribute
  try {
    const { email } = assertLinkableOidcEmail(claims, policies);
    return { requiresLocalProof: { email } }; // link only after the user proves control of the local account
  } catch {
    return { newUser: true }; // create a separate account; never merge
  }
}
```

### 4.3 CSRF / Origin gate (cookie-authenticated mutations)

```typescript
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function assertSameOriginMutation(req: Request, allowedOrigins: ReadonlySet<string>): void {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return;
  if (!req.headers.get("cookie")) return; // no ambient credentials, no CSRF

  const origin = req.headers.get("origin");
  const fetchSite = req.headers.get("sec-fetch-site");
  const ok =
    origin !== null
      ? allowedOrigins.has(origin) // "null" is never in the allowlist
      : fetchSite === "same-origin" || fetchSite === "none";
  if (!ok) {
    throw new Response(JSON.stringify({ error: "CSRF_ORIGIN_MISMATCH" }), {
      status: 403,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
}
```

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **Per-purpose keys do not stop a leaked `SESSION_SECRET`.** Rotate with a `kid` in the token and accept two keys during rollover (see the 15-minute rotation drill in [`../infra-and-supply-chain/dependency-and-ci-supply-chain.md`](../infra-and-supply-chain/dependency-and-ci-supply-chain.md)).
- **Server-side check costs a DB read per request.** Cache positively for seconds only, and measure revocation latency against an explicit SLO. A zero-grace guarantee is not testable with replicas or KV.
- **`SameSite=Lax` is not CSRF protection** for same-site attackers (sibling subdomains, user-content origins). The `__Host-` prefix blocks cookie *tossing* but not same-site request forgery, so the Origin gate stays mandatory.
- **A missing `Origin`** is legitimate for some non-browser clients, which is why the gate keys on `Cookie` presence. Machine clients must use bearer keys, not cookies.
- **Authoritative-domain tables rot.** Domain ownership changes; re-validate the allowlist and require re-authentication for linking.
- **Pending tokens bound to a browser:** bind `oidc_state` to a random value stored in a `__Host-` cookie so a leaked state URL cannot be completed by another browser. See [`account-lifecycle-and-federation.md`](account-lifecycle-and-federation.md).

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. All HMAC / cookie signing functions: is the purpose bound?
rg -n 'createHmac|Hmac::<|CookieJar|Set-Cookie' src/

# 2. OIDC / OAuth callbacks missing email_verified or issuer policy:
rg -n -C 10 'email_verified|id_token|userinfo' src/

# 3. State-changing routes that verify Origin / Sec-Fetch-Site when cookies are used:
rg -n "headers\.get\(['\"]origin['\"]\)" src/
```

Semgrep-style rule (flag any signer that does not take a purpose):

```yaml
rules:
  - id: hmac-sign-without-purpose
    languages: [typescript]
    severity: ERROR
    message: HMAC signing must go through signPurposeBoundToken (purpose is a literal union member).
    patterns:
      - pattern: createHmac($ALG, $KEY).update($DATA)
      - pattern-not-inside: |
          function subkey(...) { ... }
      - pattern-not-inside: |
          function signPurposeBoundToken(...) { ... }
```

### B. Dynamic
1. **Cookie substitution:** start every secondary flow (`login/start`, `mfa/challenge`, `oauth/start`), capture each `Set-Cookie` value, replay it as `__Host-session` against `GET /api/me`. Assert `401`.
2. **Revoke-then-replay:** log in, log out (and separately: remove the member, disable the user), replay the old session cookie. Assert `401` within the documented SLO.
3. **Single-use:** replay a consumed `pending_mfa` token twice. Second use must fail.
4. **Unverified / non-authoritative OIDC claim:** the lab's mock IdP returns `{"email":"victim@example.com","email_verified":false}`, then `true` from an issuer not authoritative for that domain. Assert no session for `victim@example.com` in both cases.
5. **Cross-origin mutation:** `POST` with a valid cookie, `Origin: https://evil.example`, `Content-Type: text/plain`. Assert `403`. Repeat with `Origin: null`.

These run in the deterministic layer described in [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. Delete any general-purpose `signCookie(payload)` helper. `TokenPurpose` is a required literal-union parameter and the key is derived per purpose.
2. Every auth cookie has a server-side row; verification is `MAC valid AND row active`.
3. Centralize the cookie serializer and reject any auth cookie name not starting with `__Host-` in production builds.
4. Wire `assertSameOriginMutation` into the top-level router so endpoint authors cannot forget it.
5. Identity is `(iss, sub)`. Email is an attribute; account merging needs an authoritative issuer or local proof.
