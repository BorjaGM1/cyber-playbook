# Cookie Purpose Confusion, OIDC Unverified Emails & CSRF

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-3.3.1`, `3.5.1`, `3.5.2`, `7.2.4`).
- **Mechanism:** Multi-step authentication flows (OIDC login, email magic links, passkey/WebAuthn enrollment, MFA challenge, account linking) often issue temporary signed cookies (`pending_auth`, `mfa_pending`, `oauth_state`) using the same server `SESSION_SECRET` and HMAC helper as full `session` cookies. If the signing helper only signs `{ userId, email, exp }` without cryptographically binding the **cookie name and purpose** into the MAC input, an attacker who completes only step 1 of a flow (e.g., entering a victim's email or starting an OAuth/MFA flow) can copy the value of the `pending_auth` cookie into the `session` cookie header and gain full account access.
- **Secondary OIDC Mechanism (Unverified Email Account Takeover):** When an application links OAuth/OIDC logins to existing accounts by matching `claims.email` without verifying `claims.email_verified === true` (and checking whether the provider is authoritative for that domain), an attacker can register an unverified `victim@company.com` profile on a permissive IdP and take over the victim's existing account.

---

## 2. Where It Hides

- Generic `signCookie(value, secret)` / `verifyCookie(signedValue, secret)` utilities shared across session cookies, MFA challenge cookies, OAuth pending-link cookies, and password-reset cookies.
- OIDC callback handlers (`/api/auth/callback/:provider`) that run `SELECT * FROM users WHERE email = $1` and auto-merge the social identity without checking `email_verified === true`.
- Cookie setters that omit the `__Host-` prefix (`Secure; Path=/; HttpOnly; SameSite=Lax`, with no `Domain` attribute), allowing a compromised sibling subdomain (`blog.example.com`) to toss cookies onto `app.example.com`.
- State-changing `POST`/`PUT`/`DELETE` endpoints that rely on cookie authentication (`SameSite=Lax`) without verifying the `Origin` header or an anti-CSRF token, or worse, endpoints that mutate state on `GET`.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Shared HMAC Without Purpose Binding + Unsafe OIDC Merge)

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

// VULNERABLE: Signs payload without binding `purpose` or `cookieName`.
// A token signed for `pending_mfa` is 100% valid when pasted into the `session` cookie!
export function signTokenVulnerable(payload: object, secret: string): string {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

// VULNERABLE OIDC CALLBACK:
// Auto-links account by email without checking `email_verified === true`.
export async function handleOidcCallbackVulnerable(oidcProfile: { sub: string; email: string }) {
  const existingUser = await db.findUserByEmail(oidcProfile.email);
  if (existingUser) {
    // Attacker with unverified email on a 3rd-party IdP just hijacked existingUser!
    return signTokenVulnerable({ userId: existingUser.id }, process.env.SESSION_SECRET!);
  }
}
```

### Hardened Pattern (TypeScript — Domain-Separated Purpose Binding + `__Host-` Cookie + OIDC Guard)

```typescript
import { createHmac, timingSafeEqual } from "node:crypto";

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

export function signPurposeBoundToken<P extends TokenPurpose>(
  purpose: P,
  claims: Omit<PurposeBoundClaims<P>, "purpose">,
  secret: string
): string {
  const fullClaims: PurposeBoundClaims<P> = { ...claims, purpose };
  const payloadB64 = Buffer.from(JSON.stringify(fullClaims), "utf8").toString("base64url");
  // Domain separation: bind the purpose string directly into the HMAC input before the dot.
  const signingInput = `${purpose}.${payloadB64}`;
  const mac = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${payloadB64}.${mac}`;
}

export function verifyPurposeBoundToken<P extends TokenPurpose>(
  expectedPurpose: P,
  rawToken: string,
  secret: string,
  nowEpochSeconds = Math.floor(Date.now() / 1000)
): PurposeBoundClaims<P> | null {
  const parts = rawToken.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, providedMac] = parts;

  const signingInput = `${expectedPurpose}.${payloadB64}`;
  const expectedMac = createHmac("sha256", secret).update(signingInput).digest("base64url");

  const a = Buffer.from(providedMac, "utf8");
  const b = Buffer.from(expectedMac, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as PurposeBoundClaims<P>;
    if (parsed.purpose !== expectedPurpose) return null;
    if (typeof parsed.exp !== "number" || parsed.exp <= nowEpochSeconds) return null;
    if (typeof parsed.sub !== "string" || parsed.sub.length === 0) return null;
    return parsed;
  } catch {
    return null;
  }
}

// Hardened Cookie Header Builder (__Host- prefix enforces Secure, Path=/, and no Domain attribute)
export function buildHostSessionCookie(token: string, maxAgeSeconds: number): string {
  return `__Host-session=${token}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

// Hardened OIDC Account Resolution:
export function assertVerifiedOidcEmail(claims: {
  iss: string;
  sub: string;
  email?: string;
  email_verified?: boolean;
}): { email: string } {
  if (!claims.email || claims.email_verified !== true) {
    throw new Error("OIDC_EMAIL_NOT_VERIFIED: Refusing to authenticate or link unverified email");
  }
  return { email: claims.email.trim().toLowerCase() };
}
```

### Hardened CSRF / Origin Enforcement for Cookie-Authenticated State Changes

```typescript
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function assertSameOriginMutation(req: Request, allowedOrigins: ReadonlySet<string>): void {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return;

  // If the request carries a Cookie header, require an exact Origin match.
  if (req.headers.get("cookie")) {
    const origin = req.headers.get("origin");
    if (!origin || !allowedOrigins.has(origin)) {
      throw new Response(JSON.stringify({ error: "CSRF_ORIGIN_MISMATCH" }), {
        status: 403,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
  }
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Inspect all HMAC / cookie signing functions to check if purpose/cookie-name is bound:
rg -n 'createHmac|Hmac::<|CookieJar|Set-Cookie' src/

# 2. Check OIDC / OAuth callbacks for missing `email_verified` checks:
rg -n -C 10 'email_verified|id_token|userinfo' src/

# 3. Check if state-changing routes verify Origin / Sec-Fetch-Site when cookies are used:
rg -n 'headers\.get\(["']origin["']\)' src/
```

### B. Dynamic Attacker Test (Cross-Cookie Substitution & CSRF Matrix)
1. **Cookie Substitution Attack:** Trigger the start of every secondary flow (`POST /api/auth/login/start`, `POST /api/auth/mfa/challenge`, `GET /api/auth/oauth/start`). Capture every `Set-Cookie` value returned. Replay that raw value inside `Cookie: __Host-session=<captured_value>` against `GET /api/me`. Assert `401 Unauthorized`.
2. **Unverified OIDC Claim Test:** Against the local mock OIDC provider in the lab harness, return an ID token with `{ "email": "victim@example.com", "email_verified": false }`. Assert that login/linking fails with `400`/`403` and does not issue a session for `victim@example.com`.
3. **Cross-Origin Mutation Test:** Send a `POST` request with a valid session cookie and `Origin: https://evil.example` (plus `Content-Type: text/plain` or `application/x-www-form-urlencoded`). Assert `403 Forbidden`.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Make `TokenPurpose` a Required Generic Parameter:** Delete any general-purpose `signCookie(payload)` helper. Every call to `signPurposeBoundToken` and `verifyPurposeBoundToken` must pass a compile-time literal from the `TokenPurpose` union, and the HMAC input must prefix `${purpose}.` before the payload bytes.
2. **Enforce `__Host-` Prefix in Cookie Helpers:** Have your central cookie serializer reject any auth cookie name that does not start with `__Host-` in production builds.
3. **Central Router Origin Gate:** Wire `assertSameOriginMutation` into the top-level HTTP router so individual endpoint authors never have to remember CSRF checks.
