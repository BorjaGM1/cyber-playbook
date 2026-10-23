# JWT & Edge Identity Header Spoofing

> **Invariant:** `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-9.1.1`, `9.1.2`, `9.1.3`, `9.2.1`).
> Related: [`nextjs-and-edge-specifics.md`](nextjs-and-edge-specifics.md) · [`../infra-and-supply-chain/surface-separation-and-destructive-gates.md`](../infra-and-supply-chain/surface-separation-and-destructive-gates.md) · [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)

---

## 1. Attack Transcript

The app sits behind an identity-aware proxy. The proxy adds `Cf-Access-Authenticated-User-Email` after authenticating. The attacker reaches the origin directly (the platform hostname) and sets the header themselves.

```http
GET /api/admin/users HTTP/1.1
Host: my-service.example-workers.dev
Cf-Access-Authenticated-User-Email: ceo@company.com

HTTP/1.1 200 OK
[{"id":"u_1","email":"ceo@company.com","role":"owner"}, ...]
```

Variant: a JWT legitimately issued for a sister application (staging, preview) is replayed against production because `aud` is never checked.

```http
GET /api/me HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...   (aud = "preview-app", valid signature, same IdP)

HTTP/1.1 200 OK
{"email":"alice@company.com","role":"owner"}
```

---

## 2. Spot the Bug

Two fatal problems and several quieter ones.

```typescript
export async function resolveUser(req: Request, env: Env): Promise<string | null> {
  const edgeEmail = req.headers.get("cf-access-authenticated-user-email");
  if (edgeEmail) {
    return edgeEmail.toLowerCase();
  }

  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const [, payloadB64] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  return payload.email ?? null;
}
```

---

## 3. Invariant Violated & Mechanism

Applications behind an identity-aware proxy (Cloudflare Access, AWS ALB OIDC, Envoy, Tailscale/Pomerium) receive both a convenience plain-text header (`Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, `X-User-Id`) and a signed JWT (`Cf-Access-Jwt-Assertion` or the `CF_Authorization` cookie). Trusting the plain header, or verifying the JWT without pinning `alg`, `iss`, `aud` and the key source, lets one forged header or one token minted for another service impersonate anyone.

Why happy-path tests pass: E2E tests either mock the header locally or send a real edge token. Nobody sends a forged header with no JWT, or a valid JWT for a sister app.

Where it hides:
- middleware that reads `cf-access-authenticated-user-email` / `x-forwarded-email` as a fallback when no cookie exists;
- multi-service setups sharing one IdP or JWKS where `aud` is unchecked;
- verifiers that read `alg`, `jku`, `x5u` or `kid` before verifying the signature (accepting `alg: none`, `RS256 -> HS256` key confusion, `kid` in a path or SQL, attacker-hosted `jku`);
- origins reachable directly by default platform hostname (`*.workers.dev`, `*.vercel.app`, `*.onrender.com`, `*.fly.dev`) or IP, bypassing the proxy entirely;
- **edge-vs-origin path differentials** (section 5): the proxy's policy and the origin's router disagree on what path a request is for.

---

## 4. Hardened Pattern

### TypeScript: fail-closed JWT verification with `jose`

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

export interface VerifiedEdgePrincipal {
  readonly sub: string;
  readonly email: string;
}

let jwksCache: ReturnType<typeof createRemoteJWKSet> | null = null;
function getJwks(certsUrl: string) {
  if (!jwksCache) {
    jwksCache = createRemoteJWKSet(new URL(certsUrl), { timeoutDuration: 3000, cooldownDuration: 30000 });
  }
  return jwksCache;
}

/** Minimal cookie reader: exact name match, first occurrence wins, no decoding surprises. */
export function extractCookie(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      const value = part.slice(idx + 1).trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

export async function verifyEdgeAccessJwt(
  req: Request,
  env: { ACCESS_TEAM_DOMAIN: string; ACCESS_POLICY_AUD: string }
): Promise<VerifiedEdgePrincipal | null> {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_POLICY_AUD) {
    throw new Error("CRITICAL: Missing ACCESS_TEAM_DOMAIN or ACCESS_POLICY_AUD");
  }

  // Read ONLY the cryptographic assertion. Never treat the plain identity headers as proof.
  const assertion =
    req.headers.get("cf-access-jwt-assertion") ??
    extractCookie(req.headers.get("cookie"), "CF_Authorization");
  if (!assertion) return null;

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  try {
    const { payload } = await jwtVerify(assertion, getJwks(`${issuer}/cdn-cgi/access/certs`), {
      algorithms: ["RS256", "ES256"],
      issuer,
      audience: env.ACCESS_POLICY_AUD,
      clockTolerance: "30s",
    });
    if (typeof payload.email !== "string" || !payload.email.includes("@") || typeof payload.sub !== "string") {
      return null; // service tokens carry no email: route them through the machine-key tier instead
    }
    return Object.freeze({ sub: payload.sub, email: payload.email.trim().toLowerCase() });
  } catch {
    return null;
  }
}
```

### Rust: explicit header and claim verification

```rust
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub email: String,
    pub aud: Vec<String>,
    pub iss: String,
    pub exp: usize,
    pub nbf: Option<usize>,
}

pub fn verify_access_jwt(
    raw_token: &str,
    expected_issuer: &str,
    expected_audience: &str,
    jwk_set: &jsonwebtoken::jwk::JwkSet,
) -> Result<AccessClaims, &'static str> {
    let header = decode_header(raw_token).map_err(|_| "invalid_jwt_header")?;

    match header.alg {
        Algorithm::RS256 | Algorithm::ES256 => {}
        _ => return Err("disallowed_jwt_algorithm"),
    }

    let kid = header.kid.as_deref().ok_or("missing_kid")?;
    let jwk = jwk_set.find(kid).ok_or("unknown_kid")?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| "invalid_jwk")?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);

    let token_data = decode::<AccessClaims>(raw_token, &decoding_key, &validation)
        .map_err(|_| "jwt_verification_failed")?;

    if token_data.claims.email.trim().is_empty() {
        return Err("empty_email_claim");
    }
    Ok(token_data.claims)
}
```

### Canonical-path guard (edge vs origin)

Reject any request whose path is not already in canonical form *before* routing, so the edge policy, the router and the authorization layer all see the same string.

```typescript
const NON_CANONICAL = /(%2e|%2f|%5c|%00|%25|;|\\)/i;

export function assertCanonicalPath(url: URL): void {
  const p = url.pathname;
  if (NON_CANONICAL.test(p) || p.includes("//") || /\/\.{1,2}(\/|$)/.test(p)) {
    throw new Response(JSON.stringify({ error: "Not Found" }), {
      status: 404,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
}
```

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **Edge-vs-origin path differentials.** An Access policy covering `/admin/*` is bypassed if the origin treats `/admin/..;/x`, `//admin/x`, `/ADMIN/x`, `/admin%2fx` or `/admin/./x` as the admin route while the edge sees a different path. The JWT check at the origin saves you only if the origin verifies the assertion on every route. Never let the edge's path policy be the *only* thing between a path and a handler; authorize in the app, using the same normalized path as the router. Also compare `Host` handling: trailing dots (`example.com.`), mixed case and `X-Forwarded-Host` overrides.
- **`aud` is per application, not per IdP.** A shared `aud` across preview, staging and production recreates the sister-app replay.
- **Direct origin access.** Disable the default platform hostname (`workers_dev = false`) or firewall the origin to the proxy; keep verifying the JWT anyway.
- **JWKS fetch failure** must fail closed, with cache keyed per issuer, never a fallback to unsigned headers.
- **Service tokens** have no `email` claim; map them to a machine tier explicitly ([`api-key-lifecycle-and-privilege-escalation.md`](api-key-lifecycle-and-privilege-escalation.md)) instead of loosening the human check.
- **Framework-level skips.** Some frameworks have had headers that skip middleware entirely; see [`nextjs-and-edge-specifics.md`](nextjs-and-edge-specifics.md).

---

## 6. How to Discover It Automatically

### A. Static (AST / ripgrep)
```bash
# 1. Direct reads of plain-text proxy identity headers:
rg -n -i 'cf-access-authenticated-user-email|x-forwarded-user|x-forwarded-email|x-authenticated-user|x-user-id' src/

# 2. Unsafe jwt.decode() calls that skip signature verification:
rg -n 'jwt\.decode\(|decodeJwt\(' src/

# 3. Every jwtVerify / jsonwebtoken::Validation call sets algorithms, issuer and audience:
rg -n -C 8 'jwtVerify|Validation::new' src/
```

```yaml
rules:
  - id: jwtverify-missing-pins
    languages: [typescript]
    severity: ERROR
    message: jwtVerify must pin algorithms, issuer and audience.
    patterns:
      - pattern: jwtVerify($T, $K, $OPTS)
      - pattern-not: jwtVerify($T, $K, { ..., algorithms: $A, ..., issuer: $I, ..., audience: $U, ... })
```

### B. Dynamic: the 8-case token spoofing matrix (+ path cases)
Against every authenticated endpoint on the local target, **all must return `401`** (or `404` for the path cases) and never leak data:

| Case | Request mutation | Expected |
|------|------------------|----------|
| `T1` | Plain header `Cf-Access-Authenticated-User-Email: admin@target.tld` + **no** JWT | `401` |
| `T2` | Plain header `X-Forwarded-User: admin@target.tld` + **no** JWT | `401` |
| `T3` | JWT header `{"alg":"none","typ":"JWT"}`, empty signature `header.payload.` | `401` |
| `T4` | Valid JWT from a trusted key, `aud` = `"https://other-app.example.com"` | `401` |
| `T5` | Valid JWT from a trusted key, `iss` = `"https://evil-idp.example.com"` | `401` |
| `T6` | Valid JWT, `exp` = `now - 120s` | `401` |
| `T7` | Valid JWT, `nbf` = `now + 3600s` | `401` |
| `T8` | Valid JWT with last signature byte flipped (`sig[last] ^= 0x01`) | `401` |
| `P1` | Protected path with `//`, `/./`, `;x`, `%2e%2e`, `%2f`, upper-case variants | `404`, not a handler response |
| `P2` | Request to the platform hostname / bare IP bypassing the proxy | connection refused or `401` |

These are emitted by [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Private constructor on `AuthenticatedActor`:** export it from a single module (`src/server/auth/actor.ts` / `src/auth.rs`) so handlers cannot build one from request headers.
2. **Ban identity-header reads outside the verifier:** a CI lint fails if `cf-access-authenticated-user-email` or `x-forwarded-user` appears anywhere else (see [`../../baselines/pre-deploy-security-pipeline.md`](../../baselines/pre-deploy-security-pipeline.md)).
3. **Lock down origin bypass:** `workers_dev = false`, firewall/mTLS to the proxy, and still verify the edge JWT in-process on every request.
4. **Canonical path in, canonical path out:** call `assertCanonicalPath` before routing and authorize by the router's matched route, not a re-parsed string.
