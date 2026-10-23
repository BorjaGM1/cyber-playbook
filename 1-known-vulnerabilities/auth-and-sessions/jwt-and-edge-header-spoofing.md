# JWT & Edge Identity Header Spoofing

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-9.1.1`, `9.1.2`, `9.1.3`, `9.2.1`).
- **Mechanism:** Applications deployed behind an identity-aware reverse proxy or edge network (e.g., Cloudflare Access, AWS ALB OIDC, Envoy, Tailscale/ Pomerium) often receive both a convenience plain-text header (such as `Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, or `X-User-Id`) and a cryptographically signed JWT (`Cf-Access-Jwt-Assertion` or `CF_Authorization` cookie). When application code trusts the plain-text header without verifying the JWT signature—or verifies the JWT without pinning the algorithm (`alg`), issuer (`iss`), audience (`aud`), and key source—an attacker can impersonate any user by sending a single forged header or a token signed for a different service/tenant.
- **Why Happy-Path Tests Miss It:** E2E tests either mock the auth header in local development or pass a valid edge token. They rarely send a forged `Cf-Access-Authenticated-User-Email: ceo@company.com` header with **no** JWT assertion, or a valid JWT issued for a staging/sister application (`aud` mismatch) against production.

---

## 2. Where It Hides

- Edge Worker or Node/Rust middleware that reads `req.headers.get("cf-access-authenticated-user-email")` or `x-forwarded-email` as a fallback when no session cookie is present.
- Multi-service architectures sharing one Identity Provider (IdP) or JWKS endpoint where `aud` (Audience) is not validated, allowing a token issued for a low-privilege preview app to authenticate against the core production API.
- JWT verifiers that read the `alg` or `jku`/`x5u`/`kid` header dynamically before verifying the signature:
  - Accepting `alg: "none"`.
  - Allowing `HS256` signed with the server's public RSA/ECDSA key (`RS256` $\to$ `HS256` key-confusion attack).
  - Using an unvalidated `kid` parameter in a file path or SQL query, or fetching keys from an attacker-controlled `jku` URL.
- Origins reachable directly by IP or default platform hostname (`*.workers.dev`, `*.vercel.app`, `*.onrender.com`, `*.fly.dev`) that bypass the edge proxy entirely.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Edge/API Middleware)

```typescript
// VULNERABLE:
// 1. Trusts plain-text edge header without verifying the cryptographic JWT.
// 2. Decodes JWT payload via atob/base64 before signature verification.
// 3. Does not enforce algorithm allowlist, issuer, or audience (`aud`).
export async function resolveUserVulnerable(req: Request, env: Env): Promise<string | null> {
  // Fatal flaw 1: Any caller who hits the worker/origin directly or on an unprotected
  // route can spoof this header.
  const edgeEmail = req.headers.get("cf-access-authenticated-user-email");
  if (edgeEmail) {
    return edgeEmail.toLowerCase();
  }

  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  // Fatal flaw 2: Decoding payload without verifying signature or `aud`/`iss`/`exp`.
  const [, payloadB64] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  return payload.email ?? null;
}
```

### Hardened Pattern (TypeScript — Fail-Closed JWT Verification with `jose`)

```typescript
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

export interface VerifiedEdgePrincipal {
  readonly sub: string;
  readonly email: string;
}

// Cache the remote JWKS fetcher with a strict timeout and cooldown.
let jwksCache: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(certsUrl: string) {
  if (!jwksCache) {
    jwksCache = createRemoteJWKSet(new URL(certsUrl), {
      timeoutDuration: 3000,
      cooldownDuration: 30000,
    });
  }
  return jwksCache;
}

export async function verifyEdgeAccessJwt(
  req: Request,
  env: { ACCESS_TEAM_DOMAIN: string; ACCESS_POLICY_AUD: string }
): Promise<VerifiedEdgePrincipal | null> {
  // 1. Fail closed if the server itself is missing its audience or issuer config.
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_POLICY_AUD) {
    throw new Error("CRITICAL: Missing ACCESS_TEAM_DOMAIN or ACCESS_POLICY_AUD");
  }

  // 2. Read ONLY the cryptographic assertion header or __Host- / CF_Authorization cookie.
  //    NEVER read Cf-Access-Authenticated-User-Email or X-Forwarded-User as proof.
  const assertion =
    req.headers.get("cf-access-jwt-assertion") ??
    extractCookie(req.headers.get("cookie"), "CF_Authorization");

  if (!assertion) return null;

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  const certsUrl = `${issuer}/cdn-cgi/access/certs`;

  try {
    // 3. Enforce signature, explicit asymmetric algorithm allowlist, issuer,
    //    pinned audience (`aud`), expiration (`exp`), and not-before (`nbf`).
    const { payload } = await jwtVerify(assertion, getJwks(certsUrl), {
      algorithms: ["RS256", "ES256"],
      issuer,
      audience: env.ACCESS_POLICY_AUD,
      clockTolerance: "30s",
    });

    if (typeof payload.email !== "string" || !payload.email.includes("@") || typeof payload.sub !== "string") {
      return null;
    }

    return Object.freeze({
      sub: payload.sub,
      email: payload.email.trim().toLowerCase(),
    });
  } catch {
    // Any signature, exp, nbf, iss, or aud mismatch fails closed.
    return null;
  }
}
```

### Hardened Pattern (Rust — Explicit Header & Claim Verification)

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

    // 1. Strict algorithm allowlist — reject HS256, none, etc.
    match header.alg {
        Algorithm::RS256 | Algorithm::ES256 => {}
        _ => return Err("disallowed_jwt_algorithm"),
    }

    // 2. Match `kid` strictly against pre-fetched trusted JWKS (never use `kid` in SQL/paths).
    let kid = header.kid.as_deref().ok_or("missing_kid")?;
    let jwk = jwk_set.find(kid).ok_or("unknown_kid")?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| "invalid_jwk")?;

    // 3. Validate signature, exp, nbf, iss, and aud.
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

---

## 4. How to Discover It Automatically

### A. Static Code Search (AST / Ripgrep)
Run these checks across the repository to locate unverified header reads or weak JWT calls:

```bash
# 1. Flag direct reads of plain-text proxy identity headers:
rg -n -i 'cf-access-authenticated-user-email|x-forwarded-user|x-forwarded-email|x-authenticated-user|x-user-id' src/

# 2. Flag unsafe jwt.decode() calls that skip signature verification:
rg -n 'jwt\.decode\(|decodeJwt\(' src/

# 3. Verify every jwtVerify / jsonwebtoken::Validation call sets `algorithms`, `issuer`, and `audience`:
rg -n -C 8 'jwtVerify|Validation::new' src/
```

### B. Dynamic Attacker Harness (The 8-Case Token Spoofing Matrix)
Against every authenticated endpoint on the local target, fire the following 8 requests and assert that **all 8 return `401 Unauthorized`** (and never leak data or return `200`):

| Case | Request Mutation | Expected |
|------|------------------|----------|
| `T1` | Plain header `Cf-Access-Authenticated-User-Email: admin@target.tld` + **no** JWT header/cookie | `401` |
| `T2` | Plain header `X-Forwarded-User: admin@target.tld` + **no** JWT | `401` |
| `T3` | Valid JWT structure with header `{"alg":"none","typ":"JWT"}` and empty signature `header.payload.` | `401` |
| `T4` | Valid JWT signed by trusted key, but `aud` set to `"https://other-app.example.com"` | `401` |
| `T5` | Valid JWT signed by trusted key, but `iss` set to `"https://evil-idp.example.com"` | `401` |
| `T6` | Valid JWT signed by trusted key, but `exp` set to `now - 120s` | `401` |
| `T7` | Valid JWT signed by trusted key, but `nbf` set to `now + 3600s` | `401` |
| `T8` | Valid JWT with last byte of signature flipped (`signature[last] ^= 0x01`) | `401` |

---

## 5. How to Eliminate the Bug Class by Construction

1. **Private Constructor on `AuthenticatedActor`:** Export the `AuthenticatedActor` type from a single module (`src/server/auth/actor.ts` or `src/auth.rs`) with a private symbol/field so route handlers cannot construct one manually from request headers.
2. **Ban Identity Header Reads Outside Auth Verifier:** Add a CI lint rule (see [`../../baselines/pre-deploy-security-pipeline.md`](../../baselines/pre-deploy-security-pipeline.md)) that fails the build if `cf-access-authenticated-user-email` or `x-forwarded-user` appears anywhere in the codebase.
3. **Lock Down Origin Bypass:** Configure origin servers (Workers `workers_dev = false`, firewall IP/mTLS rules on VPS/containers) so requests cannot bypass the edge proxy, and still verify the edge JWT inside the application process on every request.
