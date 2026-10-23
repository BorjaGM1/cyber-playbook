# Dev Auth Bypasses, Loopback Host Parsing Traps & Fail-Closed Boot Assertions

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I5 — Minimal Blast Radius & Fail-Closed Boot` and `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-6.3.2`, `13.4.1`).
- **Mechanism:** Applications frequently include local-development ergonomics—such as an environment variable (`DEV_AUTH_BYPASS=1`, `DEV_USER_EMAIL=dev@example.com`, `ALLOW_INSECURE_DEV_LOGIN=true`) or a hostname check (`isLocalhost(req)`)—so developers and local test runners can exercise routes without setting up external OIDC or Cloudflare Access. Three catastrophic failure modes turn these helpers into unauthenticated production takeovers:
  1. **Silent Production Activation:** Someone copies `.env.example` into production/staging or deploys without setting `NODE_ENV=production`, leaving the dev-bypass path active on the public internet.
  2. **Loopback Host Parsing Traps (`127.0.0.1.attacker.com` / `localhost.evil.com`):** A developer writes `url.hostname.startsWith("127.0.0.1")` or `req.headers.get("host")?.includes("localhost")` to restrict a dev-login endpoint to local development. An attacker sets a wildcard DNS `A` record for `127.0.0.1.attacker.com` (or sends `Host: 127.0.0.1.attacker.com` to the server), satisfies `.startsWith("127.0.0.1")`, and triggers the dev-bypass in production.
  3. **Weak or Default Signing Secrets:** Falling back to `process.env.SESSION_SECRET ?? "dev-secret-change-me"` when an environment variable is accidentally omitted in production, allowing any attacker to forge HMAC session cookies offline.

---

## 2. Where It Hides

- Auth middleware fallback branches (`if (env.DEV_USER_EMAIL) return { email: env.DEV_USER_EMAIL }`).
- Seed / reset / test-impersonation routes (`/api/dev/login`, `/api/test/seed`, `/api/__test__/reset`) mounted unconditionally in the main router and guarded only by a runtime `Host` header check.
- Config loaders (`src/config.ts`, `src/env.ts`) that provide hardcoded default strings for `JWT_SECRET`, `SESSION_SECRET`, `WEBHOOK_SECRET`, or `INTERNAL_API_KEY`.
- Exposed `.git` or `.env` files in static asset directories or container build contexts (`ASVS v5.0.0-13.4.1`).

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — `.startsWith("127.0.0.1")` Host Trap + Default Secret Fallback)

```typescript
// VULNERABLE:
// 1. Falls back to a known string if SESSION_SECRET is unset!
export const SESSION_SECRET = process.env.SESSION_SECRET || "default-dev-secret-do-not-use";

// 2. `hostname.startsWith("127.0.0.1")` matches `127.0.0.1.evil.com`!
// 3. `DEV_BYPASS_EMAIL` is not rejected when running on a deployed server!
export function getDevBypassUserVulnerable(req: Request, env: Record<string, string | undefined>) {
  const url = new URL(req.url);
  const isLoopback =
    url.hostname.startsWith("127.0.0.1") ||
    url.hostname.includes("localhost");

  if (isLoopback && env.DEV_BYPASS_EMAIL) {
    return { email: env.DEV_BYPASS_EMAIL, role: "owner" };
  }
  return null;
}
```

### Hardened Pattern (TypeScript & Rust — Exact Loopback Parser + Fail-Closed Boot Assertions)

```typescript
const EXACT_LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Exact hostname equality check after URL parsing (strips port, lowercases).
 * NEVER matches `127.0.0.1.evil.com` or `evil-localhost.com`.
 */
export function isExactLoopbackHost(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    return EXACT_LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

export interface ProductionEnvConfig {
  readonly APP_ENV: "development" | "test" | "production";
  readonly SESSION_SECRET: string;
  readonly ACCESS_TEAM_DOMAIN?: string;
  readonly ACCESS_POLICY_AUD?: string;
  readonly DEV_BYPASS_EMAIL?: string;
}

/**
 * Call synchronously at process/worker startup BEFORE binding any port or handling requests.
 * Fails closed (`throw`) if any production security invariant is violated.
 */
export function assertSafeBootConfig(env: ProductionEnvConfig, requestUrl?: string): void {
  const isLocalOnly = requestUrl ? isExactLoopbackHost(requestUrl) : false;
  const isProd = env.APP_ENV === "production" || (requestUrl !== undefined && !isLocalOnly);

  // 1. Require ≥32 bytes (256 bits) of entropy on SESSION_SECRET in all environments,
  //    and reject known placeholder values:
  if (
    typeof env.SESSION_SECRET !== "string" ||
    Buffer.byteLength(env.SESSION_SECRET, "utf8") < 32 ||
    /default|change-me|secret|example|000000/i.test(env.SESSION_SECRET)
  ) {
    throw new Error("BOOT_ASSERTION_FAILED: SESSION_SECRET must be >= 32 high-entropy bytes");
  }

  // 2. If running in production (or serving any non-loopback host), forbid ALL dev bypass variables:
  if (isProd) {
    if (env.DEV_BYPASS_EMAIL) {
      throw new Error(
        "BOOT_ASSERTION_FAILED: DEV_BYPASS_EMAIL is set in a production or non-loopback environment!"
      );
    }
    if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_POLICY_AUD) {
      throw new Error(
        "BOOT_ASSERTION_FAILED: Production environment requires ACCESS_TEAM_DOMAIN and ACCESS_POLICY_AUD"
      );
    }
  }
}
```

### Hardened Pattern in Rust (Exact Loopback Hostname Check)

```rust
pub fn is_exact_loopback_host(host_header_or_authority: &str) -> bool {
    let trimmed = host_header_or_authority.trim().to_ascii_lowercase();
    // Strip optional `:port` for IPv4/localhost while preserving bracketed IPv6 `[::1]:8080`:
    let host_only = if let Some(rest) = trimmed.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ipv6, _port)) => ipv6,
            None => return false,
        }
    } else {
        trimmed.split(':').next().unwrap_or("")
    };

    matches!(host_only, "127.0.0.1" | "localhost" | "::1")
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Search for substring host checks (`startsWith("127.0.0.1")`, `includes("localhost")`):
rg -n '(startsWith|includes|indexOf)\s*\(\s*["\x27](127\.0\.0\.1|localhost)' src/

# 2. Search for fallback secrets (`SECRET ||`, `SECRET ??`):
rg -n 'SECRET\s*(\|\||\?\?)' src/

# 3. Search for any `DEV_` or `BYPASS` environment variable reads:
rg -n 'DEV_|BYPASS|SKIP_AUTH|MOCK_AUTH' src/
```

### B. Dynamic Attacker Test (Host-Header Spoofing & Boot Config Fault Injection)
1. **Loopback Host Spoofing Test:** Against the running server, send requests with:
   - `Host: 127.0.0.1.attacker.example`
   - `Host: localhost.attacker.example`
   - `Host: sub.localhost`
   - `X-Forwarded-Host: 127.0.0.1`
   Assert that zero dev-bypass branches activate and all unauthenticated requests return `401`.
2. **Boot Fault-Injection Unit Test:** Invoke `assertSafeBootConfig` in unit tests with `(APP_ENV="production", DEV_BYPASS_EMAIL="admin@x.com")` and with a non-loopback URL `https://app.example.com` + `DEV_BYPASS_EMAIL="admin@x.com"`. Assert both throw `BOOT_ASSERTION_FAILED`.
3. **Dotfile Exposure Probe (`ASVS v5.0.0-13.4.1`):** Request `GET /.git/HEAD`, `GET /.git/config`, `GET /.env`, `GET /.env.production`, and `GET /sourcemaps/index.js.map`. Assert `404` across all routes.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Strip Dev Routes at Build Time or Guard with Both `APP_ENV === "development"` AND `isExactLoopbackHost`:** Never rely on a single flag. Even if `DEV_BYPASS_EMAIL` is set, refuse to honor it unless **both** `APP_ENV === "development"` and `isExactLoopbackHost(req.url)` are true, and throw at boot if `DEV_BYPASS_EMAIL` is present on any non-loopback host.
2. **Zero Fallback Defaults for Secrets:** Parse all environment variables through a strict boot schema (`zod` / `envalid` / Rust config struct) with **no `.default()`** on cryptographic keys.
