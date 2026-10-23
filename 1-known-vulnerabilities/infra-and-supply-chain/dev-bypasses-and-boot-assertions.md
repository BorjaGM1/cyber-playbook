# Dev Auth Bypasses, Loopback Host Parsing Traps & Fail-Closed Boot Assertions

> **Invariants:** `I5 — Minimal Blast Radius & Fail-Closed Boot` and `I1 — Authentic Identity & Purpose Binding` (OWASP ASVS `v5.0.0-6.3.2`, `13.4.1`).
> Related: [`surface-separation-and-destructive-gates.md`](surface-separation-and-destructive-gates.md) · [`../auth-and-sessions/jwt-and-edge-header-spoofing.md`](../auth-and-sessions/jwt-and-edge-header-spoofing.md) · [`../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md)

---

## 1. Attack Transcript

```http
GET /api/me HTTP/1.1
Host: 127.0.0.1.attacker.example
Connection: close

HTTP/1.1 200 OK
{"email":"dev@example.com","role":"owner"}
```

The attacker did not need DNS tricks at all. The `Host` header is chosen by the client:

```http
GET /api/me HTTP/1.1
Host: localhost

HTTP/1.1 200 OK
{"email":"dev@example.com","role":"owner"}
```

And the forged-cookie variant, where a missing production secret fell back to a constant:

```bash
$ node -e 'const c=require("crypto");const d=Buffer.from(JSON.stringify({userId:"u_1",exp:9999999999})).toString("base64url");console.log(d+"."+c.createHmac("sha256","default-dev-secret-do-not-use").update(d).digest("base64url"))'
eyJ1c2VySWQiOiJ1XzEiLCJleHAiOjk5OTk5OTk5OTl9.L0m...
$ curl -H 'Cookie: session=eyJ1c2VySWQiOiJ1XzEiLCJleHAiOjk5OTk5OTk5OTl9.L0m...' https://app.example.com/api/me
{"id":"u_1","role":"owner"}
```

---

## 2. Spot the Bug

Two snippets. Find at least four problems.

```typescript
export const SESSION_SECRET = process.env.SESSION_SECRET || "default-dev-secret-do-not-use";

export function getDevBypassUser(req: Request, env: Record<string, string | undefined>) {
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

```typescript
export interface ProductionEnvConfig {
  readonly APP_ENV: "development" | "test" | "production";
  readonly SESSION_SECRET: string;
  readonly ACCESS_TEAM_DOMAIN?: string;
  readonly ACCESS_POLICY_AUD?: string;
  readonly DEV_BYPASS_EMAIL?: string;
}

export function assertSafeBootConfig(env: ProductionEnvConfig, requestUrl?: string): void {
  const isLocalOnly = requestUrl ? isExactLoopbackHost(requestUrl) : false;
  const isProd = env.APP_ENV === "production" || (requestUrl !== undefined && !isLocalOnly);

  if (Buffer.byteLength(env.SESSION_SECRET, "utf8") < 32) {
    throw new Error("BOOT_ASSERTION_FAILED: SESSION_SECRET too short");
  }
  if (isProd && env.DEV_BYPASS_EMAIL) {
    throw new Error("BOOT_ASSERTION_FAILED: DEV_BYPASS_EMAIL set in production");
  }
}
```

---

## 3. Invariant Violated & Mechanism

Local ergonomics (`DEV_AUTH_BYPASS=1`, `DEV_USER_EMAIL`, an `isLocalhost(req)` helper) become unauthenticated production takeovers in five ways:

1. **Silent production activation.** `.env.example` is copied to production, or the service is deployed without `APP_ENV=production`. Any guard that is *enabled by the flag whose absence is the failure* fails open. In the second snippet, `assertSafeBootConfig` is called at boot with no `requestUrl`, so `isProd` is true only if `APP_ENV === "production"`. An unset or misspelled `APP_ENV` (`prod`, `Production`) skips the dev-bypass check entirely.
2. **Loopback host parsing traps.** `hostname.startsWith("127.0.0.1")` matches `127.0.0.1.attacker.example`; `includes("localhost")` matches `evil-localhost.com`.
3. **The `Host` header is not a trust anchor at all.** Even an *exact* loopback check on `Host`, `X-Forwarded-Host` or `req.url` (usually derived from `Host`) is attacker-controlled: `Host: localhost` passes it. Exact parsing fixes the substring bug and leaves the real bug. The trustworthy facts are the **peer socket address** and the **interface the process is bound to**.
4. **Reverse proxy on the same host.** If a proxy (nginx, a sidecar, a tunnel agent) terminates traffic and connects to the app over `127.0.0.1`, *every* internet request has a loopback peer. A peer-address check then also passes. Dev bypass must therefore be impossible when the process is reachable via any proxy.
5. **Weak or default signing secrets.** `process.env.SESSION_SECRET ?? "dev-secret-change-me"` lets anyone forge session cookies offline.

Why happy-path tests pass: they run locally, where everything is loopback and the secret fallback works.

Where it hides: auth middleware fallback branches; `/api/dev/login`, `/api/test/seed`, `/api/__test__/reset` mounted unconditionally; config loaders with `.default()` on keys; exposed `.git` / `.env` (`ASVS v5.0.0-13.4.1`).

---

## 4. Hardened Pattern

Principles: **default-deny** (anything that is not exactly `development` or `test` is production), **dev code is absent from production builds**, **peer and bind address are the anchors**, and **boot takes no request**.

### 4.1 Environment resolution and boot assertion (TypeScript)

```typescript
export type AppEnv = "development" | "test" | "production";

/** Unset, empty, misspelled or unknown values are treated as production. */
export function resolveAppEnv(raw: string | undefined): AppEnv {
  return raw === "development" || raw === "test" ? raw : "production";
}

export interface BootInputs {
  readonly APP_ENV?: string;
  readonly SESSION_SECRET?: string;
  readonly ACCESS_TEAM_DOMAIN?: string;
  readonly ACCESS_POLICY_AUD?: string;
  readonly BIND_HOST?: string;     // interface the listener binds to
  readonly TRUST_PROXY?: string;
  readonly [key: string]: string | undefined;
}

const LOOPBACK_BIND = new Set(["127.0.0.1", "::1", "localhost"]);
const PLACEHOLDER = /default|change-?me|example|placeholder|password|000000/i;

function distinctChars(s: string): number {
  return new Set(s).size;
}

/**
 * Call synchronously at startup BEFORE binding a port. Takes no request, no URL.
 * Returns the resolved env so callers cannot re-derive it differently.
 */
export function assertSafeBootConfig(env: BootInputs): AppEnv {
  const appEnv = resolveAppEnv(env.APP_ENV);

  // 1. Secret quality in every environment: length, placeholders, a crude entropy floor.
  const secret = env.SESSION_SECRET;
  if (
    typeof secret !== "string" ||
    Buffer.byteLength(secret, "utf8") < 32 ||
    distinctChars(secret) < 12 ||
    PLACEHOLDER.test(secret)
  ) {
    throw new Error("BOOT_ASSERTION_FAILED: SESSION_SECRET must be >= 32 bytes of generated randomness");
  }

  const devKeys = Object.keys(env).filter((k) => /^(DEV_|BYPASS_|SKIP_AUTH|MOCK_AUTH|ALLOW_INSECURE)/.test(k) && env[k]);

  if (appEnv === "production") {
    // 2. Production forbids every dev knob and requires the real identity configuration.
    if (devKeys.length > 0) {
      throw new Error(`BOOT_ASSERTION_FAILED: dev variables set in production: ${devKeys.join(", ")}`);
    }
    if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_POLICY_AUD) {
      throw new Error("BOOT_ASSERTION_FAILED: production requires ACCESS_TEAM_DOMAIN and ACCESS_POLICY_AUD");
    }
  } else if (devKeys.length > 0) {
    // 3. Dev bypass is allowed only when the listener cannot be reached off-box
    //    and no proxy is configured that would make remote traffic look local.
    if (!env.BIND_HOST || !LOOPBACK_BIND.has(env.BIND_HOST)) {
      throw new Error("BOOT_ASSERTION_FAILED: dev bypass requires BIND_HOST to be a loopback address");
    }
    if (env.TRUST_PROXY) {
      throw new Error("BOOT_ASSERTION_FAILED: dev bypass is incompatible with TRUST_PROXY");
    }
  }
  return appEnv;
}
```

### 4.2 Dev routes are not in the production artifact

Two entrypoints, with the dev module imported only by the dev one. The bundler never sees it in the production build.

```typescript
// main.prod.ts   (the only entrypoint the production image runs)
import { assertSafeBootConfig } from "./boot";
import { buildRouter } from "./router";            // contains NO dev login/seed routes
assertSafeBootConfig(process.env);
startServer(buildRouter());

// main.dev.ts    (never copied into the production image)
import { assertSafeBootConfig } from "./boot";
import { buildRouter } from "./router";
import { devRoutes } from "./dev/routes";           // /api/dev/login, /api/test/seed ...
if (assertSafeBootConfig(process.env) === "production") throw new Error("main.dev.ts refused in production");
startServer(buildRouter({ extra: devRoutes() }));
```

CI asserts the production bundle contains no string from `dev/` (e.g. `/api/dev/login`).

### 4.3 Request-time check uses the socket, not headers (Rust)

```rust
use std::net::SocketAddr;

/// `peer` is the TCP peer of the accepted connection; `local` is the address it arrived on.
/// Both come from the socket, never from a request header.
/// Only callable when boot already proved: APP_ENV==development, loopback bind, no trusted proxy.
pub fn dev_bypass_permitted(peer: SocketAddr, local: SocketAddr) -> bool {
    peer.ip().is_loopback() && local.ip().is_loopback()
}

/// Cosmetic only (log lines, redirects). NEVER an authorization decision: the Host header is client-chosen.
pub fn is_exact_loopback_host(host_header_or_authority: &str) -> bool {
    let trimmed = host_header_or_authority.trim().to_ascii_lowercase();
    if trimmed == "::1" {
        return true; // bare IPv6 literal without brackets or port
    }
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

### 4.4 Secrets parse with no defaults

Parse env through a strict schema (`zod`, `envalid`, a Rust config struct) with **no `.default()` on cryptographic keys**. A missing secret is a boot failure, not a fallback.

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **A secret that passes the heuristic can still be weak.** `distinctChars` and length are floors, not entropy. Generate secrets (`openssl rand -base64 48`) and reject anything that was not generated.
- **Sidecar/tunnel agents on the same host** (including a local tunnel started later by a developer) make a loopback bind reachable remotely. Dev mode refuses `TRUST_PROXY`, but a tunnel agent does not set it. Keep dev bypass off for anything that can be reached through a tunnel; prefer a signed local-only dev token over a bypass flag.
- **`APP_ENV=test` in CI deploy previews** is "non-production" by this rule. Treat any internet-reachable preview as production for this check: set `APP_ENV=production` there and use real identity.
- **Containers:** binding `0.0.0.0` inside a container is normal. Dev bypass in containers is therefore unsafe even with a "loopback" peer check, because port-mapping makes remote peers appear as the gateway. Do not enable dev bypass in containers.
- **Forgotten `.git`/`.env`/source maps** in the static root remain a separate, direct leak (ASVS `13.4.1`).
- **Config interactions** (`TRUST_PROXY` + a client-IP allowlist, an enforce flag + a monitor-only flag) need their own pairwise assertions; see [`../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md`](../../2-discovery-and-attacker-methods/attack-surface-and-config-interaction-audit.md).

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. Substring host checks (startsWith/includes/indexOf on 127.0.0.1 / localhost):
rg -n '(startsWith|includes|indexOf)\s*\(\s*["\x27](127\.0\.0\.1|localhost)' src/

# 2. Fallback secrets (SECRET || / SECRET ??):
rg -n 'SECRET\s*(\|\||\?\?)' src/

# 3. Any DEV_ / BYPASS / SKIP_AUTH / MOCK_AUTH variable reads:
rg -n 'DEV_|BYPASS|SKIP_AUTH|MOCK_AUTH' src/

# 4. Authorization decisions that read Host-derived values:
rg -n -C 3 'headers\.get\(["\x27](host|x-forwarded-host)["\x27]\)' src/
```

```yaml
rules:
  - id: authz-decision-from-host-header
    languages: [typescript]
    severity: ERROR
    message: Host / X-Forwarded-Host / req.url hostname must never gate authentication or dev paths.
    pattern-either:
      - pattern: if ($X.hostname.$M(...)) { ... }
      - pattern: if (isExactLoopbackHost($REQ.url)) { ... }
```

### B. Dynamic
1. **Host spoofing:** send `Host: 127.0.0.1.attacker.example`, `Host: localhost`, `Host: sub.localhost`, `X-Forwarded-Host: 127.0.0.1`. Zero dev branches activate; unauthenticated requests return `401`.
2. **Boot fault injection (unit tests):** call `assertSafeBootConfig` with `(APP_ENV unset, DEV_BYPASS_EMAIL set)`, `(APP_ENV="prod", DEV_BYPASS_EMAIL set)`, `(APP_ENV="development", DEV_BYPASS_EMAIL set, BIND_HOST="0.0.0.0")`, `(APP_ENV="development", DEV_BYPASS_EMAIL set, TRUST_PROXY="1")`, and a placeholder secret. All must throw.
3. **Same-host proxy test:** run the production build behind a local reverse proxy; assert dev routes return `404` and bypass stays off.
4. **Bundle scan:** grep the production artifact for dev route strings.
5. **Dotfile probe (`v5.0.0-13.4.1`):** `GET /.git/HEAD`, `/.git/config`, `/.env`, `/.env.production`, `/sourcemaps/index.js.map` all return `404`.

---

## 7. How to Eliminate the Bug Class by Construction

1. **Default-deny environment resolution.** Only the exact strings `development` and `test` relax anything. Everything else is production.
2. **Dev code does not ship.** Separate entrypoints and a bundle scan; no runtime flag decides whether dev routes exist.
3. **Socket and bind address are the only locality signals.** Headers never are.
4. **No fallback defaults on secrets,** enforced by a boot schema.
5. **Boot takes no request.** `assertSafeBootConfig(env)` returns the resolved environment, and nothing else re-derives it.
