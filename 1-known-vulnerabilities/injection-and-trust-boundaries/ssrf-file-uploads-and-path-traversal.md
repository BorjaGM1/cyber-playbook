# SSRF, DNS Rebinding, Malicious File Uploads & Path Traversal

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I4 — Context-Safe Boundary Parsing` (OWASP ASVS `v5.0.0-1.2.2`, `3.2.1`, `5.2.1`, `5.2.2`, `5.3.1`, `5.3.2`).
- **Mechanism:**
  1. **Server-Side Request Forgery (SSRF) & DNS Rebinding:** Any feature that fetches a user-supplied URL on the backend (webhook testers, link previewers / OpenGraph scrapers, avatar URL importers, PDF generators, MCP fetch tools) allows an attacker to probe internal services (`http://127.0.0.1:8080/admin`, Redis, internal Kubernetes services) or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`). Naive URL checks (`!url.hostname.includes("127.0.0.1")`) are bypassed via alternate IP encodings (`http://2130706433/`, `http://0x7f000001/`, IPv6 `[::ffff:127.0.0.1]`), open HTTP `302` redirects to internal IPs, or **DNS rebinding** (where `attacker.com` resolves to a public IP `1.2.3.4` during the validation DNS lookup, and resolves to `127.0.0.1` or `169.254.169.254` 10ms later when `fetch()` opens the TCP socket).
  2. **Polyglot / Active File Uploads & Path Traversal:** Accepting an uploaded file based solely on the client's `Content-Type` header or filename extension, storing it under a path derived from `file.name` (`../../../etc/cron.d/`), or serving uploaded `.svg`, `.html`, or `.xml` files inline from the application origin so embedded `<script>` executes in the victim's browser session.

---

## 2. Where It Hides

- Outbound webhook configuration & test-delivery endpoints (`POST /api/webhooks/test`).
- Link unfurling, RSS/sitemap importers, image proxy routes (`/api/image-proxy?url=...`), and headless browser PDF/screenshot workers.
- File upload handlers (`POST /api/upload`) that write to local disk (`path.join(UPLOAD_DIR, file.name)`) or copy the client-provided `file.type` into S3/R2 metadata.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Naive SSRF String Check + Unsafe Path Join)

```typescript
import path from "node:path";
import fs from "node:fs/promises";

// VULNERABLE SSRF:
// Bypassed by:
// - http://169.254.169.254/ (cloud metadata)
// - http://[::1]:3000/ or http://2130706433/ (decimal IPv4 for 127.0.0.1)
// - 302 redirect from https://evil.com/redirect -> http://127.0.0.1:8080/
// - DNS rebinding on evil.com
export async function fetchPreviewVulnerable(targetUrl: string) {
  const parsed = new URL(targetUrl);
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
    throw new Error("Blocked host");
  }
  return fetch(targetUrl);
}

// VULNERABLE FILE WRITE:
// If userFilename is "../../src/server.js" or "/etc/passwd", path.resolve escapes or overwrites!
export async function saveUploadVulnerable(userFilename: string, bytes: Uint8Array) {
  const dest = path.join("/var/app/uploads", userFilename);
  await fs.writeFile(dest, bytes);
}
```

### Hardened Pattern 1: SSRF-Safe Fetcher (DNS Resolution + Private IP Block + Redirect Disable)

```typescript
import dns from "node:dns/promises";
import net from "node:net";

/**
 * Returns true ONLY if the IPv4 or IPv6 address is a globally routable public unicast address.
 * Blocks loopback, RFC1918 private, link-local (169.254.0.0/16), CGNAT, multicast, and IPv4-mapped IPv6.
 */
export function isPublicRoutableIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return false;                      // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
    if (a === 169 && b === 254) return false;                                // 169.254.0.0/16 (Cloud Metadata / Link-Local)
    if (a === 172 && b >= 16 && b <= 31) return false;                       // 172.16.0.0/12
    if (a === 192 && b === 168) return false;                                // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return false;                      // 100.64.0.0/10 (CGNAT / Tailscale)
    if (a >= 224) return false;                                              // Multicast & Reserved
    return true;
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === "::1" || normalized === "::") return false;
    if (normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd")) {
      return false; // Link-local (fe80::/10) and Unique Local (fc00::/7)
    }
    if (normalized.includes("::ffff:")) {
      // IPv4-mapped IPv6 address (e.g., ::ffff:127.0.0.1)
      const ipv4Part = normalized.split("::ffff:")[1];
      return ipv4Part ? isPublicRoutableIp(ipv4Part) : false;
    }
    return true;
  }

  return false;
}

export async function safeExternalFetch(rawUrl: string, timeoutMs = 5000): Promise<Response> {
  const parsed = new URL(rawUrl);

  // 1. Strict scheme and port allowlist:
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("SSRF_BLOCKED_SCHEME");
  }
  if (parsed.username || parsed.password) {
    throw new Error("SSRF_BLOCKED_CREDENTIALS_IN_URL");
  }
  const allowedPorts = new Set(["", "80", "443"]);
  if (!allowedPorts.has(parsed.port)) {
    throw new Error("SSRF_BLOCKED_PORT");
  }

  // 2. Resolve all A/AAAA records and verify EVERY resolved IP is public:
  const records = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
  if (records.length === 0) {
    throw new Error("SSRF_DNS_RESOLUTION_EMPTY");
  }
  for (const record of records) {
    if (!isPublicRoutableIp(record.address)) {
      throw new Error(`SSRF_BLOCKED_PRIVATE_IP: ${record.address}`);
    }
  }

  // 3. Enforce `redirect: "error"` (or manually re-validate every Location hop) and strict timeout:
  //    Note: In Node.js custom agents (undici Agent), also pass a custom `lookup` callback that returns
  //    `records[0].address` directly so the socket connects to the exact validated IP (defeating DNS rebinding).
  return fetch(parsed.toString(), {
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
}
```

### Hardened Pattern 2: Magic-Byte Validation & UUID-Only Path Resolution

```typescript
import path from "node:path";
import crypto from "node:crypto";

const ALLOWED_IMAGE_MAGIC: ReadonlyArray<{
  ext: string;
  mime: string;
  matches: (buf: Uint8Array) => boolean;
}> = [
  {
    ext: "png",
    mime: "image/png",
    matches: (b) => b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47,
  },
  {
    ext: "jpg",
    mime: "image/jpeg",
    matches: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  },
  {
    ext: "webp",
    mime: "image/webp",
    matches: (b) =>
      b.length >= 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50,
  },
];

export function validateUploadAndBuildSafePath(
  baseDir: string,
  tenantId: string,
  bytes: Uint8Array,
  maxBytes = 5 * 1024 * 1024
): { diskPath: string; contentType: string } {
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) {
    throw new Error("UPLOAD_SIZE_OUT_OF_BOUNDS");
  }

  // 1. Verify magic bytes (NEVER allow SVG/HTML in image uploads, and never trust client Content-Type):
  const matched = ALLOWED_IMAGE_MAGIC.find((m) => m.matches(bytes));
  if (!matched) {
    throw new Error("UPLOAD_MAGIC_BYTES_REJECTED");
  }

  // 2. Construct storage path strictly from internal UUIDs (ASVS v5.0.0-5.3.2):
  const fileUuid = crypto.randomUUID();
  const resolvedBase = path.resolve(baseDir);
  const candidatePath = path.resolve(resolvedBase, tenantId, `${fileUuid}.${matched.ext}`);

  // 3. Canonical prefix assertion (defeats any path traversal if tenantId were ever malformed):
  if (!candidatePath.startsWith(resolvedBase + path.sep)) {
    throw new Error("PATH_TRAVERSAL_DETECTED");
  }

  return { diskPath: candidatePath, contentType: matched.mime };
}
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Find all server-side `fetch(`, `axios(`, or `reqwest` calls where the URL is not a static literal:
rg -n 'fetch\(\s*[^"\x27`]' src/

# 2. Find `path.join` or `path.resolve` calls that might consume user input:
rg -n 'path\.(join|resolve)\(' src/
```

### B. Dynamic Attacker Test (Local SSRF Listener & File Upload Canary)
1. **SSRF Canary Listener:** Start a local HTTP listener on `127.0.0.1:19999` inside the isolated lab that returns `flag{CANARY_SSRF_INTERNAL}`. Pass the following URLs to every URL-accepting parameter (`webhookUrl`, `avatarUrl`, `previewUrl`, `importUrl`):
   - `http://127.0.0.1:19999/secret`
   - `http://localhost:19999/secret`
   - `http://[::1]:19999/secret`
   - `http://[::ffff:127.0.0.1]:19999/secret`
   - `http://2130706433:19999/secret`
   - An external URL that returns `302 Found` with `Location: http://127.0.0.1:19999/secret`
   Assert that the internal listener receives **zero** connections and `flag{CANARY_SSRF_INTERNAL}` is never returned or logged.
2. **Polyglot & Traversal Upload Test:** Upload an HTML/SVG payload (`<svg onload="alert(1)">`) renamed to `avatar.png`, and a file with `filename="../../../tmp/traversal_canary"`. Assert `400`/`415` rejection on the non-PNG magic bytes and verify `/tmp/traversal_canary` is never created.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Ban Direct `globalThis.fetch` for User-Controlled URLs:** Route all external URL fetches through `safeExternalFetch` with a custom `undici.Agent` / `reqwest::DnsResolver` that pins the validated IP address at the socket layer.
2. **Never Use Client Filenames in Storage Paths:** Store the sanitized display name as a database column (`original_filename`) used only inside `Content-Disposition: attachment; filename="..."`, and key all disk/bucket objects by `crypto.randomUUID()`.
