# Dependency, Container & CI/CD Supply-Chain Defense

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I5 — Minimal Blast Radius & Fail-Closed Boot` (OWASP ASVS `v5.0.0-15.1.1`, `15.2.1`).
- **Mechanism:** Modern software supply-chain compromises rarely rely on exploiting a zero-day in your application code. Instead, attackers compromise **upstream publishing credentials, CI tokens, or mutable release tags** and ship malicious code through official channels. As demonstrated by the October 2026 wave of supply-chain incidents:
  1. **`.pth` Startup Execution Bypassing `--ignore-scripts` (LiteLLM `1.107.0`, Oct 21, 2026, `OSV MAL-2026-2144`):** Disabling install scripts (`pip install --no-build-isolation` or npm `--ignore-scripts`) does **not** stop a malicious Python wheel that drops a `.pth` file (e.g., `cook.pth`) into `site-packages`. Python automatically executes every line starting with `import ` inside any `.pth` file on **every Python interpreter startup**—including `pip` itself—stealing cloud credentials, `~/.cursor`, and `~/.claude` configs.
  2. **Mutable Docker Tags (`latest`, `main-stable`) & Mutable GitHub Release Assets (OVHcloud CLI `GHSA-862f-55f5-vmvw`, Oct 19, 2026):** In the LiteLLM incident, Docker tags `latest` and `main-stable` were pushed with a credential stealer. In the OVHcloud CLI incident (`v0.11.0`–`v0.15.0`), source code and CI were clean, but a compromised developer account overwrote already-published GitHub release binaries because **GitHub Release Immutability** was disabled. A downstream user whose CI verified `SHA-256` hashes caught the backdoored binary in ~94 minutes.
  3. **Platform Secret-Store Exposure & LLM Proxy Log Leakage (Railway Disclosure, Oct 21, 2026; LiteLLM Log Leak):** Attackers target CI/PaaS environment stores and LLM gateway logs where coding agents accidentally echo `gh auth token` or cloud keys into prompt/response bodies.

---

## 2. Where It Hides

- `Dockerfile`s using floating tags (`FROM python:3.12-slim` or `FROM ghcr.io/berriai/litellm:main-stable`) instead of immutable `@sha256:...` digests.
- `.github/workflows/*.yml` files referencing third-party actions by mutable tag (`uses: actions/checkout@v4` or `uses: some-org/action@main`) instead of a 40-character commit SHA, or lacking a top-level `permissions: { contents: read }` block.
- Rust repositories with a `deny.toml` that checks `[licenses]` only while omitting `[advisories]`, `[bans]`, and `[sources]`.
- Node/Python installs in developer machines or CI that do not enforce lockfile integrity (`npm ci --ignore-scripts`, `pnpm install --frozen-lockfile`, `uv pip sync --require-hashes`) or minimum release-age cooldowns.
- LLM gateways, observability proxies, or error trackers that log full HTTP request/response bodies containing `Authorization`, `sk_live_`, `ghp_`, `gho_`, or `AWS_SECRET_ACCESS_KEY`.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (GitHub Actions Workflow + Dockerfile + `deny.toml`)

```yaml
# VULNERABLE .github/workflows/ci.yml:
# 1. Default read/write GITHUB_TOKEN permissions.
# 2. Floating `@v4` / `@main` tags on third-party actions (vulnerable to tag hijacking).
# 3. `npm install` instead of `npm ci --ignore-scripts` (runs arbitrary postinstall scripts).
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: third-party/setup-tool@main
      - run: npm install && npm test
```

```dockerfile
# VULNERABLE Dockerfile:
# Floating image tag + unhashed pip install (vulnerable to LiteLLM 1.107.0 style .pth injection)
FROM python:3.12-slim
RUN pip install litellm
```

### Hardened Pattern 1: SHA-Pinned GitHub Workflow + Least-Privilege Token + Lockfile Gate

```yaml
# HARDENED .github/workflows/ci.yml
name: Security & Build Gate
on:
  push:
    branches: [main]
  pull_request:

# 1. Default GITHUB_TOKEN to read-only contents across all jobs:
permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      # 2. Pin EVERY action to a full 40-character commit SHA:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

      # 3. Frozen lockfile + disabled install scripts + post-install .pth check:
      - name: Install dependencies safely
        run: |
          npm ci --ignore-scripts --audit=false
          npm audit --audit-level=high

      - name: Verify zero unexpected .pth startup hooks in Python environments (if Python used)
        run: |
          if [ -d ".venv" ]; then
            find .venv -name "*.pth" -exec grep -Hn "^import " {} + && exit 1 || true
          fi
```

### Hardened Pattern 2: Complete `deny.toml` for Rust Repositories (`cargo-deny`)

Never ship a `deny.toml` that only checks `[licenses]`. Enforce `[advisories]`, `[bans]`, and `[sources]`:

```toml
# HARDENED deny.toml (run via `cargo deny check advisories bans licenses sources`)

[advisories]
version = 2
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
unmaintained = "workspace"
unsound = "all"
ignore = []

[licenses]
version = 2
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

### Hardened Pattern 3: Redacting Secrets Before Any LLM / Telemetry Log Sink

```typescript
const SECRET_PATTERNS: ReadonlyArray<RegExp> = [
  /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,            // GitHub tokens
  /\bsk_(live|test)_[A-Za-z0-9]{16,128}\b/g,                    // Stripe / API secret keys
  /\bsk-[A-Za-z0-9_-]{20,200}\b/g,                              // OpenAI / Anthropic / LLM keys
  /\bAKIA[0-9A-Z]{16}\b/g,                                      // AWS Access Key IDs
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // Raw JWTs
  /(Authorization:\s*Bearer\s+)[^\s"']+/gi,                     // Bearer headers
];

export function redactSecretsFromLog(rawText: string): string {
  let clean = rawText;
  for (const pattern of SECRET_PATTERNS) {
    clean = clean.replace(pattern, "[REDACTED_SECRET]");
  }
  return clean;
}
```

---

## 4. How to Discover It Automatically

### A. Static Supply-Chain Audit Script
```bash
# 1. Flag any GitHub Actions `uses:` line NOT pinned to a 40-hex-char SHA:
rg -n 'uses:\s*[^@\s]+@' .github/workflows/ | rg -v '@[0-9a-f]{40}\b'

# 2. Flag any Dockerfile `FROM` line NOT pinned to `@sha256:`:
rg -n '^\s*FROM\s+' Dockerfile* | rg -v '@sha256:[0-9a-f]{64}'

# 3. Check Python virtualenvs / containers for executable `import ` lines inside `.pth` files:
find / -name "*.pth" 2>/dev/null | xargs grep -Hn "^import " 2>/dev/null
```

### B. Operational Supply-Chain & Rotation Verification
1. **Lockfile Integrity Check:** Verify that modifying a single dependency version in `package.json` or `Cargo.toml` without updating `package-lock.json` / `Cargo.lock` causes CI (`npm ci` / `cargo test --locked`) to fail immediately.
2. **15-Minute Secret Rotation Drill:** Maintain an explicit inventory of every secret variable (`SESSION_SECRET`, `DATABASE_URL`, `WEBHOOK_SECRET`, `ACCESS_POLICY_AUD`, cloud bucket keys) and verify that rolling them requires only an environment update + restart with zero hardcoded values in source.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Pin Hashes Everywhere:**
   - **GitHub Actions:** 40-character commit SHAs + `persist-credentials: false` on `actions/checkout` + `permissions: contents: read`.
   - **Containers:** `FROM image:tag@sha256:<64_hex_digest>`.
   - **Packages:** Commit lockfiles (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`) and run `cargo deny check` / `npm ci --ignore-scripts` in CI.
   - **GitHub Releases:** Enable **Release Immutability** in repository settings so published release assets and tags cannot be overwritten by a compromised maintainer token.
2. **Quarantine Bleeding-Edge Package Releases:** Configure package managers (e.g., `pnpm` `minimumReleaseAge: 1440` or `uv` `--exclude-newer`) for non-security updates so malicious versions caught within the first 2–24 hours (like `litellm==1.107.0`, which lived for 104 minutes on PyPI) are never pulled into developer laptops or CI builds.
