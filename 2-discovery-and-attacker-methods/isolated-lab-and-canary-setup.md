# Step 1: Isolated Lab & Cryptographic Canary Setup

## 1. Mental Model (Why Canaries Beat Subjective Code Review)

How do you prove with **100% mathematical certainty**—and **0% false positives**—whether an attacker (`User B`) can read or mutate private data belonging to a victim (`User A`), or reach an internal network service via SSRF?

You turn your application into a local, self-contained **Capture-The-Flag (CTF) Verification Lab**:
1. You boot the application on an isolated local port (`http://127.0.0.1:4100`) backed by an ephemeral database and temporary storage directory.
2. You seed **Victim (`User A` in `Tenant A`)** with secret cryptographic canary strings (`flag{<random_uuid_v4>}`) planted in every sensitive location:
   - `CANARY_DB_PRIVATE`: Inside `User A`'s private database rows (issues, notes, billing details, hidden fields).
   - `CANARY_DB_SECRET_PROJECT`: Inside a restricted project in `Tenant A` that `ProjectGuest G` is **not** invited to.
   - `CANARY_BLOB_PRIVATE`: Inside a private file uploaded by `User A` to S3/R2/local attachment storage.
   - `CANARY_FS_ENV`: Inside a local file outside the web root (`/tmp/canary_fs_secret.txt`) to detect LFI / path traversal.
   - `CANARY_SSRF_INTERNAL`: Served by a loopback-only HTTP micro-server on `http://127.0.0.1:19999/canary` to detect SSRF.
3. **The Zero-Knowledge Oracle Trick:** You do **not** give the attacker agent the plaintext `flag{...}` strings. You only give the attacker agent:
   - The session cookie / API key of **Attacker (`User B` in `Tenant B`)** and **Restricted Guest (`Guest G` in `Tenant A`, `Project Public` only)**.
   - The UUIDs of `User A`'s resources (simulating leaked/enumerated IDs).
   - An oracle function (or list of `SHA-256(flag)` hashes) that checks whether any captured output matches `SHA-256(flag)`.

Because the attacker agent never sees the plaintext `flag{UUID}` in its prompt, **it is impossible for the agent to hallucinate a finding**. Either its exploit script extracts the exact 128-bit UUID from the server and matches the `SHA-256` hash, or it does not.

---

## 2. Architecture of the Isolated Canary Lab

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                   ISOLATED LOCAL SANDBOX (127.0.0.1 ONLY)                    │
│                                                                              │
│  ┌─────────────────────────────────────────┐   ┌──────────────────────────┐  │
│  │ Target App Instance (127.0.0.1:4100)    │   │ Internal SSRF Listener   │  │
│  │ - Ephemeral DB (SQLite/Postgres tmp)    │   │ (127.0.0.1:19999)        │  │
│  │ - Ephemeral Blob Store (/tmp/blobs)     │   │ Returns:                 │  │
│  │ - Seeded with Victim (User A) Canaries  │   │ flag{CANARY_SSRF_<UUID>} │  │
│  └───────────────────┬─────────────────────┘   └────────────▲─────────────┘  │
│                      │                                      │                │
│                      │ HTTP / WS / MCP                      │ (Only reachable│
│                      │                                      │  if SSRF bug!) │
│  ┌───────────────────▼──────────────────────────────────────┴─────────────┐  │
│  │ Attacker Harness / Micro-Agent Runner                                  │  │
│  │ - Holds ONLY: User B session, Guest G session, Revoked token,          │  │
│  │   Anonymous client, and Target Resource IDs (UUID_A_1, UUID_A_2...)    │  │
│  │ - Does NOT know plaintext flags; knows only SHA-256(flag) hashes       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Reference Implementation: Deterministic Canary Seeder & Validator (`canary-lab.mjs`)

Any engineer or coding agent can adapt this zero-dependency Node.js script to seed canaries, run an attack suite, and verify both **Confidentiality (zero canary capture)** and **Integrity (zero Victim state mutation)**:

```javascript
// canary-lab.mjs — Reference Canary Seeder & Zero-False-Positive PoV Validator
import crypto from "node:crypto";
import http from "node:http";

export function generateCanary(label) {
  const rawFlag = `flag{${label}_${crypto.randomUUID()}}`;
  const sha256 = crypto.createHash("sha256").update(rawFlag, "utf8").digest("hex");
  return Object.freeze({ label, rawFlag, sha256 });
}

/**
 * Starts a loopback-only HTTP listener on an ephemeral port to detect blind or full-response SSRF.
 * Any hit to this server proves the target application made an unauthorized internal request!
 */
export async function startSsrfCanaryServer(canaryFlag) {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push({
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      headers: req.headers,
    });
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(canaryFlag);
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}/latest/meta-data/iam/security-credentials`,
    hits,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/**
 * Scans any HTTP response body, header map, or captured output string for any planted canary
 * without exposing the plaintext canary to the attacker agent.
 */
export function scanOutputForCanaries(rawOutput, canaryRegistry) {
  const flagRegex = /flag\{[A-Za-z0-9_-]{10,120}\}/g;
  const matches = rawOutput.match(flagRegex) ?? [];
  const captured = [];

  for (const candidate of matches) {
    const candidateHash = crypto.createHash("sha256").update(candidate, "utf8").digest("hex");
    for (const entry of canaryRegistry) {
      if (entry.sha256 === candidateHash) {
        captured.push({
          label: entry.label,
          sha256: entry.sha256,
          proofSnippet: rawOutput.slice(0, 300),
        });
      }
    }
  }
  return captured;
}

/**
 * Computes a canonical SHA-256 snapshot of Victim (User A)'s records before and after the
 * attacker harness runs. If the hash changes, User B illegally mutated User A's state!
 */
export function hashVictimStateSnapshot(victimStateJson) {
  const canonical = JSON.stringify(victimStateJson);
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}
```

---

## 4. Step-by-Step Execution Protocol for Agents

When setting up the isolated lab on any repository:

1. **Enforce Strict Localhost Isolation:**
   - Set `DATABASE_URL` to a temporary SQLite file (`/tmp/cyber_lab_${runId}.db`) or an isolated local Postgres schema.
   - Replace all external third-party API keys (`STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `RESEND_API_KEY`) with local mock endpoints so the attacker harness can never bill real APIs or send real emails.
2. **Seed the 5 Canonical Actors & 4 Canary Types:**
   - Create `Tenant A` (`Owner A`, `Member A`, `ProjectGuest G` scoped only to `Project A_Public`) and `Tenant B` (`Owner B` = main cross-tenant attacker).
   - Plant:
     - `CANARY_TENANT_A_ISSUE` inside an issue in `Tenant A`.
     - `CANARY_SECRET_PROJECT_ISSUE` inside `Project A_Secret` (which `ProjectGuest G` must not see).
     - `CANARY_ATTACHMENT_BLOB` inside an uploaded attachment on `Project A_Secret`.
     - `CANARY_SSRF_LOOPBACK` on the local `startSsrfCanaryServer()` listener.
3. **Record Victim Pre-Attack State Hash:**
   - Query all of `Tenant A`'s entities as `Owner A` and compute `preAttackHash = hashVictimStateSnapshot(state)`.
4. **Run All Attacker Suites (`Steps 2–5`):**
   - Execute the differential surface oracle, micro-agent red-team scripts, and race harnesses using only `Owner B`, `ProjectGuest G`, `Revoked`, and `Anonymous` credentials.
5. **Evaluate Deterministic Oracles:**
   - **Confidentiality Breach (`CRITICAL`):** `scanOutputForCanaries` returns $\ge 1$ matched canary SHA-256 hash.
   - **Blind SSRF Breach (`CRITICAL`):** `ssrfServer.hits.length > 0`.
   - **Integrity / Cross-Tenant Mutation Breach (`CRITICAL`):** Re-query `Tenant A` as `Owner A` after the attack; `postAttackHash !== preAttackHash` (excluding expected timestamps if untouched, or comparing normalized entity fields).
