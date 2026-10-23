# API Key Lifecycle, Hashing & Privilege Escalation

## 1. Invariant Violated & Mechanism

- **Invariant Violated:** `I1 — Authentic Identity & Purpose Binding` and `I5 — Minimal Blast Radius` (OWASP ASVS `v5.0.0-7.2.2`, `7.4.2`, `14.2.1`).
- **Mechanism:** Applications frequently support both interactive human sessions (browser cookies / OIDC) and long-lived programmatic API keys (`Bearer sk_live_...`) for CLI tools, webhooks, or background workers. Three critical flaws recur in API key implementations:
  1. **Privilege Amplification (`Key-Mints-Key`):** An endpoint that creates, lists, or rotates API keys (`POST /api/keys`) accepts authentication via an existing API key. If an attacker compromises a single short-lived or scoped machine key from a CI log, they immediately call `POST /api/keys` to mint a fresh, permanent key that survives when the victim rotates the original leaked key.
  2. **Plaintext Storage / Timing Side-Channels:** Storing raw API keys in the `api_keys` table instead of `SHA-256(raw_key)`, turning any read-only SQL leak or backup exposure into total account compromise.
  3. **Orphaned Keys After Role/Account Revocation:** Validating the API key row without joining or checking that the owning user and organization membership are still active (`revoked_at IS NULL` AND `member.status = 'active'`).

---

## 2. Where It Hides

- Unified `requireAuth(req)` middlewares that treat a cookie session and an `Authorization: Bearer <api_key>` header as identical `User` objects, allowing API keys to call `/api/keys`, `/api/account/password`, `/api/billing`, or `/api/members/invite`.
- Machine-to-machine worker endpoints that mount the full application router instead of a restricted machine router.
- Soft-delete or member-removal handlers (`DELETE /api/orgs/:orgId/members/:userId`) that remove the user from `org_members` without revoking or scoping their personal API keys, or cache key lookups in Redis/memory for 5–15 minutes after revocation.

---

## 3. Vulnerable vs. Hardened Pattern

### Vulnerable Pattern (TypeScript — Unified Auth + Plaintext Key Lookup)

```typescript
// VULNERABLE:
// 1. Looks up raw plaintext API key in the database.
// 2. Returns the exact same `{ userId, orgId }` object for both browser sessions and machine keys.
// 3. `POST /api/keys` uses `requireAuth`, so a leaked machine key can mint new keys forever!
export async function requireAuthVulnerable(req: Request, db: Database) {
  const bearer = req.headers.get("authorization")?.replace("Bearer ", "");
  if (bearer) {
    const row = await db.queryOne(
      "SELECT user_id, org_id FROM api_keys WHERE raw_key = $1",
      [bearer]
    );
    if (row) return { userId: row.user_id, orgId: row.org_id };
  }
  return verifyBrowserSession(req);
}
```

### Hardened Pattern (Rust — Distinct Credential Tiers + SHA-256 Storage + Live Membership Join)

```rust
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Distinct authentication tiers prevent a machine API key from calling human-only
/// administrative or key-minting routes at compile time.
#[derive(Debug, Clone)]
pub enum AuthCredential {
    InteractiveHumanSession {
        user_id: String,
        org_id: String,
        session_id: String,
    },
    MachineApiKey {
        key_id: String,
        user_id: String,
        org_id: String,
        scopes: Vec<String>,
    },
}

/// Proof type required by key-management, member-role, and billing routes.
/// Can ONLY be constructed from `AuthCredential::InteractiveHumanSession`.
#[derive(Debug, Clone)]
pub struct HumanAdminActor {
    pub user_id: String,
    pub org_id: String,
}

impl AuthCredential {
    pub fn require_human_interactive(&self) -> Result<HumanAdminActor, &'static str> {
        match self {
            AuthCredential::InteractiveHumanSession { user_id, org_id, .. } => Ok(HumanAdminActor {
                user_id: user_id.clone(),
                org_id: org_id.clone(),
            }),
            AuthCredential::MachineApiKey { .. } => {
                Err("FORBIDDEN_CREDENTIAL_TIER: API keys cannot manage keys, roles, or billing")
            }
        }
    }
}

/// Generate a high-entropy prefixed API key: returns `(raw_key_shown_once, key_prefix, sha256_hex)`.
pub fn generate_api_key() -> (String, String, String) {
    let mut entropy = [0u8; 32]; // 256 bits of CSPRNG entropy
    rand::thread_rng().fill_bytes(&mut entropy);
    let secret_part = hex::encode(entropy);
    let raw_key = format!("sk_live_{secret_part}");
    let key_prefix = raw_key[..16].to_string();
    let key_hash = sha256_hex(raw_key.as_bytes());
    (raw_key, key_prefix, key_hash)
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}
```

### Hardened SQL Query for API Key Verification (Immediate Revocation & Active Member Check)

```sql
-- Verify the SHA-256 hash, key revocation, key expiration, user status, AND active org membership
-- in a single atomic join so removing a member immediately kills all their API keys:
SELECT
    k.id            AS key_id,
    k.user_id       AS user_id,
    k.org_id        AS org_id,
    k.scopes        AS scopes,
    k.key_hash      AS stored_hash
FROM api_keys k
INNER JOIN users u
    ON u.id = k.user_id
   AND u.disabled_at IS NULL
INNER JOIN org_members m
    ON m.org_id = k.org_id
   AND m.user_id = k.user_id
   AND m.revoked_at IS NULL
WHERE k.key_hash = $1
  AND k.revoked_at IS NULL
  AND (k.expires_at IS NULL OR k.expires_at > CURRENT_TIMESTAMP);
```

---

## 4. How to Discover It Automatically

### A. Static Code Search
```bash
# 1. Check how api_keys table stores secrets (look for missing hash column or plaintext storage):
rg -n 'CREATE TABLE.*api_keys|INSERT INTO.*api_keys' src/ migrations/

# 2. Check key-minting and role-management handlers to verify they reject API key auth:
rg -n -C 12 '/api/keys|create_api_key|mint_key' src/
```

### B. Dynamic Attacker Test (Privilege Escalation & Revocation Immediate-Effect Check)
1. **Key-Mints-Key Test:** Using a valid machine API key (`Authorization: Bearer sk_live_...`), send `POST /api/keys` to create a second API key, `DELETE /api/keys/:id`, and `POST /api/members/invite`. Assert `403 Forbidden` (or `401` if mounted on a separate surface).
2. **Zero-Window Revocation Test:**
   - Mint `sk_live_test` for `User B` in `Org 1`.
   - Verify `GET /api/projects` with `Bearer sk_live_test` returns `200 OK`.
   - Have `User A` (Owner of `Org 1`) remove `User B` from `Org 1` (or revoke `sk_live_test`).
   - Within `<10ms`, replay `GET /api/projects` with `Bearer sk_live_test`. Assert `401 Unauthorized`.
3. **Query-String Token Rejection (`v5.0.0-14.2.1`):** Send `GET /api/projects?api_key=sk_live_test` with no `Authorization` header. Assert `401 Unauthorized`.

---

## 5. How to Eliminate the Bug Class by Construction

1. **Encode Credential Tier in the Type System:** Route handlers that mint credentials, change passwords/emails, or alter billing must require `HumanAdminActor` (or be mounted exclusively on the interactive UI server/worker), making it a compile error to pass a `MachineApiKey` principal.
2. **Physical Surface Split Where Possible:** On edge/serverless platforms, deploy two distinct entry points: an interactive UI surface (accepts only browser/Access sessions; mounts key-management routes) and a machine API surface (accepts `Bearer` API keys; physically does not compile or mount key-minting routes).
