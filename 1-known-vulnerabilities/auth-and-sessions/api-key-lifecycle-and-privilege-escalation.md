# API Key Lifecycle, Hashing & Privilege Escalation

> **Invariants:** `I1 — Authentic Identity & Purpose Binding` and `I5 — Minimal Blast Radius` (OWASP ASVS `v5.0.0-7.2.2`, `7.4.2`, `14.2.1`).
> Related: [`../infra-and-supply-chain/surface-separation-and-destructive-gates.md`](../infra-and-supply-chain/surface-separation-and-destructive-gates.md) · [`../../strategy/scoped-db.md`](../../strategy/scoped-db.md) · [`../authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../authorization-and-tenancy/async-jobs-and-scope-propagation.md)

---

## 1. Attack Transcript

A scoped, read-only CI key leaks in a build log. The attacker uses it to mint a permanent one, and the victim rotates the leaked key, which does nothing.

```http
POST /api/keys HTTP/1.1
Host: api.example.com
Authorization: Bearer sk_live_<leaked read-only CI key>
Content-Type: application/json

{"name":"backup","scopes":["*"]}

HTTP/1.1 201 Created
{"id":"key_9f","secret":"sk_live_c2b1...e07"}
```

```http
DELETE /api/keys/key_ci HTTP/1.1          <- victim rotates the leaked key
...
GET /api/projects HTTP/1.1
Authorization: Bearer sk_live_c2b1...e07  <- attacker's minted key

HTTP/1.1 200 OK
```

Second transcript (orphaned key): the owner removes a contractor from the org, and the contractor's key keeps working.

```http
DELETE /api/orgs/org_1/members/user_77  ->  204
GET /api/projects  (Authorization: Bearer sk_live_<user_77's key>)  ->  200
```

---

## 2. Spot the Bug

How many separate problems are in this lookup and route table?

```typescript
export async function requireAuth(req: Request, db: Database) {
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

app.post("/api/keys", async (req) => {
  const actor = await requireAuth(req, db);
  const { name, scopes } = await req.json();
  return createKey(actor.userId, actor.orgId, name, scopes);
});
```

---

## 3. Invariant Violated & Mechanism

Applications that support interactive human sessions and long-lived programmatic keys (`Bearer sk_live_...`) hit three recurring flaws:

1. **Privilege amplification (`key-mints-key`):** the key-management endpoint accepts a key as authentication. One leaked machine key produces a permanent replacement that survives rotation of the original.
2. **Plaintext storage:** raw keys in the `api_keys` table turn any read-only SQL leak or backup exposure into account compromise. Store `SHA-256(raw_key)`; for 256-bit CSPRNG keys a fast hash is correct (a slow KDF buys nothing and costs DoS surface). Because lookup is by hash equality via an index, the application never compares secrets itself; if you ever do compare in app code, use a constant-time comparison.
3. **Orphaned keys and unbounded privilege:** the key row is validated without joining the owner's *current* user and membership state, and the key inherits the owner's full role. A "read-only CI" key that really means "everything the owner can do" is not scoped.

The effective privilege of a key at use time must be the **intersection** of the key's declared scopes and the owner's **current** role in the org. Neither can be cached into the key at creation.

Why happy-path tests pass: they create a key and call `GET`. They never call `POST /api/keys` with a key, never remove the owner and replay, and never check whether a "read-only" key can write.

Where it hides: unified `requireAuth(req)` middlewares; machine routers that mount the full app; member-removal handlers that do not touch the keys; Redis or memory key caches with 5–15 minute TTLs.

---

## 4. Hardened Pattern

### 4.1 Distinct credential tiers, with an honest statement of what the type system guarantees

```rust
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    ReadProjects,
    WriteProjects,
    ManageMembers,
    ManageKeys,
    ManageBilling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Member,
    Guest,
}

pub fn role_permissions(role: Role) -> HashSet<Permission> {
    use Permission::*;
    match role {
        Role::Owner => [ReadProjects, WriteProjects, ManageMembers, ManageKeys, ManageBilling].into(),
        Role::Admin => [ReadProjects, WriteProjects, ManageMembers, ManageKeys].into(),
        Role::Member => [ReadProjects, WriteProjects].into(),
        Role::Guest => [ReadProjects].into(),
    }
}

/// Human-only permissions: a machine key can NEVER hold these, whatever its scopes say.
const HUMAN_ONLY: [Permission; 3] = [Permission::ManageKeys, Permission::ManageMembers, Permission::ManageBilling];

/// Proof types. Constructors are private to this module (fields are not `pub`).
pub struct HumanActor { user_id: String, org_id: String, perms: HashSet<Permission> }
pub struct MachineActor { key_id: String, user_id: String, org_id: String, perms: HashSet<Permission> }

impl HumanActor {
    pub fn user_id(&self) -> &str { &self.user_id }
    pub fn org_id(&self) -> &str { &self.org_id }
    pub fn has(&self, p: Permission) -> bool { self.perms.contains(&p) }
}
impl MachineActor {
    pub fn org_id(&self) -> &str { &self.org_id }
    pub fn has(&self, p: Permission) -> bool { self.perms.contains(&p) }
}

pub enum Authenticated {
    Human(HumanActor),
    Machine(MachineActor),
}

/// Effective key privilege = declared scopes ∩ owner's CURRENT role permissions \ human-only.
pub fn effective_machine_permissions(scopes: &[String], owner_role: Role) -> HashSet<Permission> {
    let declared: HashSet<Permission> = scopes.iter().filter_map(|s| parse_scope(s)).collect();
    let role = role_permissions(owner_role);
    declared
        .intersection(&role)
        .copied()
        .filter(|p| !HUMAN_ONLY.contains(p))
        .collect()
}

fn parse_scope(s: &str) -> Option<Permission> {
    match s {
        "projects:read" => Some(Permission::ReadProjects),
        "projects:write" => Some(Permission::WriteProjects),
        _ => None, // unknown scopes (including "*") grant nothing
    }
}

/// Minting: a new key's scopes must be a subset of the minting human's own permissions.
pub fn validate_mint_request(minter: &HumanActor, requested: &[String]) -> Result<(), &'static str> {
    if !minter.has(Permission::ManageKeys) {
        return Err("FORBIDDEN");
    }
    for s in requested {
        match parse_scope(s) {
            Some(p) if minter.has(p) => {}
            _ => return Err("SCOPE_NOT_GRANTABLE"),
        }
    }
    Ok(())
}

/// Generate a high-entropy prefixed key: returns `(raw_key_shown_once, key_prefix, sha256_hex)`.
pub fn generate_api_key() -> (String, String, String) {
    let mut entropy = [0u8; 32]; // 256 bits of CSPRNG entropy
    rand::thread_rng().fill_bytes(&mut entropy);
    let raw_key = format!("sk_live_{}", hex::encode(entropy));
    let key_prefix = raw_key[..16].to_string(); // display only
    let key_hash = sha256_hex(raw_key.as_bytes());
    (raw_key, key_prefix, key_hash)
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}
```

**What this guarantees, honestly.** The compile-time guarantee holds only for handlers whose signature *requires* `HumanActor`. A handler that takes `Authenticated` (or the old `AuthCredential`) and calls a runtime check is still a runtime guarantee. So make the rule structural: **no handler receives the enum**. The router resolves the credential once and passes a `HumanActor` or `MachineActor` according to the route's declared surface (see [`surface-separation-and-destructive-gates.md`](../infra-and-supply-chain/surface-separation-and-destructive-gates.md)). Key, member and billing handlers accept only `&HumanActor`; machine routes accept only `&MachineActor`.

### 4.2 Key verification with live membership, role and expiry in one query

```sql
-- Hash match, key revocation/expiry, user status AND active org membership AND current role,
-- in one statement so removing a member or disabling a user kills every key immediately.
SELECT
    k.id            AS key_id,
    k.user_id       AS user_id,
    k.org_id        AS org_id,
    k.scopes        AS scopes,
    m.role          AS owner_role      -- current role, never cached on the key
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

The caller maps `(scopes, owner_role)` through `effective_machine_permissions`. A demotion from `Admin` to `Member` immediately shrinks every key that user owns.

---

## 5. Residual Edge Cases (why the hardened version is still not enough)

- **Query-string and log leakage:** reject `?api_key=` outright (ASVS `14.2.1`) and redact `Authorization` in every log and LLM-gateway sink.
- **Caches:** if you cache the lookup, the TTL *is* your revocation latency. Keep it in seconds, invalidate on member removal and demotion, and document the SLO.
- **Key-per-user vs service accounts:** a key tied to a person who leaves is a revocation event; prefer org-owned service accounts with their own role row.
- **Scope drift:** adding a new scope later must not silently widen existing keys; scopes are an allowlist parsed by exact string.
- **Prefix collisions:** the displayed prefix is not a lookup key; never authenticate by prefix.
- **Rotation overlap:** support two active keys per integration so rotation does not force downtime, otherwise teams keep leaked keys alive.
- **Jobs and webhooks acting for a key:** the key's authority must survive queues as a scope, not as a service handle. See [`../authorization-and-tenancy/async-jobs-and-scope-propagation.md`](../authorization-and-tenancy/async-jobs-and-scope-propagation.md).

---

## 6. How to Discover It Automatically

### A. Static
```bash
# 1. How does the api_keys table store secrets (missing hash column / plaintext)?
rg -n 'CREATE TABLE.*api_keys|INSERT INTO.*api_keys' src/ migrations/

# 2. Key-minting and role-management handlers: do they reject key auth?
rg -n -C 12 '/api/keys|create_api_key|mint_key' src/
```

```yaml
rules:
  - id: handler-takes-unified-auth-enum
    languages: [rust]
    severity: WARNING
    message: Route handlers must take HumanActor or MachineActor, never the Authenticated enum.
    pattern: async fn $H(..., $A: Authenticated, ...) -> $R { ... }
```

### B. Dynamic
1. **Key-mints-key:** with a valid machine key, `POST /api/keys`, `DELETE /api/keys/:id`, `POST /api/members/invite`, `PATCH /api/account/password`. Assert `401/403/404`.
2. **Scope enforcement:** with a `projects:read` key, `POST /api/projects`. Assert `403`.
3. **Zero-window revocation (within SLO):** remove the member (or revoke the key), replay `GET /api/projects` with the key. Assert `401`.
4. **Demotion:** demote the owner to `Guest`; the key's write calls must fail on the next request.
5. **Query-string token (`v5.0.0-14.2.1`):** `GET /api/projects?api_key=sk_live_test` with no header. Assert `401`.

All five belong in the no-LLM sweep: [`../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md`](../../2-discovery-and-attacker-methods/deterministic-oracle-sweep.md).

---

## 7. How to Eliminate the Bug Class by Construction

1. **Credential tier in the type system, at the router.** Handlers never see a credential enum; they see `HumanActor` or `MachineActor`. Human-only permissions are subtracted from every machine key unconditionally.
2. **Physical surface split where possible.** On edge platforms, deploy an interactive UI surface (mounts key-management) and a machine surface that does not even compile those routes.
3. **Effective privilege computed at use time** from the live membership row, intersected with scopes.
4. **Minting is monotone:** a minted key can never exceed its minter's current permissions.
