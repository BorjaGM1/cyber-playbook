# Step 5: Stateful Property Testing, Entry-Point Fuzzing & Autonomous Fuzz Labs

## 1. Mental Model (Finding the 7-Step Logic Bug Nobody Thought to Write a Test For)

Hand-written unit tests and even single-request canary probes only test transitions 1 step deep (`Create Issue` $\to$ `Read Issue`). What happens when:
1. `Owner A` creates `Project 1` (public) and `Project 2` (restricted).
2. `Owner A` invites `Guest G` to `Project 1`.
3. `Guest G` creates an issue `I_1` inside `Project 1` and attaches a file `F_1`.
4. `Owner A` moves `I_1` from `Project 1` into `Project 2` (restricted).
5. `Owner A` removes `Guest G` from `Project 1`, then re-invites `Guest G` to a third project `Project 3`.
6. `Guest G` queries `/api/search` or `/api/attachments/{F_1}` or `/api/issues/{I_1}/history`.

No human engineer writes a test for that specific 6-step sequence. **Stateful Property-Based Testing (`fast-check` in TypeScript, `proptest` / `proptest-state-machine` in Rust)** discovers it automatically by:
1. Maintaining a **tiny in-memory Reference Model** (a 50-line idealized `Map` of who currently owns what and who is currently granted access to which project).
2. Generating thousands of random sequences of **Commands** (`CreateProject`, `InviteGuest`, `RevokeGuest`, `CreateIssue`, `MoveIssue`, `DeleteKey`, `SearchAsActor`, `ReadHistoryAsActor`).
3. Checking after **every single step** that the real database/API agrees with the Reference Model on all [Five Universal Invariants](../strategy/five-universal-invariants.md).
4. **Automatic Shrinking:** When a 17-step random sequence violates an invariant, `fast-check` or `proptest` automatically prunes redundant steps and hands you the **minimal 3- or 4-step sequence** that reproduces the bug.

---

## 2. Reference Pattern 1: Multi-Step Authorization & Lifecycle State Machine in TypeScript (`fast-check`)

```typescript
import fc from "fast-check";

// 1. Idealized Reference Model (50 lines — trivial to audit by eye):
interface ReferenceModel {
  projects: Map<string, { orgId: string; isSecret: boolean }>;
  issues: Map<string, { orgId: string; projectId: string; canary: string; historyProjectIds: Set<string> }>;
  activeGuestGrants: Set<string>; // Format: `${userId}:${projectId}`
  revokedTokens: Set<string>;
}

// Helper: Pure mathematical definition of Invariant I2 on the Reference Model:
function modelCanGuestSeeIssue(model: ReferenceModel, guestId: string, issueId: string): boolean {
  const issue = model.issues.get(issueId);
  if (!issue) return false;
  return model.activeGuestGrants.has(`${guestId}:${issue.projectId}`);
}

// 2. Define Stateful Commands that mutate BOTH the real system (`RealApp`) and `ReferenceModel`:
class MoveIssueCommand implements fc.AsyncCommand<ReferenceModel, RealApp> {
  constructor(
    readonly issueId: string,
    readonly targetProjectId: string,
    readonly guestId: string
  ) {}

  check(model: Readonly<ReferenceModel>): boolean {
    return model.issues.has(this.issueId) && model.projects.has(this.targetProjectId);
  }

  async run(model: ReferenceModel, real: RealApp): Promise<void> {
    // Mutate Real System as Owner:
    await real.moveIssueAsOwner(this.issueId, this.targetProjectId);

    // Mutate Reference Model:
    const issue = model.issues.get(this.issueId)!;
    issue.projectId = this.targetProjectId;
    issue.historyProjectIds.add(this.targetProjectId);

    // Assert Invariant I2 across ALL surfaces (Primary GET, Search, and History) as Guest:
    const expectedVisible = modelCanGuestSeeIssue(model, this.guestId, this.issueId);
    const getStatus = await real.getIssueStatusAsGuest(this.guestId, this.issueId);
    const searchResults = await real.searchAsGuest(this.guestId, issue.canary);

    if (!expectedVisible) {
      if (getStatus !== 404) {
        throw new Error(`I2_VIOLATION: Guest got HTTP ${getStatus} (expected 404) after MoveIssue`);
      }
      if (searchResults.includes(issue.canary)) {
        throw new Error(`I2_SIDE_DOOR_LEAK: Search leaked canary ${issue.canary} after MoveIssue`);
      }
    }
  }

  toString(): string {
    return `MoveIssue(issue=${this.issueId}, toProject=${this.targetProjectId})`;
  }
}
```

---

## 3. Reference Pattern 2: Stateful Property Testing in Rust (`proptest`)

```rust
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
enum AuthAction {
    CreateProject { proj_id: u8 },
    GrantGuest { proj_id: u8 },
    RevokeGuest { proj_id: u8 },
    CreateSecretIssue { issue_id: u8, proj_id: u8 },
    MoveIssue { issue_id: u8, to_proj_id: u8 },
    MintAndRevokeApiKey,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]
    #[test]
    fn prop_guest_and_revoked_actor_never_leak_across_any_transition_sequence(
        actions in prop::collection::vec(any::<AuthAction>(), 1..25)
    ) {
        let mut store = RealStore::new_in_memory();
        let mut model_guest_projects: HashSet<u8> = HashSet::new();
        let mut model_issue_project: HashMap<u8, u8> = HashMap::new();

        for action in actions {
            match action {
                AuthAction::CreateProject { proj_id } => {
                    store.ensure_project(proj_id);
                }
                AuthAction::GrantGuest { proj_id } => {
                    store.grant_guest("guest_1", proj_id);
                    model_guest_projects.insert(proj_id);
                }
                AuthAction::RevokeGuest { proj_id } => {
                    store.revoke_guest("guest_1", proj_id);
                    model_guest_projects.remove(&proj_id);
                }
                AuthAction::CreateSecretIssue { issue_id, proj_id } => {
                    if store.has_project(proj_id) {
                        store.upsert_issue(issue_id, proj_id, &format!("flag{{CANARY_{issue_id}}}"));
                        model_issue_project.insert(issue_id, proj_id);
                    }
                }
                AuthAction::MoveIssue { issue_id, to_proj_id } => {
                    if store.has_project(to_proj_id) && model_issue_project.contains_key(&issue_id) {
                        store.move_issue(issue_id, to_proj_id);
                        model_issue_project.insert(issue_id, to_proj_id);
                    }
                }
                AuthAction::MintAndRevokeApiKey => {
                    let raw_key = store.mint_key("guest_1");
                    store.revoke_key(&raw_key);
                    // Invariant I1/I2: Revoked key must fail immediately on the very next call:
                    prop_assert!(store.authenticate_key(&raw_key).is_err());
                }
            }

            // Universal Invariant I2 Oracle after EVERY transition:
            // Compare primary CRUD, Search, and History for `guest_1` against `model_guest_projects`:
            for (&issue_id, &proj_id) in &model_issue_project {
                let should_see = model_guest_projects.contains(&proj_id);
                let can_read_crud = store.read_issue_as_guest("guest_1", issue_id).is_ok();
                let can_find_search = store.search_as_guest("guest_1", &format!("CANARY_{issue_id}"));

                prop_assert_eq!(can_read_crud, should_see, "CRUD visibility mismatch on issue {}", issue_id);
                prop_assert_eq!(can_find_search, should_see, "Search side-door leak on issue {}", issue_id);
            }
        }
    }
}
```

---

## 4. Coverage-Guided Fuzzing & The Entry-Point Rule (`OSS-Fuzz-Gen` + `FalseCrashReducer`, 2026)

When using an LLM agent to write fuzz targets (`cargo-fuzz` / `libFuzzer` in Rust, `Jazzer.js` in TypeScript) for binary frame decoders, VT100 terminal parsers, JWT/header parsers, or URL validators, there is one critical rule proven by Google's **OSS-Fuzz-Gen & FalseCrashReducer** study ([July 2026, arXiv:2510.02185](https://arxiv.org/abs/2510.02185)):

> **Never fuzz internal helper functions that assume caller preconditions without enforcing those preconditions in the fuzz harness.**

In Google's study across 15,204 fuzz-target runs in 160 projects, unguarded LLM-generated harnesses produced massive numbers of **spurious crashes** because the LLM called internal functions with null pointers, uninitialized state, or out-of-contract lengths that public entry points already reject. Pairing LLM constraint analysis (`FalseCrashReducer`) with entry-point harnesses maintained **96.2%–96.9% precision**.

### The 3 Rules for High-Signal Fuzz Targets
1. **Target the Public Trust-Boundary Entry Point:** Fuzz `Frame::decode(raw_bytes)`, `sanitize_and_wrap_bracketed_paste(raw_str)`, `verify_access_jwt(raw_token)`, or `is_exact_loopback_host(raw_host)`—not internal private helpers.
2. **Enforce Round-Trip & No-Panic Invariants (`I4`):**
   - **No panics / OOMs:** Arbitrary byte slices `&[u8]` up to 64KB must never trigger `panic!`, integer overflow, slice index out-of-bounds, or unbounded allocation (e.g., reading a 4GB length prefix from 4 bytes and calling `Vec::with_capacity(len)` before checking `MAX_FRAME_SIZE`).
   - **Decode $\leftrightarrow$ Encode Round-Trip:** For any valid `Frame`, `Frame::decode(&frame.encode()) == Ok(frame)`.
3. **Cap Allocation Size on Length-Prefixed Protocols:**
   ```rust
   // HARDENED FRAME DECODER: Always validate `payload_len <= MAX_FRAME_BYTES`
   // BEFORE allocating `Vec::with_capacity(payload_len)`!
   pub const MAX_FRAME_BYTES: usize = 1024 * 1024; // 1 MiB ceiling

   pub fn decode_frame(input: &[u8]) -> Result<&[u8], &'static str> {
       if input.len() < 4 {
           return Err("incomplete_header");
       }
       let len = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
       if len > MAX_FRAME_BYTES {
           return Err("frame_exceeds_max_bytes"); // Prevents 4GB OOM DoS from 4-byte fuzz input!
       }
       if input.len() < 4 + len {
           return Err("incomplete_payload");
       }
       Ok(&input[4..4 + len])
   }
   ```

---

## 5. Autonomous Fuzz Lab Construction When Static Reading Plateaus (*Patch the Planet*, July 2026)

What should an agent do when auditing a mature, heavily scrutinized parser or protocol library where static code reading yields 0 bugs?

In Trail of Bits and OpenAI's **Patch the Planet** field reports ([July 2, 2026](https://blog.trailofbits.com/2026/07/02/field-reports-from-patch-the-planet/) and [July 28, 2026](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)), when `/goal` was pointed at **`zlib`**—one of the most heavily fuzzed C libraries on earth—the agent recognized that static code reading was a low-yield waste of tokens. Instead, **in under 24 hours, the agent autonomously designed and built a custom dynamic fuzzing laboratory** targeting three blind spots that standard `OSS-Fuzz` harnesses had missed for years:

1. **Compile-Time Feature & Variant Matrix Fuzzing:**
   - Standard CI fuzzers almost always compile a library with its single default feature set.
   - On `zlib`, the agent enumerated conditional compilation flags used in downstream production builds—such as `INFLATE_STRICT`, `BUILDFIXED`, `PKZIP_BUG_WORKAROUND`, and `ZLIB_CONST`—and compiled dedicated AddressSanitizer (`ASan`) + UndefinedBehaviorSanitizer (`UBSan`) fuzz binaries for each compile-time variant.
   - **Rule for Rust/TypeScript/C++:** Have your fuzz harness builder inspect `Cargo.toml` `[features]`, `#ifdef` guards, and runtime config flags (`config.strictMode`, `config.legacyCompat`) and compile/run fuzz targets across the **non-default feature matrix**.
2. **Environmental & OS Backpressure Injection (Fuzzing the I/O Boundary, Not Just Pure Buffers):**
   - Standard fuzz targets pass an in-memory byte slice to a pure function (`inflate()`), assuming I/O always succeeds atomically.
   - On `zlib`, the agent noticed that the `gz*` file-streaming state machine (`gzwrite`, `gzread`, `gzflush`) had complex buffer-refill and partial-flush recovery paths that only execute when the underlying OS file descriptor experiences **write backpressure (`EAGAIN` / `EWOULDBLOCK` or short partial writes)**. By wrapping the file descriptor in a custom fault-injecting shim driven by the fuzzer input stream, the agent reached deep state transitions inside `gz*` that pure memory-buffer fuzzers never touch.
   - **Rule for Web/Systems Code:** When fuzzing streaming parsers, WebSocket frame handlers, database poolers, or multipart uploaders, feed the fuzzer byte stream into **both** the payload bytes **and** the chunk-boundary / simulated-backpressure schedule (splitting frames into arbitrary 1-byte to $N$-byte partial reads and simulated transient write stalls).
3. **Historical Differential Fuzzing (`curl` Case Study):**
   - While auditing `curl`, Trail of Bits' agent compared behavior across historical release tags (`curl-7_51_0` vs. `HEAD`) alongside targeted dynamic harnesses, uncovering subtle state-handling bugs in `curl`'s HTTP `Strict-Transport-Security` (`HSTS`) parser, cookie engine, and SASL authentication state machine.
