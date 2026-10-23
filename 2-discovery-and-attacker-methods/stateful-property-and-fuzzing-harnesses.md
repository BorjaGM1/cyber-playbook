# Step 5: Stateful Property Testing, Entry-Point Fuzzing & Autonomous Fuzz Labs

## 1. Mental Model (Finding the 7-Step Logic Bug Nobody Thought to Write a Test For)

Hand-written unit tests and even single-request canary probes only test transitions 1 step deep (`Create Issue` $\to$ `Read Issue`). What happens when:
1. `Owner A` creates `Project 1` (public) and `Project 2` (restricted).
2. `Owner A` invites `Guest G` to `Project 1`.
3. `Guest G` creates an issue `I_1` inside `Project 1`, comments, and attaches a file `F_1`.
4. `Owner A` moves `I_1` from `Project 1` into `Project 2` (restricted).
5. `Owner A` removes `Guest G` from `Project 1`, then re-invites `Guest G` to a third project `Project 3`.
6. `Guest G` queries `/api/search`, `/api/attachments/{F_1}`, `/api/issues/{I_1}/history` or `/api/issues/{I_1}/comments`.

No human engineer writes a test for that specific sequence. **Stateful Property-Based Testing (`fast-check` in TypeScript, `proptest` / `proptest-state-machine` in Rust)** discovers it automatically by:
1. Maintaining a **tiny in-memory Reference Model** (a ~60-line idealized `Map` of who owns what, who is granted what, and *where each comment and history event was recorded*).
2. Generating thousands of random sequences of **Commands** (`CreateProject`, `InviteGuest`, `RevokeGuest`, `CreateIssue`, `CommentOnIssue`, `MoveIssue`, `DeleteIssue`, `SearchAsActor`, `ReadHistoryAsActor`) over a **small bounded ID domain** (2–3 projects, 2–3 issues) so collisions and re-use happen constantly.
3. Checking after **every single step** that the real application agrees with the Reference Model on **every read surface** (primary GET, list, search, comments, history, export), not just the one the command touched.
4. **Automatic Shrinking:** When a 17-step random sequence violates an invariant, the framework prunes redundant steps and hands you the **minimal 3- or 4-step sequence** that reproduces the bug.

**The model encodes the specification, not the implementation.** It must be written from `authz-matrix.yaml` ([`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md)), not by reading the handlers; a model copied from the code under test inherits its bugs.

---

## 2. Reference Pattern 1: Multi-Step Authorization & Lifecycle State Machine in TypeScript (`fast-check`)

The rule being specified: *a restricted guest may see an issue only if they currently hold a grant on the issue's current project, and may see a comment or history event only if they hold a grant on the project where it was recorded* (full members see everything in the tenant). After a move, pre-move comments and history stay hidden from guests who lack the old project.

```typescript
import fc from "fast-check";

// ---- Idealized Reference Model (spec, not implementation) -----------------------------------
interface ModelIssue {
  projectId: number;
  deleted: boolean;
  canary: string;
  comments: { id: number; recordedInProject: number; canary: string }[];
  history: { id: number; recordedInProject: number; canary: string }[];
}
interface Model {
  projects: Set<number>;
  grants: Set<number>;                     // projects on which Guest G currently holds a grant
  issues: Map<number, ModelIssue>;
  seq: number;
}
const newModel = (): Model => ({ projects: new Set(), grants: new Set(), issues: new Map(), seq: 0 });

const guestCanSeeIssue = (m: Model, i: ModelIssue) => !i.deleted && m.grants.has(i.projectId);
const guestCanSeeEvent = (m: Model, i: ModelIssue, e: { recordedInProject: number }) =>
  guestCanSeeIssue(m, i) && m.grants.has(e.recordedInProject);

// ---- System under test: a thin typed client over the lab (per-agent clone) ---------------------
interface Real {
  createProject(p: number): Promise<void>;
  grantGuest(p: number): Promise<void>;
  revokeGuest(p: number): Promise<void>;
  createIssue(i: number, p: number, canary: string): Promise<void>;
  commentAsOwner(i: number, canary: string): Promise<void>;
  moveIssue(i: number, toProject: number): Promise<void>;
  deleteIssue(i: number): Promise<void>;
  // Guest-visible surfaces — ALL of them:
  guestGetIssue(i: number): Promise<{ status: number; body: string }>;
  guestList(): Promise<string>;
  guestSearch(q: string): Promise<string>;
  guestComments(i: number): Promise<{ status: number; body: string }>;
  guestHistory(i: number): Promise<{ status: number; body: string }>;
  guestExport(): Promise<string>;
}

// ---- The oracle: after EVERY command, compare every surface to the model ------------------------
async function assertAllSurfaces(m: Model, r: Real): Promise<void> {
  const list = await r.guestList();
  const search = (c: string) => r.guestSearch(c);
  const exp = await r.guestExport();
  for (const [id, issue] of m.issues) {
    const seesIssue = guestCanSeeIssue(m, issue);
    const get = await r.guestGetIssue(id);
    if (!seesIssue) {
      if (get.status !== 404) throw new Error(`I2: GET issue ${id} -> ${get.status}, expected 404`);
      for (const [where, text] of [["list", list], ["export", exp], ["search", await search(issue.canary)]] as const) {
        if (text.includes(issue.canary)) throw new Error(`I2 side door: ${where} leaked canary of issue ${id}`);
      }
    }
    // comments and history are checked even when the issue is visible: this is the post-MOVE leak.
    const comments = await r.guestComments(id);
    const history = await r.guestHistory(id);
    for (const c of issue.comments) {
      const allowed = guestCanSeeEvent(m, issue, c);
      if (!allowed && comments.body.includes(c.canary)) throw new Error(`I2: comment ${c.id} (recorded in project ${c.recordedInProject}) visible after move/revoke`);
      if (!allowed && (await search(c.canary)).includes(c.canary)) throw new Error(`I2 side door: search leaked comment ${c.id}`);
    }
    for (const h of issue.history) {
      if (!guestCanSeeEvent(m, issue, h) && history.body.includes(h.canary)) throw new Error(`I2: history event ${h.id} (recorded in project ${h.recordedInProject}) visible`);
    }
    if (!seesIssue && (comments.status !== 404 || history.status !== 404)) {
      throw new Error(`I2: child collection of hidden issue ${id} returned ${comments.status}/${history.status} (must be 404, never 200 [])`);
    }
  }
}

// ---- Commands (each mutates BOTH the model and the real system, then runs the oracle) -------------
type Cmd = fc.AsyncCommand<Model, Real>;
const P = fc.integer({ min: 0, max: 2 });
const I = fc.integer({ min: 0, max: 2 });

const cmd = (name: string, check: (m: Model) => boolean, run: (m: Model, r: Real) => Promise<void>): Cmd => ({
  check, toString: () => name,
  run: async (m, r) => { await run(m, r); await assertAllSurfaces(m, r); },
});

const arbCommands: fc.Arbitrary<Cmd>[] = [
  P.map((p) => cmd(`CreateProject(${p})`, (m) => !m.projects.has(p),
    async (m, r) => { await r.createProject(p); m.projects.add(p); })),
  P.map((p) => cmd(`GrantGuest(${p})`, (m) => m.projects.has(p),
    async (m, r) => { await r.grantGuest(p); m.grants.add(p); })),
  P.map((p) => cmd(`RevokeGuest(${p})`, (m) => m.grants.has(p),
    async (m, r) => { await r.revokeGuest(p); m.grants.delete(p); })),
  fc.tuple(I, P).map(([i, p]) => cmd(`CreateIssue(${i}, in ${p})`, (m) => m.projects.has(p) && !m.issues.has(i),
    async (m, r) => {
      const canary = `cnry${++m.seq}x${Math.random().toString(36).slice(2, 12)}`;
      await r.createIssue(i, p, canary);
      m.issues.set(i, { projectId: p, deleted: false, canary, comments: [], history: [{ id: ++m.seq, recordedInProject: p, canary }] });
    })),
  I.map((i) => cmd(`Comment(${i})`, (m) => !!m.issues.get(i) && !m.issues.get(i)!.deleted,
    async (m, r) => {
      const issue = m.issues.get(i)!;
      const canary = `cmnt${++m.seq}x${Math.random().toString(36).slice(2, 12)}`;
      await r.commentAsOwner(i, canary);
      issue.comments.push({ id: m.seq, recordedInProject: issue.projectId, canary });
    })),
  fc.tuple(I, P).map(([i, p]) => cmd(`MoveIssue(${i} -> ${p})`, (m) => !!m.issues.get(i) && !m.issues.get(i)!.deleted && m.projects.has(p),
    async (m, r) => {
      await r.moveIssue(i, p);
      const issue = m.issues.get(i)!;
      issue.projectId = p;
      issue.history.push({ id: ++m.seq, recordedInProject: p, canary: `move${m.seq}` });
    })),
  I.map((i) => cmd(`DeleteIssue(${i})`, (m) => !!m.issues.get(i) && !m.issues.get(i)!.deleted,
    async (m, r) => { await r.deleteIssue(i); m.issues.get(i)!.deleted = true; })),
];

test("guest visibility holds across every lifecycle sequence and every read surface", async () => {
  await fc.assert(
    fc.asyncProperty(fc.commands(arbCommands, { maxCommands: 25 }), async (cmds) => {
      const real = await freshLabClone();                         // per-run DB clone, see isolated-lab note
      try { await fc.asyncModelRun(() => ({ model: newModel(), real }), cmds); }
      finally { await real.destroy(); }
    }),
    { numRuns: 200, verbose: 1 }
  );
});
```

If the search API echoes the query string back (`"results for cnry3x…"`), have `guestSearch` remove the echoed query from the body before returning it, otherwise every search probe is a false positive.

`freshLabClone()` returns a `Real` backed by a fresh database cloned from the seed template. Because the comment/history canaries are recorded with the project in which they were created, the oracle catches exactly the pre-move leak the previous version of this example promised and never asserted.

---

## 3. Reference Pattern 2: Stateful Property Testing in Rust (`proptest`)

```rust
use proptest::prelude::*;
use proptest_derive::Arbitrary;
use std::collections::{HashMap, HashSet};

// Small bounded domains force collisions and reuse; proptest shrinks sequences automatically.
#[derive(Debug, Clone, Arbitrary)]
enum AuthAction {
    CreateProject { #[proptest(strategy = "0u8..3")] proj_id: u8 },
    GrantGuest    { #[proptest(strategy = "0u8..3")] proj_id: u8 },
    RevokeGuest   { #[proptest(strategy = "0u8..3")] proj_id: u8 },
    CreateIssue   { #[proptest(strategy = "0u8..3")] issue_id: u8, #[proptest(strategy = "0u8..3")] proj_id: u8 },
    Comment       { #[proptest(strategy = "0u8..3")] issue_id: u8 },
    MoveIssue     { #[proptest(strategy = "0u8..3")] issue_id: u8, #[proptest(strategy = "0u8..3")] to_proj_id: u8 },
    MintAndRevokeApiKey,
}

#[derive(Default)]
struct Model {
    guest_projects: HashSet<u8>,
    issue_project: HashMap<u8, u8>,
    // (issue, recorded-in project, canary) for comments and history events
    events: Vec<(u8, u8, String)>,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]
    #[test]
    fn prop_guest_and_revoked_actor_never_leak_across_any_transition_sequence(
        actions in prop::collection::vec(any::<AuthAction>(), 1..25)
    ) {
        // RealStore is the PRODUCTION store behind the production service layer, in-memory test engine.
        let mut store = RealStore::new_in_memory();
        let mut m = Model::default();
        let mut n = 0u32;

        for action in actions {
            match action {
                AuthAction::CreateProject { proj_id } => store.ensure_project(proj_id),
                AuthAction::GrantGuest { proj_id } => { if store.has_project(proj_id) { store.grant_guest("guest_1", proj_id); m.guest_projects.insert(proj_id); } }
                AuthAction::RevokeGuest { proj_id } => { store.revoke_guest("guest_1", proj_id); m.guest_projects.remove(&proj_id); }
                AuthAction::CreateIssue { issue_id, proj_id } => {
                    if store.has_project(proj_id) && !m.issue_project.contains_key(&issue_id) {
                        n += 1;
                        let canary = format!("cnry{n}xq{issue_id}");
                        store.upsert_issue(issue_id, proj_id, &canary);
                        m.issue_project.insert(issue_id, proj_id);
                        m.events.push((issue_id, proj_id, canary));
                    }
                }
                AuthAction::Comment { issue_id } => {
                    if let Some(&p) = m.issue_project.get(&issue_id) {
                        n += 1;
                        let canary = format!("cmnt{n}xq{issue_id}");
                        store.comment(issue_id, &canary);
                        m.events.push((issue_id, p, canary));          // recorded in the CURRENT project
                    }
                }
                AuthAction::MoveIssue { issue_id, to_proj_id } => {
                    if store.has_project(to_proj_id) && m.issue_project.contains_key(&issue_id) {
                        store.move_issue(issue_id, to_proj_id);
                        m.issue_project.insert(issue_id, to_proj_id);
                    }
                }
                AuthAction::MintAndRevokeApiKey => {
                    let raw = store.mint_key("guest_1");
                    store.revoke_key(&raw);
                    prop_assert!(store.authenticate_key(&raw).is_err());
                }
            }

            // Oracle after EVERY transition: primary CRUD, search, comments and history for `guest_1`.
            for (&issue_id, &proj_id) in &m.issue_project {
                let sees_issue = m.guest_projects.contains(&proj_id);
                prop_assert_eq!(store.read_issue_as_guest("guest_1", issue_id).is_ok(), sees_issue, "CRUD mismatch on issue {}", issue_id);
                let comments = store.comments_as_guest("guest_1", issue_id);
                let history  = store.history_as_guest("guest_1", issue_id);
                if !sees_issue {
                    prop_assert!(comments.is_err() && history.is_err(), "child collection of hidden issue {} must be an error, not an empty list", issue_id);
                }
                for (ev_issue, recorded_in, canary) in m.events.iter().filter(|e| e.0 == issue_id) {
                    let allowed = sees_issue && m.guest_projects.contains(recorded_in);
                    let in_search = store.search_as_guest("guest_1", canary);
                    prop_assert_eq!(in_search, allowed, "search side door for event of issue {} recorded in {}", ev_issue, recorded_in);
                    if !allowed {
                        prop_assert!(!comments.as_ref().map_or(false, |c| c.contains(canary)), "comment leaked after move/revoke");
                        prop_assert!(!history.as_ref().map_or(false, |h| h.contains(canary)), "history leaked after move/revoke");
                    }
                }
            }
        }
    }
}
```

`RealStore` stands for the production service layer under an in-memory test engine—never a re-implementation. For an HTTP application, use the TypeScript pattern above against the lab clone.

---

## 4. Generating the Command Alphabet Instead of Hand-Writing It

Hand-written command sets miss the one mutating route nobody remembered. Generate the alphabet from the surface map's **capability graph** ([`surface-and-sink-mapping.md`](surface-and-sink-mapping.md), Table F) and the OpenAPI document: every mutating route tagged with an *effect* that changes who can see what is a command.

```javascript
// gen-commands.mjs — emit command skeletons for every permission-changing route
import { readFileSync, writeFileSync } from "node:fs";
const map = JSON.parse(readFileSync("SECURITY_SURFACE_MAP.json", "utf8"));
const EFFECTS = new Set(["grant_membership", "revoke_membership", "change_role", "move_parent",
                         "change_visibility", "delete", "restore", "transfer_owner", "create", "rotate_credential"]);
const lines = [];
for (const edge of map.capabilityGraph) {
  if (!EFFECTS.has(edge.effect)) continue;
  const params = Object.entries(edge.params ?? {})
    .map(([name, kind]) => `${name}: ${kind}Arb`).join(", ");
  lines.push(`// ${edge.method} ${edge.route}  effect=${edge.effect} entity=${edge.entity}`);
  lines.push(`export const ${edge.effect}_${edge.entity}_${edge.operationId} = fc.record({ ${params} })` +
             `.map((a) => cmd(\`${edge.operationId}(\${JSON.stringify(a)})\`, preconditionFor("${edge.effect}", "${edge.entity}"), runVia("${edge.method}", "${edge.route}", a)));`);
}
writeFileSync("commands.generated.ts", lines.join("\n") + "\n");
```

Each `kind` (`ProjectId`, `IssueId`, `UserId`) maps to a bounded arbitrary (`fc.integer({min:0,max:2})`). Every new permission-changing route then enters the stateful search automatically; a route present in the capability graph but absent from the command set fails CI (`coverage.json`: `statefulAlphabetMissing`).

### Chain Agent (LLM Proposes, Harness Disposes)

Random generation reaches many sequences but few *interesting* ones at depth 6+. A **chain agent** reads the capability graph (not the whole repo) and proposes targeted sequences ("grant → create → move → revoke → export" for each entity with a parent FK and a visibility rule). The harness executes each proposed sequence against a lab clone and runs the full-surface oracle after every step; the agent never decides whether a chain "worked". Surviving violations are shrunk by the property-testing framework into a minimal PoV. Dispatch rules and budgets: [`autonomous-micro-agent-red-teaming.md`](autonomous-micro-agent-red-teaming.md).

---

## 5. Coverage-Guided Fuzzing & The Entry-Point Rule (`OSS-Fuzz-Gen` + `FalseCrashReducer`, 2026)

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

## 6. Autonomous Fuzz Lab Construction When Static Reading Plateaus (*Patch the Planet*, July 2026)

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
