# Step 6: Bounded Formal & Symbolic Verification (`Kani`, `Alloy` & `TLA+`)

## 1. Mental Model (Mathematical Proof on the Critical 300 Lines)

Fuzzing and property-based testing run 1,000 to 1,000,000 random inputs. That catches most bugs, but what if a parser or authorization check only fails when a specific 32-bit integer equals `0x7fff_ffff` or when a specific combination of 4 boolean flags occurs?

You do **not** try to formally verify a 50,000-line web application (intractable and a waste of engineering time). Instead, you apply **Bounded Symbolic Model Checking** to the **critical ~300 lines of pure logic** where a single edge case compromises the entire system:
1. **Rust Symbolic Proof Harnesses (`Kani`):** bit-precise symbolic execution (CBMC under the hood) on standard Rust functions. Instead of passing random inputs, `kani::any()` represents **all possible values simultaneously** up to a bounded size, proving zero panics, zero integer overflows, and adherence to assertions—or outputting a concrete counterexample trace.
2. **Relational / State-Machine Model Checking (`Alloy` / `TLA+`):** models your authorization hierarchy (`Organization` $\to$ `Team` $\to$ `Project` $\to$ `Issue` $\to$ `History` with `Owner`, `Member`, `Guest`, and `IssueMove` transitions) in about 60 lines and exhaustively checks every configuration up to $N$ nodes in seconds.

---

## 2. Rules That Separate Verification From Theater

A proof of a *copy* of your logic, or a property that restates the code, produces a green checkmark and no assurance. An earlier version of the examples in this file made both mistakes: the Kani harness defined its own `evaluate_access` inside the proof module (so it proved a copy), its state had a `has_guest_project_grant` boolean that was **never tied to the resource's project** (so the "proved" specification allowed a guest granted project 1 to read a project 2 resource—the very bug class under study), and the Alloy assertion `canViewHistoryHardened implies (…)` merely restated one conjunct of the predicate, so the check could not fail and was never run against the vulnerable predicate. Enforce these rules:

| # | Rule | Check |
|---|------|-------|
| 1 | **Verify the production symbol.** Import it; never copy the function into the proof module. | `use crate::access::can_read;` — the harness has no private reimplementation |
| 2 | **Write the specification independently**, from `authz-matrix.yaml`, in a *different structure* (truth table / necessary conditions), not by transcribing the `if` chain. | Spec reviewed by someone who has not read the implementation |
| 3 | **State necessary conditions (safety) and sufficient cases (liveness).** A function that always returns `false` satisfies every "must never allow" assertion. | At least one `assert!(allowed)` per legitimate role; Alloy `run` shows a satisfying instance |
| 4 | **Positive control.** Run the same harness on the known-bad variant; it must produce a counterexample. | A kept `vulnerable_*` function or Alloy predicate whose `check` is expected to fail in CI |
| 5 | **Document the bound** (input length, number of projects, `unwind`) and why a bug cannot hide beyond it. | Bound ≥ longest attack sequence (e.g., ≥ 6 bytes for an escape marker) |
| 6 | **Make the model include every field the real decision reads**, especially the foreign keys that bind a grant to a resource. | Compare the struct fields to the production `Principal`/`Resource` types |

---

## 3. Where Bounded Formal Verification Gives High ROI

Apply `Kani` (Rust) or `Alloy`/`Z3` (TypeScript/SQL state models) exclusively to these four targets:
1. **Authentication & Host/Header Parsers:** proving `is_exact_loopback_host`, JWT header parsing, and cookie purpose-prefix verification can never panic or accept a malformed prefix across all byte sequences of length $\le N$.
2. **Binary Frame Decoders & Terminal Sanitizers:** proving `decode_frame` and `sanitize_and_wrap_bracketed_paste` never panic, never allocate beyond `MAX_FRAME_BYTES`, and never emit an unescaped `0x1b` (`ESC`) byte inside the bracketed paste body.
3. **Access-Control Decision Matrices:** proving that for **all** combinations of `(ActorRole, OrgMatch, ProjectGrant, KeyRevoked, UserDisabled)`, a revoked actor or cross-tenant caller is **never** granted read or write access, **and a guest is granted access only to the exact project of the grant**.
4. **Ledger, Fee & Quota Arithmetic:** proving that fixed-point credit/currency calculations never overflow `i64`, never round in favor of creating free credits, and preserve conservation (`sender_delta + receiver_delta + fee == 0`).

To make target 3 provable, extract the decision into a **pure function over plain data** (no I/O). That extraction is also good design: the same function is called by the repository layer, the query-log oracle's expected-visibility model, and the proof.

---

## 4. Concrete Example 1: Kani Proof of the REAL Access Decision & Terminal Paste Sanitizer (Rust)

Install Kani (`cargo install --locked kani-verifier && cargo kani setup`).

### 4.1 The production decision function (the thing being verified)

```rust
// src/access.rs — PRODUCTION code, also used by the repository layer
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role { Owner, Member, Guest }

#[derive(Clone, Copy)]
pub struct Principal {
    pub org_id: u32,
    pub role: Role,
    pub credential_revoked: bool,
    pub user_disabled: bool,
    /// bit p is set iff the principal holds a live guest grant on project p (p < 64)
    pub guest_project_mask: u64,
}

#[derive(Clone, Copy)]
pub struct Resource { pub org_id: u32, pub project_id: u8 }

pub fn can_read(p: &Principal, r: &Resource) -> bool {
    if p.credential_revoked || p.user_disabled { return false; }
    if p.org_id != r.org_id { return false; }
    match p.role {
        Role::Owner | Role::Member => true,
        Role::Guest => r.project_id < 64 && (p.guest_project_mask >> r.project_id) & 1 == 1,
    }
}
```

(If the `r.project_id < 64` guard were missing, Kani would report a shift-overflow counterexample at `project_id >= 64`—a bug the original copy-based harness could not have found.)

### 4.2 The proof harness (specification written independently as a truth table)

```rust
#[cfg(kani)]
mod proofs {
    use super::*;                                   // imports the PRODUCTION can_read, Principal, Resource

    fn any_role() -> Role {
        match kani::any::<u8>() % 3 { 0 => Role::Owner, 1 => Role::Member, _ => Role::Guest }
    }
    fn any_principal() -> Principal {
        Principal {
            org_id: kani::any(), role: any_role(),
            credential_revoked: kani::any(), user_disabled: kani::any(),
            guest_project_mask: kani::any(),
        }
    }
    fn any_resource() -> Resource { Resource { org_id: kani::any(), project_id: kani::any() } }

    /// Independent spec (from authz-matrix.yaml), deliberately NOT the same shape as `can_read`.
    fn spec_allows(p: &Principal, r: &Resource) -> bool {
        let live = !p.credential_revoked && !p.user_disabled;
        let same_org = p.org_id == r.org_id;
        let granted_on_this_project = r.project_id < 64 && (p.guest_project_mask & (1u64 << (r.project_id % 64))) != 0;
        match (live, same_org, p.role) {
            (true, true, Role::Owner) | (true, true, Role::Member) => true,
            (true, true, Role::Guest) => granted_on_this_project,
            _ => false,
        }
    }

    /// SAFETY (necessary conditions) — hold for ALL symbolic states (every org id, role, flag combination, grant mask and project id).
    #[kani::proof]
    fn proof_never_allows_when_spec_forbids() {
        let (p, r) = (any_principal(), any_resource());
        let allowed = can_read(&p, &r);
        if p.credential_revoked || p.user_disabled { assert!(!allowed, "revoked/disabled principal allowed"); }
        if p.org_id != r.org_id                    { assert!(!allowed, "cross-tenant principal allowed"); }
        if matches!(p.role, Role::Guest) && r.project_id < 64 && (p.guest_project_mask >> r.project_id) & 1 == 0 {
            assert!(!allowed, "guest without a grant on THIS project allowed (grant on another project must not count)");
        }
    }

    /// LIVENESS (sufficient cases) — a function that returns `false` always must fail here.
    #[kani::proof]
    fn proof_allows_legitimate_actors() {
        let (p, r) = (any_principal(), any_resource());
        kani::assume(!p.credential_revoked && !p.user_disabled && p.org_id == r.org_id);
        kani::assume(matches!(p.role, Role::Owner | Role::Member));
        assert!(can_read(&p, &r), "live same-org member/owner denied");
    }

    /// Full equivalence with the independent truth-table spec (catches both over- and under-grant).
    #[kani::proof]
    fn proof_matches_independent_spec() {
        let (p, r) = (any_principal(), any_resource());
        assert_eq!(can_read(&p, &r), spec_allows(&p, &r));
    }

    /// Bracketed-paste sanitizer: REAL function, exhaustive over every 8-byte input.
    /// The bound (8) exceeds the 6-byte ESC[201~ marker, so any marker-shaped sequence plus context is covered.
    #[kani::proof]
    #[kani::unwind(10)]
    fn proof_bracketed_paste_never_contains_inner_escape() {
        let raw_bytes: [u8; 8] = kani::any();
        if let Ok(input_str) = core::str::from_utf8(&raw_bytes) {
            let framed = crate::terminal::sanitize_and_wrap_bracketed_paste(input_str);   // PRODUCTION symbol
            assert!(framed.len() >= 12);
            assert_eq!(&framed[..6], b"\x1b[200~");
            assert_eq!(&framed[framed.len() - 6..], b"\x1b[201~");
            for &b in &framed[6..framed.len() - 6] {
                assert_ne!(b, 0x1b, "inner paste payload must never contain ESC (0x1b)");
            }
        }
    }
}
```

### 4.3 Positive control (the harness must be able to fail)

Keep the broken decision in the test tree and assert the proof fails on it:

```rust
#[cfg(kani)]
mod positive_control {
    use super::*;
    /// Known-bad: a guest with ANY grant is allowed (the original copy-based model's bug).
    fn can_read_any_grant(p: &Principal, r: &Resource) -> bool {
        if p.credential_revoked || p.user_disabled || p.org_id != r.org_id { return false; }
        match p.role { Role::Owner | Role::Member => true, Role::Guest => p.guest_project_mask != 0 }
    }
    #[kani::proof]
    #[kani::should_panic]      // Kani must find the counterexample, otherwise the safety harness is blind
    fn bad_variant_is_refuted() {
        let p = Principal { org_id: kani::any(), role: Role::Guest, credential_revoked: false, user_disabled: false, guest_project_mask: kani::any() };
        let r = Resource { org_id: p.org_id, project_id: kani::any() };
        kani::assume(r.project_id < 64 && (p.guest_project_mask >> r.project_id) & 1 == 0);
        assert!(!can_read_any_grant(&p, &r));
    }
}
```

---

## 5. Concrete Example 2: Alloy Relational Model for Cross-Project Issue Moves & History

Before implementing complex permission hierarchies (guests, issue moves across projects, historical audit logs), verify the relational design in **Alloy 6**. The assertion states *necessary conditions of the specification*; the predicates are the candidate implementations. The check is run on **both** predicates: it must fail for the vulnerable one and hold for the hardened one.

```alloy
module tenancy_isolation

sig Org {}
sig Project { org: one Org }
sig User {
  memberOf: set Org,            // full members
  guestProjects: set Project    // live guest grants
}
sig Issue {
  org: one Org,
  currentProject: one Project,
  historyEvents: set HistoryEvent
}
sig HistoryEvent {
  recordedInProject: one Project   // the project the issue lived in WHEN the event was recorded
}

fact structural_consistency {
  all i: Issue | i.currentProject.org = i.org
  all i: Issue, h: i.historyEvents | h.recordedInProject.org = i.org
  all h: HistoryEvent | one i: Issue | h in i.historyEvents
}

pred canViewIssue[u: User, i: Issue] {
  i.org in u.memberOf or i.currentProject in u.guestProjects
}

// CANDIDATE 1 — VULNERABLE: authorizes against the issue's CURRENT project only.
pred canViewHistoryVulnerable[u: User, i: Issue, h: HistoryEvent] {
  h in i.historyEvents and canViewIssue[u, i]
}

// CANDIDATE 2 — HARDENED: additionally requires access to the project where the event was recorded.
pred canViewHistoryHardened[u: User, i: Issue, h: HistoryEvent] {
  h in i.historyEvents
  and canViewIssue[u, i]
  and (i.org in u.memberOf or h.recordedInProject in u.guestProjects)
}

// SPECIFICATION (necessary conditions, independent of either candidate):
// a user who is not a full member of the issue's org may be shown an event
// ONLY IF they hold a grant on the project where the event was recorded.
pred specNecessary[u: User, i: Issue, h: HistoryEvent] {
  (i.org not in u.memberOf) implies h.recordedInProject in u.guestProjects
}

// The hardened candidate must satisfy the spec for every instance within scope: expected to HOLD.
assert HardenedRespectsSpec {
  all u: User, i: Issue, h: HistoryEvent | canViewHistoryHardened[u, i, h] implies specNecessary[u, i, h]
}
check HardenedRespectsSpec for 6

// The vulnerable candidate must violate the spec: Alloy MUST produce a counterexample
// (a guest granted only on Public, an issue moved Secret -> Public, an event recorded in Secret).
assert VulnerableRespectsSpec {
  all u: User, i: Issue, h: HistoryEvent | canViewHistoryVulnerable[u, i, h] implies specNecessary[u, i, h]
}
check VulnerableRespectsSpec for 6

// LIVENESS: the hardened predicate is satisfiable (it is not vacuously "deny all").
run { some u: User, i: Issue, h: HistoryEvent | canViewHistoryHardened[u, i, h] and i.org not in u.memberOf } for 4
```

Expected results in CI: `HardenedRespectsSpec` — no counterexample; `VulnerableRespectsSpec` — counterexample found (this is the **positive control**; if Alloy finds no counterexample, the model is too weak or the bound too small); `run` — instance found.

The counterexample Alloy prints is the exact multi-step story: an issue created in `Project Secret`, an event recorded there, the issue moved to `Project Public`, and a guest granted only on `Project Public` who now sees the Secret-era event.

---

## 6. Workflow

1. Extract the pure decision function(s). Keep them in a module with no I/O.
2. Write the spec from `authz-matrix.yaml`, in a different structure than the implementation.
3. Write safety, liveness and equivalence harnesses plus a positive control.
4. Run `cargo kani` for changed pure-logic modules in the PR gate ([`../baselines/pre-deploy-security-pipeline.md`](../baselines/pre-deploy-security-pipeline.md)); run Alloy checks when the permission model changes.
5. Treat a Kani/Alloy result as bounded: record the bound in `coverage.json`, and rely on the stateful tests ([`stateful-property-and-fuzzing-harnesses.md`](stateful-property-and-fuzzing-harnesses.md)) for sequences the bound excludes.
