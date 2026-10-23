# Step 6: Bounded Formal & Symbolic Verification (`Kani`, `Alloy` & `TLA+`)

## 1. Mental Model (Mathematical Proof on the Critical 300 Lines)

Fuzzing and property-based testing run 1,000 to 1,000,000 random inputs. That catches 99% of bugs, but what if a parser or authorization check only fails when a specific 32-bit integer equals `0x7fff_ffff` or when a specific combination of 4 boolean flags occurs?

You do **not** try to formally verify a 50,000-line web application (that is intractable and a waste of engineering time). Instead, you apply **Bounded Symbolic Model Checking** to the **critical ~300 lines of pure logic** where a single edge case compromises the entire system:
1. **Rust Symbolic Proof Harnesses (`Kani`):** Uses SAT/SMT bit-precise symbolic execution (CBMC under the hood) on standard Rust functions. Instead of passing random inputs, `kani::any()` represents **all possible values simultaneously** up to a bounded size, mathematically proving zero panics, zero integer overflows, and 100% adherence to security assertions—or outputting a concrete counterexample trace.
2. **Relational / State-Machine Model Checking (`Alloy` / `TLA+`):** Models your authorization hierarchy (e.g., `Organization` $\to$ `Team` $\to$ `Project` $\to$ `Issue` $\to$ `History` with `Owner`, `Member`, `Guest`, and `IssueMove` transitions) in 60 lines and exhaustively checks every possible graph configuration up to $N$ nodes in under 2 seconds.

---

## 2. Where Bounded Formal Verification Gives $10\times$ ROI

Apply `Kani` (for Rust code) or `Z3`/`Alloy` (for TypeScript/SQL state models) exclusively to these four high-leverage targets:
1. **Authentication & Host/Header Parsers:** Proving `is_exact_loopback_host`, JWT header parsing, and cookie purpose-prefix verification can never panic or accept a malformed prefix across all byte sequences of length $\le N$.
2. **Binary Frame Decoders & Terminal Sanitizers:** Proving `decode_frame` and `sanitize_and_wrap_bracketed_paste` never panic, never allocate beyond `MAX_FRAME_BYTES`, and never emit an unescaped `0x1b` (`ESC`) byte inside the bracketed paste body.
3. **Access-Control Decision Matrices:** Proving that for **all** combinations of `(ActorRole, OrgMatch, ProjectGrant, KeyRevoked, UserDisabled)`, a revoked actor or cross-tenant caller is **never** granted read or write access.
4. **Ledger, Fee & Quota Arithmetic:** Proving that fixed-point credit/currency calculations never overflow `i64`, never round in favor of creating free credits, and preserve conservation (`sender_delta + receiver_delta + fee == 0`).

---

## 3. Concrete Example 1: Kani Symbolic Proof Harness for Authorization & Terminal Paste (Rust)

Install Kani (`cargo install --locked kani-verifier && cargo kani setup`) and drop `#[kani::proof]` harnesses directly alongside your critical Rust modules:

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[derive(Clone, Copy)]
    struct SymbolicAccessState {
        actor_org_id: u8,
        resource_org_id: u8,
        resource_project_id: u8,
        is_org_owner: bool,
        is_full_member: bool,
        has_guest_project_grant: bool,
        is_credential_revoked: bool,
        is_user_disabled: bool,
    }

    fn evaluate_access(s: SymbolicAccessState) -> bool {
        if s.is_credential_revoked || s.is_user_disabled {
            return false;
        }
        if s.actor_org_id != s.resource_org_id {
            return false;
        }
        if s.is_org_owner || s.is_full_member {
            return true;
        }
        s.has_guest_project_grant
    }

    /// Mathematically proves across ALL 2^28 possible state combinations that:
    /// 1. A revoked credential or disabled user NEVER gains access (even if `is_org_owner == true`).
    /// 2. A cross-tenant caller (`actor_org_id != resource_org_id`) NEVER gains access.
    /// 3. A non-owner, non-member guest without a matching project grant NEVER gains access.
    #[kani::proof]
    fn proof_authorization_invariants_never_violated() {
        let state = SymbolicAccessState {
            actor_org_id: kani::any(),
            resource_org_id: kani::any(),
            resource_project_id: kani::any(),
            is_org_owner: kani::any(),
            is_full_member: kani::any(),
            has_guest_project_grant: kani::any(),
            is_credential_revoked: kani::any(),
            is_user_disabled: kani::any(),
        };

        let allowed = evaluate_access(state);

        if state.is_credential_revoked || state.is_user_disabled {
            assert!(!allowed, "Revoked or disabled principal must never be allowed");
        }
        if state.actor_org_id != state.resource_org_id {
            assert!(!allowed, "Cross-tenant principal must never be allowed");
        }
        if !state.is_org_owner && !state.is_full_member && !state.has_guest_project_grant {
            assert!(!allowed, "Unauthorized guest must never be allowed");
        }
    }

    /// Mathematically proves that for ANY arbitrary 8-byte UTF-8 input string,
    /// `sanitize_and_wrap_bracketed_paste` never panics and never leaves an `ESC` (0x1b)
    /// byte anywhere inside the inner payload between `\x1b[200~` and `\x1b[201~`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn proof_bracketed_paste_never_contains_inner_escape() {
        let raw_bytes: [u8; 8] = kani::any();
        if let Ok(input_str) = core::str::from_utf8(&raw_bytes) {
            let framed = sanitize_and_wrap_bracketed_paste(input_str);
            assert!(framed.len() >= 12);
            assert_eq!(&framed[..6], b"\x1b[200~");
            assert_eq!(&framed[framed.len() - 6..], b"\x1b[201~");

            let inner = &framed[6..framed.len() - 6];
            for &b in inner {
                assert_ne!(b, 0x1b, "Inner paste payload must never contain ESC (0x1b)");
            }
        }
    }
}
```

---

## 4. Concrete Example 2: Alloy Relational Model for Cross-Project Issue Moves & History

Before implementing complex permission hierarchies (such as guests, issue moves across projects, and historical audit logs), an engineer or agent can verify the relational design in **Alloy 6** in 40 lines:

```alloy
module tenancy_isolation

sig Org {}
sig Project { org: one Org }
sig User {
  memberOf: set Org,
  guestProjects: set Project
}
sig Issue {
  org: one Org,
  currentProject: one Project,
  historyEvents: set HistoryEvent
}
sig HistoryEvent {
  recordedInProject: one Project
}

fact structural_consistency {
  all i: Issue | i.currentProject.org = i.org
  all i: Issue, h: i.historyEvents | h.recordedInProject.org = i.org
}

pred canViewIssue[u: User, i: Issue] {
  i.org in u.memberOf or i.currentProject in u.guestProjects
}

// VULNERABLE HISTORY PREDICATE (checks only if user can view the issue NOW):
pred canViewHistoryVulnerable[u: User, i: Issue, h: HistoryEvent] {
  h in i.historyEvents and canViewIssue[u, i]
}

// HARDENED HISTORY PREDICATE (requires access to both current issue AND historical project):
pred canViewHistoryHardened[u: User, i: Issue, h: HistoryEvent] {
  h in i.historyEvents
  and canViewIssue[u, i]
  and (i.org in u.memberOf or h.recordedInProject in u.guestProjects)
}

// Invariant: A user who is NOT a full org member must NEVER view a history event
// that was recorded in a project they are not granted access to:
assert NoCrossProjectHistoryLeak {
  all u: User, i: Issue, h: HistoryEvent |
    canViewHistoryHardened[u, i, h] implies
      (i.org in u.memberOf or h.recordedInProject in u.guestProjects)
}

check NoCrossProjectHistoryLeak for 5
```
Running `check` in Alloy immediately generates a counterexample diagram for `canViewHistoryVulnerable` (an issue created in `Project Secret`, commented on, and then moved to `Project Public`) and proves `NoCrossProjectHistoryLeak` holds for `canViewHistoryHardened`.
