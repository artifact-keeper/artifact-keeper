/-!
# Age-gate check decision

A model of `decide_age_gate_check`
(`backend/src/services/age_gate_service.rs`): given the review row for a
version (if any) and whether the version meets the age threshold on the
current clock, what the gate does.

The function is a list of rules applied in order. This file states what those
rules add up to: exactly when a version is served.
-/

namespace ArtifactKeeper.AgeGate.CheckDecision

/-- `AgeGateReviewStatus`, plus `other` for a status this build does not know. -/
inductive ReviewStatus where
  | pending | approved | rejected | other
  deriving DecidableEq, Repr

/-- `ReviewIdentityMatch`: how the identity an approval was bound to compares
with the current policy's. `legacy` is an approval from before identities. -/
inductive Identity where
  | matches | legacy | differs
  deriving DecidableEq, Repr

/-- `ReviewPolicyView`, reduced to what the decision reads. -/
structure Review where
  status : ReviewStatus
  isAutomatic : Bool
  identity : Identity
  deriving DecidableEq, Repr

/-- `AgeGateCheckAction`. -/
inductive Action where
  | allow
  | blockRejected
  | allowAndAutoApprovePending
  | allowAlreadyApproved
  | blockAndRequestReview
  | blockAndResetReview
  deriving DecidableEq, Repr

def Action.serves : Action → Bool
  | .allow | .allowAndAutoApprovePending | .allowAlreadyApproved => true
  | .blockRejected | .blockAndRequestReview | .blockAndResetReview => false

/-- `decide_age_gate_check`, rule for rule. -/
def decide (existing : Option Review) (meetsThreshold : Bool) : Action :=
  match existing with
  | some r =>
    if r.status = .rejected then .blockRejected
    else if meetsThreshold then
      if r.status = .pending then .allowAndAutoApprovePending else .allow
    else if r.status = .approved then
      if r.isAutomatic = false ∧ r.identity ≠ .differs then .allowAlreadyApproved
      else .blockAndResetReview
    else .blockAndRequestReview
  | none => if meetsThreshold then .allow else .blockAndRequestReview

/-- A manual approval that the current policy still honours. -/
def HonouredManualApproval (r : Review) : Prop :=
  r.status = .approved ∧ r.isAutomatic = false ∧ r.identity ≠ .differs

/-- A rejection blocks, whatever the clock says and whatever else the row holds. -/
theorem rejection_always_blocks (r : Review) (meets : Bool) (h : r.status = .rejected) :
    (decide (some r) meets).serves = false := by
  simp [decide, h, Action.serves]

/-- The whole decision in one line: a version is served exactly when it is not
rejected and either meets the threshold or carries a manual approval the
current policy still honours. -/
theorem serves_iff (existing : Option Review) (meets : Bool) :
    (decide existing meets).serves = true ↔
      (∀ r, existing = some r → r.status ≠ .rejected) ∧
        (meets = true ∨ ∃ r, existing = some r ∧ HonouredManualApproval r) := by
  cases existing with
  | none =>
    cases meets <;> simp [decide, Action.serves]
  | some r =>
    obtain ⟨status, isAutomatic, identity⟩ := r
    cases status <;> cases meets <;> cases isAutomatic <;> cases identity <;>
      simp [decide, Action.serves, HonouredManualApproval]

/-- Below the threshold, an automatic approval never serves a version: it is
only ever a cache of "the age check passed", which the current clock has just
contradicted. -/
theorem automatic_approval_never_serves_below_threshold (r : Review)
    (hauto : r.isAutomatic = true) : (decide (some r) false).serves = false := by
  obtain ⟨status, isAutomatic, identity⟩ := r
  cases status <;> cases identity <;> simp_all [decide, Action.serves]

/-- Below the threshold, an approval bound to a different identity (a repointed
upstream, a switched mode) never serves a version. -/
theorem approval_for_another_identity_never_serves_below_threshold (r : Review)
    (hid : r.identity = .differs) : (decide (some r) false).serves = false := by
  obtain ⟨status, isAutomatic, identity⟩ := r
  cases status <;> cases isAutomatic <;> simp_all [decide, Action.serves]

end ArtifactKeeper.AgeGate.CheckDecision
