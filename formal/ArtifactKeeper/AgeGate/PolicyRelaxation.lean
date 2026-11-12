/-!
# Age-gate policy relaxation

A model of `AgeGatePolicy::is_relaxed_by`
(`backend/src/services/age_gate_service.rs`, #4238).

A repository administrator may change an instance-locked policy only in ways
that do not relax it. The check looks at one change at a time, so the question
is whether a run of individually allowed changes can add up to a relaxation.
It cannot: this file proves the gate stays enabled, in the same mode, with a
minimum age that never drops.
-/

namespace ArtifactKeeper.AgeGate.PolicyRelaxation

/-- `AgeGateMode`. -/
inductive Mode where
  | upstreamPublishTime | firstSeen
  deriving DecidableEq, Repr

/-- `AgeGatePolicy`. -/
structure Policy where
  enabled : Bool
  minAgeDays : Int
  mode : Mode
  deriving DecidableEq, Repr

/-- `AgeGatePolicy::is_relaxed_by`, as written. -/
def isRelaxedBy (self next : Policy) : Bool :=
  self.enabled &&
    (!next.enabled || decide (next.minAgeDays < self.minAgeDays) || decide (next.mode ≠ self.mode))

/-- `next` is at least as strict as `self`: still on, same clock, no younger. -/
def AtLeastAsStrict (self next : Policy) : Prop :=
  next.enabled = true ∧ next.mode = self.mode ∧ self.minAgeDays ≤ next.minAgeDays

/-- For an enabled gate, "not relaxed" is exactly "at least as strict". -/
theorem not_relaxed_iff (self next : Policy) (hon : self.enabled = true) :
    isRelaxedBy self next = false ↔ AtLeastAsStrict self next := by
  unfold isRelaxedBy AtLeastAsStrict
  simp [hon]
  constructor
  · rintro ⟨⟨h1, h2⟩, h3⟩
    exact ⟨h1, h3, h2⟩
  · rintro ⟨h1, h2, h3⟩
    exact ⟨⟨h1, h3⟩, h2⟩

/-- A run of changes, each checked against the policy it replaces. -/
def AllowedRun : Policy → List Policy → Prop
  | _, [] => True
  | p, q :: rest => isRelaxedBy p q = false ∧ AllowedRun q rest

/-- Where a run of changes ends. -/
def final : Policy → List Policy → Policy
  | p, [] => p
  | _, q :: rest => final q rest

/-- However many allowed changes are applied to an enabled gate, the result is
at least as strict as the policy we started from. -/
theorem allowed_run_never_relaxes (start : Policy) (changes : List Policy)
    (hon : start.enabled = true) (hrun : AllowedRun start changes) :
    changes = [] ∨ AtLeastAsStrict start (final start changes) := by
  induction changes generalizing start with
  | nil => exact Or.inl rfl
  | cons q rest ih =>
    right
    obtain ⟨hstep, hrest⟩ := hrun
    have hq := (not_relaxed_iff start q hon).mp hstep
    rcases ih q hq.1 hrest with hnil | hstrict
    · subst hnil
      exact hq
    · exact ⟨hstrict.1, hstrict.2.1.trans hq.2.1, Int.le_trans hq.2.2 hstrict.2.2⟩

/-- The documented exception: a disabled gate accepts any change, because it
cannot be weakened further. -/
theorem disabled_gate_accepts_anything (self next : Policy) (hoff : self.enabled = false) :
    isRelaxedBy self next = false := by
  simp [isRelaxedBy, hoff]

end ArtifactKeeper.AgeGate.PolicyRelaxation
