/-!
# Scan-state classification

A model of `classify_scan_state` and `ScanState::is_unscanned`
(`backend/src/services/scan_state.rs`), the input to the `block_unscanned`
promotion gate.

The guarantee: an artifact passes the gate only when a scan completed, or when
every scanner said it does not apply. The rule as first written did not give
that for a status the build does not recognise; the counterexample is kept
below, next to the rule that fixes it.
-/

namespace ArtifactKeeper.Scan.ScanState

/-- `scan_results.status`. `other` stands for any value this build does not
know (a status added by a newer release). -/
inductive Status where
  | completed | pending | running | failed | notApplicable | other
  deriving DecidableEq, Repr

/-- `ScanStateRow`, reduced to what the classifier reads. `marker` is whether
`error_message` carries the legacy "does not apply" sentinel. -/
structure Row where
  status : Status
  marker : Bool
  deriving DecidableEq, Repr

/-- `ScanStateRow::is_not_applicable`. -/
def Row.isNotApplicable (r : Row) : Bool :=
  r.status == .notApplicable || (r.status == .failed && r.marker)

def Row.isCompleted (r : Row) : Bool := r.status == .completed
def Row.inProgress (r : Row) : Bool := r.status == .pending || r.status == .running
def Row.genuineFailure (r : Row) : Bool := r.status == .failed && !r.isNotApplicable

/-- `ScanState`. -/
inductive State where
  | completed | inProgress | failed | neverScanned | notApplicable
  deriving DecidableEq, Repr

/-- `ScanState::is_unscanned`. -/
def State.isUnscanned : State → Bool
  | .inProgress | .failed | .neverScanned => true
  | .completed | .notApplicable => false

/-- `classify_scan_state` as first written: whatever is left after the known
cases is "not applicable". -/
def classifyOriginal (rows : List Row) : State :=
  if rows.any Row.isCompleted then .completed
  else if rows.any Row.inProgress then .inProgress
  else if rows.any Row.genuineFailure then .failed
  else if rows.isEmpty then .neverScanned
  else .notApplicable

/-- `classify_scan_state` with the fall-through closed: "not applicable" only
when every row says so. -/
def classify (rows : List Row) : State :=
  if rows.any Row.isCompleted then .completed
  else if rows.any Row.inProgress then .inProgress
  else if rows.any Row.genuineFailure then .failed
  else if rows.isEmpty then .neverScanned
  else if rows.all Row.isNotApplicable then .notApplicable
  else .failed

/-! ## What does not hold for the original rule -/

/-- One row with an unrecognised status passes the gate. Unreachable while the
`scan_results_status_check` constraint lists exactly the five known statuses;
reachable the day a sixth is added. -/
theorem original_passes_an_unrecognised_status :
    (classifyOriginal [⟨.other, false⟩]).isUnscanned = false := by
  decide

/-! ## What holds for the fixed rule -/

/-- A "not applicable" row is none of: completed, in progress, a genuine failure. -/
theorem notApplicable_row_is_nothing_else (r : Row) (h : r.isNotApplicable = true) :
    r.isCompleted = false ∧ r.inProgress = false ∧ r.genuineFailure = false := by
  cases r with
  | mk status marker =>
    cases status <;>
      simp_all [Row.isNotApplicable, Row.isCompleted, Row.inProgress, Row.genuineFailure]

/-- If every row is "not applicable", no row matches a predicate that "not
applicable" rows never satisfy. -/
theorem all_notApplicable_excludes (rows : List Row) (p : Row → Bool)
    (hp : ∀ r, r.isNotApplicable = true → p r = false)
    (hall : rows.all Row.isNotApplicable = true) : rows.any p = false := by
  cases hany : rows.any p with
  | false => rfl
  | true =>
    obtain ⟨r, hr, hpr⟩ := List.any_eq_true.mp hany
    have := hp r (List.all_eq_true.mp hall r hr)
    simp [this] at hpr

/-- The gate is passed exactly when a scan completed, or there is at least one
row and every row is "not applicable". -/
theorem passes_gate_iff (rows : List Row) :
    (classify rows).isUnscanned = false ↔
      rows.any Row.isCompleted = true ∨
        (rows ≠ [] ∧ rows.all Row.isNotApplicable = true) := by
  constructor
  · intro h
    unfold classify at h
    by_cases hc : rows.any Row.isCompleted = true
    · exact Or.inl hc
    · right
      by_cases hp : rows.any Row.inProgress = true
      · simp [hc, hp, State.isUnscanned] at h
      · by_cases hf : rows.any Row.genuineFailure = true
        · simp [hc, hp, hf, State.isUnscanned] at h
        · by_cases he : rows.isEmpty = true
          · simp [hc, hp, hf, he, State.isUnscanned] at h
          · by_cases ha : rows.all Row.isNotApplicable = true
            · exact ⟨fun hnil => he (by simp [hnil]), ha⟩
            · simp [hc, hp, hf, he, ha, State.isUnscanned] at h
  · intro h
    unfold classify
    rcases h with hc | ⟨hne, hall⟩
    · simp [hc, State.isUnscanned]
    · have hc := all_notApplicable_excludes rows Row.isCompleted
        (fun r hr => (notApplicable_row_is_nothing_else r hr).1) hall
      have hp := all_notApplicable_excludes rows Row.inProgress
        (fun r hr => (notApplicable_row_is_nothing_else r hr).2.1) hall
      have hf := all_notApplicable_excludes rows Row.genuineFailure
        (fun r hr => (notApplicable_row_is_nothing_else r hr).2.2) hall
      have he : rows.isEmpty = false := by
        cases rows with
        | nil => exact absurd rfl hne
        | cons _ _ => rfl
      simp [hc, hp, hf, he, hall, State.isUnscanned]

/-- Fail closed: no completed scan, and something still running or genuinely
crashed, is always unscanned. -/
theorem unfinished_work_is_unscanned (rows : List Row)
    (hc : rows.any Row.isCompleted = false)
    (hwork : rows.any Row.inProgress = true ∨ rows.any Row.genuineFailure = true) :
    (classify rows).isUnscanned = true := by
  unfold classify
  rcases hwork with hp | hf
  · simp [hc, hp, State.isUnscanned]
  · by_cases hp : rows.any Row.inProgress = true
    · simp [hc, hp, State.isUnscanned]
    · simp [hc, hp, hf, State.isUnscanned]

end ArtifactKeeper.Scan.ScanState
