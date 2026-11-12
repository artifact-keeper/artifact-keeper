/-!
# Quarantine download gate

A model of `check_download_allowed`, `admin_quarantine_allowed` and
`status_after_scan` (`backend/src/services/quarantine_service.rs`).

The gate reads `artifacts.quarantine_status` and `quarantine_until`. This file
proves what the gate guarantees about each kind of hold as time passes, and
records one thing it does not guarantee.
-/

namespace ArtifactKeeper.Quarantine.DownloadGate

/-- `artifacts.quarantine_status`. `other` stands for every value the gate has
no arm for: `released`, `clean`, `unscanned`, `flagged`, NULL, and any status
this build does not know. -/
inductive Status where
  | quarantined | rejected | other
  deriving DecidableEq, Repr

/-- Time as a number; only the order matters. -/
abbrev Time := Int

/-- `check_download_allowed`: `true` is `Ok(())`. -/
def downloadAllowed (status : Status) (expiry : Option Time) (now : Time) : Bool :=
  match status with
  | .quarantined =>
    match expiry with
    | some t => decide (t ≤ now)
    | none => false
  | .rejected => false
  | .other => true

/-- A rejected artifact is never downloadable, whatever the clock or the
expiry column says. -/
theorem rejected_never_downloads (expiry : Option Time) (now : Time) :
    downloadAllowed .rejected expiry now = false := rfl

/-- A hold with no expiry (an administrator's quarantine, a scan-policy hold)
never lapses on its own. -/
theorem permanent_hold_never_lapses (now : Time) :
    downloadAllowed .quarantined none now = false := rfl

/-- A timed hold blocks for exactly its window. -/
theorem timed_hold_blocks_until_expiry (t now : Time) :
    downloadAllowed .quarantined (some t) now = false ↔ now < t := by
  simp [downloadAllowed, Int.not_le]

/-- Time only moves a timed hold one way: once it has lapsed it stays lapsed. -/
theorem lapsed_hold_stays_lapsed (t now later : Time) (hlater : now ≤ later)
    (h : downloadAllowed .quarantined (some t) now = true) :
    downloadAllowed .quarantined (some t) later = true := by
  simp [downloadAllowed] at *
  exact Int.le_trans h hlater

/-- `admin_quarantine_allowed`: an administrator may quarantine anything that
is not already rejected. -/
def adminQuarantineAllowed (current : Status) : Bool :=
  match current with
  | .rejected => false
  | _ => true

/-- The admin quarantine-now write: status `quarantined`, no expiry. -/
def adminQuarantine (current : Status) : Option (Status × Option Time) :=
  if adminQuarantineAllowed current then some (.quarantined, none) else none

/-- Quarantine-now never makes a blocked artifact downloadable: it is refused
on a rejection, and otherwise produces a permanent hold. -/
theorem admin_quarantine_always_blocks (current : Status) (now : Time)
    (result : Status × Option Time) (h : adminQuarantine current = some result) :
    downloadAllowed result.1 result.2 now = false := by
  unfold adminQuarantine at h
  split at h
  · cases h; rfl
  · cases h

/-- Quarantine-now cannot be used to turn a rejection into a hold that might
later be released. -/
theorem admin_quarantine_refused_on_rejection : adminQuarantine .rejected = none := rfl

/-! ## What the gate does not guarantee

Every status without an arm is downloadable. That is intended for `released`,
`clean`, `unscanned` and `flagged`, but it also covers a status this build has
never heard of: the gate fails open on an unrecognised value. It is safe only
as long as a database constraint keeps the column to known values, the same
situation as `classify_scan_state` (#5715). -/

theorem unrecognised_status_downloads (expiry : Option Time) (now : Time) :
    downloadAllowed .other expiry now = true := rfl

end ArtifactKeeper.Quarantine.DownloadGate
