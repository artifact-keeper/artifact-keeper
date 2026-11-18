/-!
# A scoped memo of the Remote origin gate

A model of `gate_through_memo` (`backend/src/services/proxy_service.rs`) and
its two kinds of caller, added in #6069:

* `ensure_origin_policy_allows(repo)` gates one Remote as the caller holds it,
  `(id, upstream_url)`, and reuses only a pass recorded for that same Remote.
* the key-addressed `ensure_origin_policy_allows_for(Key(k))` looks the row
  for `k` up and gates it, and accepts any pass recorded for `k`, including
  "`k` names no Remote".

The memo lives for one scope (`ProxyService::with_origin_gate_memo`). The
first caller to reach the gate evaluates; a pass, and a key that names no
Remote, are recorded; a refusal or a lookup error is not, so the next caller
evaluates for itself.

The only production scope is a Maven jar GET's content fetch (by id) joined
with its cached `.sha1` read (by key) in `maven_remote_stream`, where the
sidecar decides only the `X-Checksum-SHA1` header. A HEAD is not in a scope:
its fall-back GET and cold `.sha1` fetch contact the upstream. `maven_pair_*`
below is that scope.

Paired Rust test: `origin_gate_memo_laws` in
`backend/src/services/proxy_service.rs` (sequential runs against `run`
exactly, concurrent runs against `run` for some turn order, cancellation);
`maven_jar_get_evaluates_the_origin_gate_once_6069` in
`backend/src/api/handlers/proxy_origin_policy_tests.rs` (one evaluation and
no key lookup per warm jar GET).

`ev k r` is what the `k`-th fresh evaluation in the scope answers for Remote
`r`. Indexing by both lets a policy change part-way through the scope; a
steady policy is `ev k r = pol r`.

Not modelled: liveness. Concurrent callers wait on the `OnceCell` while the
first one evaluates, so for safety they behave like callers taking turns (the
paired Rust property test checks concurrent runs against this model), but a
gate future held unpolled inside the scope would block the waiters forever.
-/

namespace ArtifactKeeper.Proxy.OriginGateMemo

/-- One evaluation of the gate. `unavailable` is a lookup error; callers fail
closed on it. -/
inductive Gate where
  | allow | deny | unavailable
  deriving DecidableEq, Repr

/-- A Remote, as `(id, upstream_url)`. -/
abbrev Remote := Nat

/-- A gate call: by the Remote the caller holds, or by key, where `row` is the
Remote the key names right now (`none`: no Remote). -/
inductive Caller where
  | byId (r : Remote)
  | byKey (row : Option Remote)
  deriving DecidableEq, Repr

/-- What the memo records. -/
inductive Pass where
  | remote (r : Remote)
  | noRemote
  deriving DecidableEq, Repr

/-- One caller's outcome. -/
structure Step where
  caller : Caller
  answer : Gate
  evaluated : Bool
  deriving DecidableEq, Repr

/-- The `k`-th fresh evaluation's answer for Remote `r`. -/
abbrev Evals := Nat → Remote → Gate

/-- What a fresh evaluation that allowed records. -/
def record (r : Remote) (g : Gate) : Option Pass :=
  if g = .allow then some (.remote r) else none

/-- `gate_through_memo` over one scope. -/
def run : List Caller → Evals → Nat → Option Pass → List Step
  | [], _, _, _ => []
  | .byId r :: cs, ev, k, some (.remote m) =>
    if m = r then ⟨.byId r, .allow, false⟩ :: run cs ev k (some (.remote m))
    else ⟨.byId r, ev k r, true⟩ :: run cs ev (k + 1) (some (.remote m))
  | .byId r :: cs, ev, k, some .noRemote =>
    ⟨.byId r, ev k r, true⟩ :: run cs ev (k + 1) (some .noRemote)
  | .byId r :: cs, ev, k, none =>
    ⟨.byId r, ev k r, true⟩ :: run cs ev (k + 1) (record r (ev k r))
  | .byKey row :: cs, ev, k, some p =>
    ⟨.byKey row, .allow, false⟩ :: run cs ev k (some p)
  | .byKey none :: cs, ev, k, none =>
    ⟨.byKey none, .allow, false⟩ :: run cs ev k (some .noRemote)
  | .byKey (some r) :: cs, ev, k, none =>
    ⟨.byKey (some r), ev k r, true⟩ :: run cs ev (k + 1) (record r (ev k r))

/-- Without the memo every caller that has a Remote to gate evaluates. -/
def runWithoutMemo : List Caller → Evals → Nat → List Step
  | [], _, _ => []
  | .byId r :: cs, ev, k => ⟨.byId r, ev k r, true⟩ :: runWithoutMemo cs ev (k + 1)
  | .byKey none :: cs, ev, k => ⟨.byKey none, .allow, false⟩ :: runWithoutMemo cs ev k
  | .byKey (some r) :: cs, ev, k =>
    ⟨.byKey (some r), ev k r, true⟩ :: runWithoutMemo cs ev (k + 1)

/-! ## No invented passes -/

/-- The Remote a caller would evaluate, if it has one. -/
def evaluatedRemote : Caller → Option Remote
  | .byId r => some r
  | .byKey row => row

/-- Every allowed step is justified. `ok`: Remotes that already had an
evaluated allow in the scope; `seen`: whether anything was recorded yet.

* A caller by id is allowed only by its own evaluation or an earlier
  evaluated allow for the same Remote.
* A caller by key with a Remote is allowed only by its own evaluation or by
  something recorded earlier in the scope (any Remote: it accepts any pass
  for its key).
* A key that names no Remote has nothing to gate. -/
def justified : List Step → List Remote → Bool → Bool
  | [], _, _ => true
  | s :: ss, ok, seen =>
    (match s.caller with
      | .byId r => s.answer != .allow || s.evaluated || ok.contains r
      | .byKey (some _) => s.answer != .allow || s.evaluated || seen
      | .byKey none => true) &&
    justified ss
      (match evaluatedRemote s.caller with
        | some r => if s.evaluated && s.answer == .allow then r :: ok else ok
        | none => ok)
      (seen || (s.evaluated && s.answer == .allow) || s.caller == .byKey none)

/-- The memo never invents a pass. -/
theorem memo_never_invents_a_pass :
    ∀ (cs : List Caller) (ev : Evals) (k : Nat) (memo : Option Pass) (ok : List Remote)
      (seen : Bool),
      (∀ m, memo = some (.remote m) → m ∈ ok) → (memo.isSome → seen = true) →
      justified (run cs ev k memo) ok seen = true := by
  intro cs
  induction cs with
  | nil => intro _ _ _ _ _ _ _; rfl
  | cons c cs ih =>
    intro ev k memo ok seen hok hseen
    cases c with
    | byId r =>
      cases memo with
      | none =>
        by_cases ha : ev k r = .allow
        · have := ih ev (k + 1) (some (.remote r)) (r :: ok) true
            (fun m h => by cases h; exact List.mem_cons_self) (fun _ => rfl)
          simp [run, record, justified, evaluatedRemote, ha, this]
        · have := ih ev (k + 1) none ok seen (fun _ h => by cases h) (fun h => by cases h)
          have hb : (ev k r == Gate.allow) = false := beq_eq_false_iff_ne.mpr ha
          have hc : (Caller.byId r == Caller.byKey none) = false := rfl
          simp only [run, record, ha, ite_false, justified, evaluatedRemote, hb, hc,
            Bool.or_false, Bool.and_false, Bool.or_true]
          simpa [hb] using this
      | some p =>
        have hs : seen = true := hseen rfl
        cases p with
        | noRemote =>
          by_cases ha : ev k r = .allow
          · have := ih ev (k + 1) (some .noRemote) (r :: ok) true
              (fun _ h => by cases h) (fun _ => rfl)
            simp [run, justified, evaluatedRemote, ha, hs, this]
          · have := ih ev (k + 1) (some .noRemote) ok true
              (fun _ h => by cases h) (fun _ => rfl)
            simp [run, justified, evaluatedRemote, ha, hs, this]
        | remote m =>
          have hm : m ∈ ok := hok m rfl
          by_cases hmr : m = r
          · subst hmr
            have := ih ev k (some (.remote m)) ok true hok (fun _ => rfl)
            simp [run, justified, evaluatedRemote, hm, hs, this]
          · by_cases ha : ev k r = .allow
            · have := ih ev (k + 1) (some (.remote m)) (r :: ok) true
                (fun m' h => by cases h; exact List.mem_cons_of_mem _ hm) (fun _ => rfl)
              simp [run, justified, evaluatedRemote, hmr, ha, hs, this]
            · have := ih ev (k + 1) (some (.remote m)) ok true hok (fun _ => rfl)
              simp [run, justified, evaluatedRemote, hmr, ha, hs, this]
    | byKey row =>
      cases memo with
      | some p =>
        have hs : seen = true := hseen rfl
        have := ih ev k (some p) ok true hok (fun _ => rfl)
        cases row <;> simp [run, justified, evaluatedRemote, hs, this]
      | none =>
        cases row with
        | none =>
          have := ih ev k (some .noRemote) ok true (fun _ h => by cases h) (fun _ => rfl)
          simp [run, justified, evaluatedRemote, this]
        | some r =>
          by_cases ha : ev k r = .allow
          · have := ih ev (k + 1) (some (.remote r)) (r :: ok) true
              (fun m h => by cases h; exact List.mem_cons_self) (fun _ => rfl)
            simp [run, record, justified, evaluatedRemote, ha, this]
          · have := ih ev (k + 1) none ok seen (fun _ h => by cases h) (fun h => by cases h)
            have hb : (ev k r == Gate.allow) = false := beq_eq_false_iff_ne.mpr ha
            have hc : (Caller.byKey (some r) == Caller.byKey none) = false := rfl
            simp only [run, record, ha, ite_false, justified, evaluatedRemote, hb, hc,
              Bool.or_false, Bool.and_false, Bool.or_true]
            simpa [hb] using this

/-- Fail closed: when no evaluation in the scope allows and no key names "no
Remote", no caller is allowed. -/
theorem every_refusal_refuses :
    ∀ (cs : List Caller) (ev : Evals) (k : Nat),
      (∀ i r, ev i r ≠ .allow) → .byKey none ∉ cs →
      ∀ s ∈ run cs ev k none, s.answer ≠ .allow := by
  intro cs
  induction cs with
  | nil => intro _ _ _ _ s hs; cases hs
  | cons c cs ih =>
    intro ev k hev hnone s hs
    have hrest : Caller.byKey none ∉ cs := fun h => hnone (List.mem_cons_of_mem _ h)
    cases c with
    | byId r =>
      simp only [run, record, hev k r, ite_false] at hs
      rcases List.mem_cons.mp hs with h | h
      · subst h; exact hev k r
      · exact ih ev (k + 1) hev hrest s h
    | byKey row =>
      cases row with
      | none => exact absurd List.mem_cons_self hnone
      | some r =>
        simp only [run, record, hev k r, ite_false] at hs
        rcases List.mem_cons.mp hs with h | h
        · subst h; exact hev k r
        · exact ih ev (k + 1) hev hrest s h

/-! ## Cost -/

/-- How many fresh evaluations a list of steps ran. -/
def evaluations (steps : List Step) : Nat := (steps.filter (·.evaluated)).length

/-- Callers that have a Remote to gate. -/
def gated : List Caller → Nat
  | [] => 0
  | .byKey none :: cs => gated cs
  | _ :: cs => gated cs + 1

theorem without_memo_evaluations :
    ∀ (cs : List Caller) (ev : Evals) (k : Nat),
      evaluations (runWithoutMemo cs ev k) = gated cs := by
  intro cs
  induction cs with
  | nil => intro _ _; rfl
  | cons c cs ih =>
    intro ev k
    cases c with
    | byId r => simp [runWithoutMemo, evaluations, gated] at *; exact ih ev (k + 1)
    | byKey row =>
      cases row with
      | none => simp [runWithoutMemo, evaluations, gated] at *; exact ih ev k
      | some r => simp [runWithoutMemo, evaluations, gated] at *; exact ih ev (k + 1)

/-- The memo never evaluates more often than the callers would on their own. -/
theorem never_more_evaluations (cs : List Caller) (ev : Evals) (k : Nat)
    (memo : Option Pass) :
    evaluations (run cs ev k memo) ≤ evaluations (runWithoutMemo cs ev k) := by
  rw [without_memo_evaluations]
  induction cs generalizing k memo with
  | nil => exact Nat.le_refl 0
  | cons c cs ih =>
    cases c with
    | byId r =>
      cases memo with
      | none =>
        have := ih (k + 1) (record r (ev k r))
        simp [run, evaluations, gated] at *; omega
      | some p =>
        cases p with
        | noRemote =>
          have := ih (k + 1) (some .noRemote)
          simp [run, evaluations, gated] at *; omega
        | remote m =>
          by_cases hmr : m = r
          · subst hmr
            have := ih k (some (.remote m))
            simp [run, evaluations, gated] at *; omega
          · have := ih (k + 1) (some (.remote m))
            simp [run, evaluations, gated, hmr] at *; omega
    | byKey row =>
      cases memo with
      | some p =>
        have := ih k (some p)
        cases row <;> simp [run, evaluations, gated] at * <;> omega
      | none =>
        cases row with
        | none =>
          have := ih k (some .noRemote)
          simp [run, evaluations, gated] at *; omega
        | some r =>
          have := ih (k + 1) (record r (ev k r))
          simp [run, evaluations, gated] at *; omega

/-! ## Steady policies -/

/-- With a steady policy and callers by id only, every caller gets exactly
its own Remote's answer, whatever the Remotes. -/
theorem steady_by_id_same_answers (pol : Remote → Gate) :
    ∀ (rs : List Remote) (k : Nat) (memo : Option Pass),
      (∀ m, memo = some (.remote m) → pol m = .allow) →
      (run (rs.map .byId) (fun _ r => pol r) k memo).map (·.answer) = rs.map pol := by
  intro rs
  induction rs with
  | nil => intro _ _ _; rfl
  | cons r rs ih =>
    intro k memo h
    cases memo with
    | none =>
      by_cases ha : pol r = .allow
      · have := ih (k + 1) (some (.remote r)) (fun m hm => by cases hm; exact ha)
        simp [run, record, ha] at *; exact this
      · have := ih (k + 1) none (fun _ hm => by cases hm)
        simp [run, record, ha] at *; exact this
    | some p =>
      cases p with
      | noRemote =>
        have := ih (k + 1) (some .noRemote) (fun _ hm => by cases hm)
        simp [run] at *; exact this
      | remote m =>
        by_cases hmr : m = r
        · subst hmr
          have := ih k (some (.remote m)) h
          simp [run, h m rfl] at *; exact this
        · have := ih (k + 1) (some (.remote m)) h
          simp [run, hmr] at *; exact this

/-! ## The production scope: a Maven jar GET -/

/-- The content fetch gates by id first, then the sidecar read by key. -/
def mavenPair (r : Remote) (row : Option Remote) : List Caller := [.byId r, .byKey row]

/-- What is served is decided by the content fetch's own fresh evaluation,
with or without the memo: the memo cannot change whether the jar is served. -/
theorem maven_pair_serves_the_same (r : Remote) (row : Option Remote) (ev : Evals) :
    ((run (mavenPair r row) ev 0 none).head?.map (·.answer)) = some (ev 0 r) ∧
    ((runWithoutMemo (mavenPair r row) ev 0).head?.map (·.answer)) = some (ev 0 r) := by
  constructor <;> rfl

/-- One evaluation serves both when the jar is allowed. -/
theorem maven_pair_evaluates_once (r : Remote) (row : Option Remote) (ev : Evals)
    (h : ev 0 r = .allow) :
    evaluations (run (mavenPair r row) ev 0 none) = 1 := by
  simp [mavenPair, run, record, h, evaluations]

/-- The sidecar read's answer can differ from evaluating it fresh only when
the jar was allowed, and then only if the key now names another Remote or a
second evaluation would refuse. That answer decides the checksum header,
never the body. -/
theorem maven_pair_differs_only_on_an_allowed_jar (r : Remote) (row : Option Remote)
    (ev : Evals)
    (h : (run (mavenPair r row) ev 0 none).map (·.answer) ≠
      (runWithoutMemo (mavenPair r row) ev 0).map (·.answer)) :
    ev 0 r = .allow ∧ (row ≠ some r ∨ ev 1 r ≠ .allow) := by
  by_cases ha : ev 0 r = .allow
  · refine ⟨ha, ?_⟩
    cases row with
    | none =>
      exfalso; apply h; simp [mavenPair, run, runWithoutMemo, record, ha]
    | some r' =>
      by_cases hr : r' = r
      · subst hr
        by_cases h1 : ev 1 r' = .allow
        · exfalso; apply h; simp [mavenPair, run, runWithoutMemo, record, ha, h1]
        · exact Or.inr h1
      · exact Or.inl (fun e => hr (Option.some.inj e))
  · exfalso; apply h
    cases row with
    | none => simp [mavenPair, run, runWithoutMemo, record, ha]
    | some r' => simp [mavenPair, run, runWithoutMemo, record, ha]

/-- With a steady policy and a key that still names the jar's Remote, the
memo changes nothing. -/
theorem maven_pair_steady_same (r : Remote) (pol : Remote → Gate) :
    (run (mavenPair r (some r)) (fun _ x => pol x) 0 none).map (·.answer) =
      (runWithoutMemo (mavenPair r (some r)) (fun _ x => pol x) 0).map (·.answer) := by
  by_cases ha : pol r = .allow <;> simp [mavenPair, run, runWithoutMemo, record, ha]

/-- Recorded, not assumed away: a deny written between the two evaluations.
The jar is served either way; with the memo it keeps its checksum header. -/
theorem maven_pair_policy_flip_differs :
    (run (mavenPair 0 (some 0)) (fun k _ => if k = 0 then .allow else .deny) 0 none).map
        (·.answer) ≠
      (runWithoutMemo (mavenPair 0 (some 0)) (fun k _ => if k = 0 then .allow else .deny)
        0).map (·.answer) := by
  decide

/-- Recorded, not assumed away: the key re-pointed to a Remote the policy
refuses (the content fetch gated the handler's cached row). The jar is served
either way, from the Remote the request resolved; with the memo it keeps its
checksum header. -/
theorem maven_pair_repointed_key_differs :
    (run (mavenPair 0 (some 1)) (fun _ x => if x = 0 then .allow else .deny) 0 none).map
        (·.answer) ≠
      (runWithoutMemo (mavenPair 0 (some 1)) (fun _ x => if x = 0 then .allow else .deny)
        0).map (·.answer) := by
  decide

end ArtifactKeeper.Proxy.OriginGateMemo
