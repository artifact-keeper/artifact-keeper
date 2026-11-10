/-!
# Curation rule evaluation

A model of `CurationService::evaluate_rules`
(`backend/src/services/curation_service.rs`): the first-match evaluation of
pattern rules that gates PyPI, npm, conda and every other curated format.

Rules arrive ordered by priority. The first rule that applies to the request
decides; if none applies, the repository's default action does. A rule that
cannot be decided for a request (a version constraint with no version in the
request, an architecture scope with no architecture) is skipped, not guessed.

Name globbing and version comparison are abstracted: a rule carries whether
its pattern matches the requested package, and its constraint is any predicate
on versions. What is proved here is the shape of the evaluation, which holds
whatever those two are.
-/

namespace ArtifactKeeper.Curation.RuleEvaluation

inductive Action where
  | allow | block | flag
  deriving DecidableEq, Repr

abbrev Version := Nat
abbrev Arch := Nat

/-- One `rule_type = "pattern"` rule, as it bears on one requested package. -/
structure Rule where
  /-- `pattern_matches(rule.package_pattern, package_name)`. -/
  nameMatches : Bool
  /-- `rule.version_constraint`; `none` is `*`. -/
  constraint : Option (Version → Bool)
  /-- `rule.architecture`; `none` is `*`. -/
  arch : Option Arch
  action : Action

structure Request where
  version : Option Version
  arch : Option Arch

/-- Whether the loop body reaches its `return` for this rule. -/
def Rule.applies (rule : Rule) (req : Request) : Bool :=
  rule.nameMatches &&
    (match req.version, rule.constraint with
      | some v, some c => c v
      | some _, none => true
      | none, some _ => false -- cannot be decided: skip
      | none, none => true) &&
    (match rule.arch, req.arch with
      | none, _ => true
      | some a, some b => a == b
      | some _, none => false) -- cannot be decided: skip

/-- `evaluate_rules`: the first applicable rule's action, else the default. -/
def evaluate (rules : List Rule) (default : Action) (req : Request) : Action :=
  match rules.find? (·.applies req) with
  | some rule => rule.action
  | none => default

/-- The first rule that applies decides, whatever comes after it. -/
theorem first_applicable_rule_decides (before after : List Rule) (rule : Rule)
    (default : Action) (req : Request)
    (hbefore : ∀ r ∈ before, r.applies req = false) (happlies : rule.applies req = true) :
    evaluate (before ++ rule :: after) default req = rule.action := by
  unfold evaluate
  induction before with
  | nil => simp [happlies]
  | cons b rest ih =>
    have hb : b.applies req = false := hbefore b (by simp)
    simp only [List.cons_append, List.find?, hb]
    exact ih (fun r hr => hbefore r (by simp [hr]))

/-- So a block rule ahead of every other applicable rule cannot be overridden
by adding rules below it. -/
theorem rules_below_a_matching_block_cannot_unblock (before after extra : List Rule)
    (rule : Rule) (default : Action) (req : Request)
    (hbefore : ∀ r ∈ before, r.applies req = false) (happlies : rule.applies req = true)
    (hblock : rule.action = .block) :
    evaluate (before ++ rule :: (after ++ extra)) default req = .block := by
  rw [first_applicable_rule_decides before (after ++ extra) rule default req hbefore happlies]
  exact hblock

/-- With no applicable rule the default action decides. -/
theorem no_applicable_rule_gives_default (rules : List Rule) (default : Action) (req : Request)
    (hnone : ∀ r ∈ rules, r.applies req = false) : evaluate rules default req = default := by
  unfold evaluate
  induction rules with
  | nil => rfl
  | cons r rest ih =>
    have hr : r.applies req = false := hnone r (by simp)
    simp only [List.find?, hr]
    exact ih (fun x hx => hnone x (by simp [hx]))

/-! ## Undecidable rules are skipped

Both skips are deliberate (#2912): comparing a constraint against a missing
version, or treating a missing architecture as a match, each made rules fire
on requests they were never written for. The cost is stated below so it is
not rediscovered as a surprise. -/

/-- A version-constrained rule never applies to a request without a version. -/
theorem constrained_rule_skips_versionless_request (rule : Rule) (req : Request)
    (c : Version → Bool) (hc : rule.constraint = some c) (hv : req.version = none) :
    rule.applies req = false := by
  simp [Rule.applies, hc, hv]

/-- An architecture-scoped rule never applies to a request without one. -/
theorem scoped_rule_skips_archless_request (rule : Rule) (req : Request)
    (a : Arch) (ha : rule.arch = some a) (hr : req.arch = none) :
    rule.applies req = false := by
  cases hn : rule.nameMatches <;> cases hv : req.version <;> cases hcst : rule.constraint <;>
    simp [Rule.applies, ha, hr, hn, hv, hcst]

/-- The cost: under a default of `allow`, a rule that blocks EVERY version of a
package through a constraint does not block a request that names no version
(an index or metadata page). Blocking a whole package needs the `*`
constraint. -/
theorem a_constraint_that_blocks_every_version_still_admits_a_versionless_request :
    let blockAll : Rule := ⟨true, some (fun _ => true), none, .block⟩
    (∀ v, evaluate [blockAll] .allow ⟨some v, none⟩ = .block) ∧
      evaluate [blockAll] .allow ⟨none, none⟩ = .allow := by
  constructor
  · intro v
    simp [evaluate, List.find?, Rule.applies]
  · simp [evaluate, List.find?, Rule.applies]

end ArtifactKeeper.Curation.RuleEvaluation
