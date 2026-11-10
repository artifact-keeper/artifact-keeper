/-!
# Repository ceiling on token minting

A model of `AuthExtension::mint_repo_ceiling`
(`backend/src/api/middleware/auth.rs`, #4225) and `AccessScope::grants`
(`backend/src/models/access_scope.rs`).

The guarantee (GHSA-qh2h-m7hp-27pc): a token never reaches a repository the
credential that minted it could not reach, through any chain of mints.

The stored restriction is the legacy `Option<Vec<Uuid>>`, where an empty list
is stored as "no restriction". The model keeps that step, because it is what
makes the empty-allowlist refusal in `mint_repo_ceiling` load-bearing.
-/

namespace ArtifactKeeper.Auth.MintRepoCeiling

/-- A repository id. -/
abbrev Repo := Nat

/-- `AccessScope`. -/
inductive Scope where
  /-- `AccessScope::Admin`: no repository restriction. -/
  | unrestricted
  /-- `AccessScope::Restricted`: an allowlist; empty grants nothing. -/
  | restricted (ids : List Repo)
  deriving DecidableEq, Repr

/-- `AccessScope::grants`. -/
def Scope.grants : Scope → Repo → Prop
  | .unrestricted, _ => True
  | .restricted ids, r => r ∈ ids

/-- What a stored token restriction means when it is read back: an empty
restriction "would be stored as none". -/
def stored (restriction : Option (List Repo)) : Scope :=
  match restriction with
  | none => .unrestricted
  | some [] => .unrestricted
  | some ids => .restricted ids

/-- `mint_repo_ceiling`: `none` is the 403; `some c` is the ceiling, where
`c = none` means "the request's own restriction applies unchanged". -/
def mintRepoCeiling (cred : Scope) (requestsRestriction : Bool) : Option (Option (List Repo)) :=
  match cred with
  | .unrestricted => some none
  | .restricted ids =>
    if requestsRestriction then none
    else if ids.isEmpty then none
    else some (some ids)

/-- The scope of the token a mint produces, or `none` when it is refused.
`requested` is the restriction named in the request, if any. -/
def mint (cred : Scope) (requested : Option (List Repo)) : Option Scope :=
  match mintRepoCeiling cred requested.isSome with
  | none => none
  | some none => some (stored requested)
  | some (some ceiling) => some (stored (some ceiling))

/-- One mint never widens: whatever the new token reaches, the credential
reached. -/
theorem mint_never_widens (cred minted : Scope) (requested : Option (List Repo))
    (hmint : mint cred requested = some minted) (r : Repo)
    (hgrant : minted.grants r) : cred.grants r := by
  cases cred with
  | unrestricted => trivial
  | restricted ids =>
    unfold mint mintRepoCeiling at hmint
    cases hreq : requested.isSome
    · cases ids with
      | nil => simp [hreq] at hmint
      | cons x xs =>
        simp [hreq, stored] at hmint
        subst hmint
        exact hgrant
    · simp [hreq] at hmint

/-- A chain of mints, each token minting the next. -/
def MintChain : Scope → List (Option (List Repo) × Scope) → Prop
  | _, [] => True
  | cred, (requested, minted) :: rest =>
    mint cred requested = some minted ∧ MintChain minted rest

/-- The last token of a chain (the original credential when it is empty). -/
def lastToken : Scope → List (Option (List Repo) × Scope) → Scope
  | cred, [] => cred
  | _, (_, minted) :: rest => lastToken minted rest

/-- Through any chain of mints, the last token reaches only what the original
credential reached. -/
theorem mint_chain_never_widens (cred : Scope) (chain : List (Option (List Repo) × Scope))
    (hchain : MintChain cred chain) (r : Repo)
    (hgrant : (lastToken cred chain).grants r) : cred.grants r := by
  induction chain generalizing cred with
  | nil => exact hgrant
  | cons step rest ih =>
    obtain ⟨requested, minted⟩ := step
    obtain ⟨hmint, hrest⟩ := hchain
    exact mint_never_widens cred minted requested hmint r (ih minted hrest hgrant)

/-! ## Why the empty-allowlist refusal is load-bearing -/

/-- `mint_repo_ceiling` without the `ids.is_empty()` refusal. -/
def mintWithoutEmptyCheck (cred : Scope) (requested : Option (List Repo)) : Option Scope :=
  match cred with
  | .unrestricted => some (stored requested)
  | .restricted ids => if requested.isSome then none else some (stored (some ids))

/-- Without it, a credential restricted to nothing mints a token that reaches
everything. -/
theorem without_the_check_nothing_becomes_everything :
    mintWithoutEmptyCheck (.restricted []) none = some .unrestricted := by
  decide

/-- With it, that mint is refused. -/
theorem restricted_to_nothing_cannot_mint (requested : Option (List Repo)) :
    mint (.restricted []) requested = none := by
  cases requested <;> simp [mint, mintRepoCeiling]

end ArtifactKeeper.Auth.MintRepoCeiling
