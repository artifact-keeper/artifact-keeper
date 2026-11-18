import ArtifactKeeper.Quarantine.DownloadGate

/-!
Wire codec and case enumeration for the `Quarantine.DownloadGate` oracle. No
model logic lives here: `answer` parses a line, calls the model, prints the
result. Every committed vector is the model's own answer.

  download <status> <expiry> <now>   =>  allow | block     (`downloadAllowed`)
  admin <status>                     =>  allow | refuse    (`adminQuarantineAllowed`)

  status   q (quarantined) | r (rejected) | o (any other value, NULL included)
  expiry   an integer, or `-` for none
  now      an integer

The Rust test maps each abstract status to the concrete column values it
stands for (`o` covers `released`, `clean`, `unscanned`, `flagged`, NULL and
values this build does not know) and each integer to a timestamp.
-/
namespace ArtifactKeeper.Oracle.QuarantineDownloadGate
open ArtifactKeeper.Quarantine.DownloadGate

def parseStatus : String → Option Status
  | "q" => some .quarantined | "r" => some .rejected | "o" => some .other | _ => none
def fmtStatus : Status → String
  | .quarantined => "q" | .rejected => "r" | .other => "o"

def parseExpiry (s : String) : Option (Option Time) :=
  if s == "-" then some none else s.toInt?.map some
def fmtExpiry : Option Time → String
  | none => "-" | some t => toString t

/-- One input line ↦ the model's answer. -/
def answer : List String → String
  | ["download", s, e, n] =>
    match parseStatus s, parseExpiry e, n.toInt? with
    | some st, some ex, some now => if downloadAllowed st ex now then "allow" else "block"
    | _, _, _ => "BADARGS"
  | ["admin", s] =>
    match parseStatus s with
    | some st => if adminQuarantineAllowed st then "allow" else "refuse"
    | none => "BADARGS"
  | _ => "BADARGS"

def statuses : List Status := [.quarantined, .rejected, .other]

/-- Exhaustive over every status, an absent expiry or one in [-3, 3], and
`now` in [-3, 3]: every ordering of expiry and now, equality included. Then a
few far-apart times, so a bound that only works near zero is caught too. -/
def cases : List String :=
  let small : List Int := [-3, -2, -1, 0, 1, 2, 3]
  let expiries : List (Option Time) := none :: small.map some
  let far : List Int := [-1000000000, -1, 0, 1, 1000000000]
  let near :=
    statuses.flatMap fun st => expiries.flatMap fun ex => small.map fun now =>
      s!"download {fmtStatus st} {fmtExpiry ex} {now}"
  let distant :=
    statuses.flatMap fun st => far.flatMap fun ex => far.map fun now =>
      s!"download {fmtStatus st} {ex} {now}"
  let admin := statuses.map fun st => s!"admin {fmtStatus st}"
  near ++ distant ++ admin

end ArtifactKeeper.Oracle.QuarantineDownloadGate
