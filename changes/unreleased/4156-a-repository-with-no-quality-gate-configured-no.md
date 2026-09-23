---
section: Fixed
issues: [#4156]
---
- **A repository with no quality gate configured no longer logs a WARN on every successful promotion** (#4156). `evaluate_gate_once` logged "Quality gate evaluation failed for artifact …" at WARN for every `Err` out of `evaluate_quality_gate`, including the two states that are simply the default: the repository has no enabled quality gate, and the artifact has no health score yet. Both come back as `AppError::NotFound`, so every promotion on an ungated repository — the out-of-the-box configuration — read as an error to log-based alerting while the promotion itself succeeded. Those two outcomes are now classified as a no-op and logged at DEBUG, matched on the error variant rather than on the message text; a genuine evaluation failure (a database error, say) keeps the WARN it had.
