---
section: Fixed
issues: [#4204]
---
- **A quality-gate evaluation error now fails the promotion closed instead of letting it through** (#4204). On both promote routes, a genuine gate-evaluation failure (a database error, for example) was logged and treated as "not evaluated", so the artifact was promoted without the gate having run. The single route now answers a retryable 503 and the bulk route fails just that item; the unchanged "no enabled gate / no health score yet" defaults still proceed as before.
