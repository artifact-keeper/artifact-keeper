---
section: Fixed
issues: [#4557]
---
- **Bulk promotion reports the same per-rule `gate_results` as single-artifact promotion, passed rules included** (#4557). An item that a scan-policy predicate refused came back from `POST .../promote` (bulk) with `"gate_results": []`, while promoting the same artifact on its own listed the failing `policy-predicate` rule, so a UI showing the gate decision had nothing to show for bulk promotions. Every bulk item now carries every evaluated rule with `passed` and `reason`: items refused by the scan policy, items refused by a per-pair promotion rule (policy results followed by the failing rules), items refused by the quality gate (as `quality-gate`), and items that were promoted.
