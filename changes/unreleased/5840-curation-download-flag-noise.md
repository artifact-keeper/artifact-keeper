---
section: Changed
issues: [#5840]
---
- **Curation flags on Remote and Virtual downloads are quiet, and all-ASCII confusables no longer block them by default** (#5840). A served flag is now logged at `debug` with the repository, package, rule id and reason, and counted in `ak_curation_flagged_downloads_total{repository,rule_id}`, so repeat pulls show volume without burying new names. A homoglyph collision whose name is all ASCII, such as `c1ick` for `click`, is only a flag like an edit-distance match; Unicode and mixed-script lookalikes still get `403 curation_blocked`. This supersedes the `c1ick` example in the earlier `popularity` note. Operators who want the stricter download behaviour can set `"block_ascii_confusables": true` on the rule. The staging sync is unchanged.
