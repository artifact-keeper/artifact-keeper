# Curation name checks on Remote and Virtual downloads

A `popularity` curation rule compares package names against a list of popular
names: edit distance, confusable skeletons (homoglyphs), mixed script, and
affixes. The staging sync always runs these checks. With
`"download_name_checks": true`, the rule also runs them on npm and PyPI Remote
and Virtual downloads (#5274). The download path makes no network call and has
no review queue, so every match is either a refusal (`403 curation_blocked`)
or a flag (the download is served and logged).

## What blocks and what flags on a download

| Match | `block_typosquat: false` | `block_typosquat: true` |
|---|---|---|
| Edit distance (`reqeusts` for `requests`) | flag | flag |
| Affix (`python-numpy`) | flag | flag |
| Lookalike with a non-ASCII character (`lodash` with a Cyrillic `о`, fullwidth or Greek letters, mixed script) | flag | **block** |
| All-ASCII lookalike (`c1ick` for `click`, `paypa1`, `rnicrosoft`) | flag | `ascii_lookalikes`: `"flag"` (the default) or `"block"` |

**Why ASCII lookalikes flag by default (1.13.0, #5840).** The confusable
skeletons of UTS #39 also fold ASCII into ASCII: `1` and `I` become `l`, `0`
becomes `o`, and `rn` becomes `m`. An all-ASCII name whose skeleton matches a
popular one is therefore one or two characters away from it. That is the same
kind of match as edit distance, which only flags on downloads because real
packages have such names and a download has no review step. A lookalike with a
non-ASCII character has no such legitimate cause, so it is still refused.
Mixed script always involves a non-ASCII letter. The check runs on the decoded
name that is fetched, so a percent-encoded lookalike is not taken for ASCII.

PyPI only accepts ASCII names (PEP 508). So on PyPI the `ascii_lookalikes`
setting decides whether the download path refuses lookalikes at all.

```json
{
  "download_name_checks": true,
  "block_typosquat": true,
  "ascii_lookalikes": "block",
  "popular_packages": ["paypal", "click"]
}
```

`ascii_lookalikes` takes `"block"` or `"flag"`. Any other value is refused
with `400` when the rule is created or updated. It has no effect without
`block_typosquat: true`, and none on the staging sync.

## Upgrading to 1.13.0

Migration 421 sets `"ascii_lookalikes": "block"` on every `popularity` rule
that has `block_typosquat: true` and no `ascii_lookalikes` yet. **An existing
rule therefore refuses exactly what it refused in 1.12.** Only rules written
after the upgrade without the key get the new `"flag"` default. To move an
existing rule to the new behaviour, set `"ascii_lookalikes": "flag"` on it.

During a rolling upgrade, a rule created by a replica still on 1.12 after the
migration has run gets no stamp, and so it flags. Set the key on such a rule if
it should block.

## Flag logs and the flag metric

A flagged download is logged at `warn`:

```
curation flagged a proxy download; serving it (no review queue on the proxy path)
  repo_key=… package=… rule_id=… reason=… repeat_log_window_secs=3600
```

The line is written **once per (repository, package, rule) per hour**, per
process. Repeats within the hour are logged at `debug`. A flagged package is
pulled again and again: on PyPI the index and then the file, and through a
Virtual once per member checked. Logging every pull buried the first sighting
of a new name.

Every flag, logged or not, is counted:

| Metric | Type | Labels |
|---|---|---|
| `ak_curation_proxy_flags_total` | counter | `repository`, `rule_id` |

```promql
# Flags per rule over the last hour.
sum by (rule_id) (increase(ak_curation_proxy_flags_total[1h]))
```
