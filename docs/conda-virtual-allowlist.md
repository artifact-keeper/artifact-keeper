# Conda virtual channel allowlist

A virtual conda repository can restrict what it serves to an approved set of
packages (#4576). The list is the channel's boundary: when it is enabled, the
channel serves only the packages it admits, whichever member they come from
(#5055).

## What it filters

When the list is enabled, a package record it does not admit is left out of
every index the virtual serves:

- `repodata.json`, `repodata.json.zst` and `repodata.json.bz2`
- the CEP-16 shard index (`repodata_shards.msgpack.zst`) and its shards
- `current_repodata.json` and `run_exports.json`
- `channeldata.json`

and a download through the virtual of a package it does not admit (and of
its CEP-50 `.sigs` sidecar) answers 404, exactly like a package no member
has. A solver therefore reports the package as not found.

JLAP (`repodata.jlap`) is only served by hosted repositories, never by a
virtual, so it is not affected.

Reads of a member repository through its own URL are never filtered: the
list belongs to the virtual channel, not to its members. Restrict who can
read members directly with repository permissions.

## Scope

| `scope` | Filters | Notes |
|---|---|---|
| `all_members` (default) | hosted (local, staging) and remote members | The list is the channel's boundary. |
| `remote_only` | remote members only | Hosted members pass through unfiltered: the behaviour before #5055. |

A `PUT` that omits `scope` keeps the scope already stored (a new list gets
`all_members`), so a client that does not know the field cannot undo an
opt-out. `GET` always reports the scope in force.

### Upgrading

Before #5055 the list only filtered remote members. After upgrading to a release with #5055, on a
channel with an enabled list, hosted packages that are not on the list
disappear from the channel (its index and downloads through it) until they
are added to the list. To keep the old behaviour on a channel, set
`"scope": "remote_only"`. The hosted repositories keep serving the packages
directly.

## Entries and matching

```json
{
  "enabled": true,
  "scope": "all_members",
  "entries": [
    {"name": "numpy", "version": ">=2,<3", "subdirs": ["linux-64", "osx-arm64"]},
    {"name": "lib*"},
    {"name": "tzdata", "version": "2025b"}
  ]
}
```

- `name`: an exact conda package name or a glob (`*`, `?`), case-insensitive.
- `version` (optional): a conda version spec evaluated with conda ordering
  (`2.2.3`, `2.2.*`, `>=2,<3`, `1.0|1.1`, `!=1.5`, `~=1.2`). A record whose
  version does not parse is not admitted by a constrained entry.
- `subdirs` (optional): the platforms the entry applies to.

A record is admitted when any entry admits it, by the name and version its
filename carries and by the `name` and `version` the record itself claims.
An enabled empty list admits nothing from the members in scope;
`enabled: false` keeps the entries and turns filtering off.

Limits: 10,000 entries, names up to 128 bytes, version specs up to 256 bytes,
32 subdirs per entry.

## Hosted packages and name ownership

A hosted member owns the package names it publishes: the virtual never takes
a record of an owned name from a remote member, so a public upstream cannot
outbid an internal package (dependency confusion). Ownership comes from what
the hosted members hold, not from what the list admits. When the list does
not admit a hosted package, that package is dropped and its name stays
owned: the upstream's packages of that name stay out too. Add the name to the
list to serve the hosted package.

## Shards

A remote shard carries every version of its package and is addressed by the
hash of its bytes, so a remote name is listed in the virtual's shard index
only when an entry admits all of its versions (an entry without a version
constraint). A hosted name admitted under a version constraint is listed with
a shard rebuilt from its admitted records only.

## API

- `GET /api/v1/repositories/{key}/allowlist`
- `PUT /api/v1/repositories/{key}/allowlist`
- `DELETE /api/v1/repositories/{key}/allowlist`

Reading and changing the list requires the repository `admin` action. Changes
apply to the next request: every merged document of the channel is keyed by
the stored list, scope included, so a change is a new merge on every replica.
Changes are audited (`REPOSITORY_ALLOWLIST_CHANGED`, with the scope before and after).

## Observability

Responses that a list filtered carry `x-ak-allowlist-dropped` with the number
of records (names, for `channeldata.json` and the shard index) left out.
`ak_conda_allowlist_dropped_total{repository, member}` counts them per member,
hosted and remote (see `docs/operations/conda-security-metrics.md`).
