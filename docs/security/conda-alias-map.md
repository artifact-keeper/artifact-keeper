# Conda to PyPI alias map

Conda package names rarely match their PyPI distributions: `py-opencv` is
`opencv-python`, `pytorch` is `torch`, `pytables` is `tables`. OSV and the
GitHub Advisory Database have no conda ecosystem, so advisory coverage for
conda content comes from an explicit conda-to-PyPI alias map (#4042).

The map is an input, never a guess. Artifact Keeper does not invent an alias
from a name that merely looks alike: a wrong mapping produces confident
findings against the wrong package, which is worse than no mapping. Without a
loaded map a small vendored table still covers the well-known renames; every
other package is recorded as unmapped and its scan is graded `partial`, not
clean.

## Where the map comes from

`AK_CONDA_PYPI_ALIAS_MAP` names a JSON file on the backend container. Mount it
into the container and point the variable at the mounted path:

```yaml
environment:
  AK_CONDA_PYPI_ALIAS_MAP: /etc/artifact-keeper/conda-pypi-aliases.json
volumes:
  - ./conda-pypi-aliases.json:/etc/artifact-keeper/conda-pypi-aliases.json:ro
```

The file must use the schema-tagged canonical shape below. `provenance.source`
is free text identifying the upstream, `provenance.fetched_at` is when *you*
fetched or built the map, and `provenance.channel` is optional. An empty
`pypi_names` list is a positive statement that the conda package ships no PyPI
distribution, which lets a scan answer "nothing to look up" instead of
reporting a coverage gap.

```json
{
  "schema": "artifact-keeper/conda-pypi-alias/v1",
  "provenance": {
    "source": "conda-forge grayskull mapping, revision abc123",
    "fetched_at": "2026-11-20T08:00:00Z",
    "channel": "conda-forge"
  },
  "entries": {
    "py-opencv": ["opencv-python"],
    "pytorch": ["torch"],
    "zlib": []
  }
}
```

The published conda-forge/grayskull mapping is keyed by PyPI name and needs to
be inverted before use. Fetch it from your usual source, invert it into the
shape above, and stamp your own `provenance` (the upstream file has no fetch
time). Do not copy a mapping you did not fetch: its age must be true.

On air-gapped installs, copy the canonical file to the backend container by
your normal offline import path, set `AK_CONDA_PYPI_ALIAS_MAP`, then call the
reload endpoint below. No outbound network is needed; leave
`AK_CONDA_PYPI_ALIAS_MAP_URL` unset.

## Optional URL refresh

Set `AK_CONDA_PYPI_ALIAS_MAP_URL` to fetch the map on a timer instead of
managing the file by hand. It is off by default. The URL is operator
configuration (never a user-supplied value), is validated against the SSRF
allowlist, and is fetched with the same custom CA and non-blocking DNS
resolver as other trusted internal services. The body is capped at 32 MiB and
the request times out after 30 seconds.

By default the URL serves the canonical schema above. If it serves the
published grayskull shape instead, set `AK_CONDA_PYPI_ALIAS_MAP_FORMAT=grayskull`;
Artifact Keeper then inverts it and records the fetch time and URL as
provenance. The format is explicit so a malformed canonical document is
reported rather than silently reinterpreted as another shape. Grayskull
records without `conda_name` are rejected, never invented from the PyPI key.

A failed fetch logs a warning, records the error in the status, and **keeps
the last good map**. Coverage narrows only when no usable map was ever
loaded. A successful fetch replaces the whole map atomically, so a lookup
already in flight finishes against the old map rather than a half-loaded one.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `AK_CONDA_PYPI_ALIAS_MAP` | unset | Path to a canonical schema-tagged mapping file inside the backend container. Unset or empty: only the vendored table answers. |
| `AK_CONDA_PYPI_ALIAS_MAP_URL` | unset | Optional URL to fetch on a timer. Unset: no outbound requests. |
| `AK_CONDA_PYPI_ALIAS_MAP_FORMAT` | `canonical` | Shape served at the URL: `canonical` or `grayskull`. The on-disk file is always canonical. |
| `AK_CONDA_PYPI_ALIAS_REFRESH_SECS` | `86400` | Seconds between background reloads. Values below 60 fall back to one day. |
| `AK_CONDA_PYPI_ALIAS_MAX_AGE_HOURS` | unset (off) | Age past which a loaded map is `stale` and a throttled warning is logged. Ages are still reported while off. |

A bad path no longer only reaches the logs: the load error is in the API
status. A stale map stays in use; staleness means the renames it records are
still valid but packages added upstream since the fetch may be unmapped.

## Report and reload

Both routes are under `/api/v1/admin/security` and require an unscoped admin
token:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$AK/api/v1/admin/security/conda-alias-map"

curl -X POST -H "Authorization: Bearer $TOKEN" \
  "$AK/api/v1/admin/security/conda-alias-map/reload"
```

The `GET` response carries `state` (`built_in_only`, `loaded` or `stale`),
`loaded_entries`, `rejected_entries`, `source`, `fetched_at`, `age_seconds`,
`max_age_seconds`, `last_success_at`, `last_error`, `last_attempt_at` and
`refresh_url`. `POST` applies the configured source immediately: the URL when
set, otherwise the file. Replacing the file at the configured path and calling
`POST` makes a new mapping take effect without a restart.

A stale map also produces one warning per hour naming its source, age and
limit. The warning does not change a verdict: a missing or stale mapping is
reported honestly, and the existing unmapped-to-`partial` rule keeps an
unexamined package from rendering as clean.
