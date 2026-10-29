# Conda security metrics

The conda controls (CEP-27 attestation verification, install-script analysis
and the package allowlist on a virtual channel) each export a Prometheus
counter, so they can be graphed and alerted on (#4711). All labels are bounded:
`repository` and `member` are repository keys, never package names.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ak_conda_attestation_total` | counter | `repository`, `outcome` | One per CEP-27 attestation decision; see the outcomes below. |
| `ak_conda_install_script_findings_total` | counter | `repository`, `kind` | Install scripts found in an uploaded package's payload. `kind` is the hook: `pre-link`, `post-link` or `pre-unlink`. The recipe's archived copy of a script in `info/` is the same script and counts once. |
| `ak_conda_allowlist_dropped_total` | counter | `repository`, `member` | Records a virtual channel's package allowlist kept out of a merged `repodata.json`, `run_exports.json`, `channeldata.json` or shard index. `repository` is the virtual, `member` the member that offered them: a remote member, or a hosted one when the list's scope is `all_members` (the default since #5055). |
| `ak_virtual_member_metadata_failures_total` | counter | `format`, `virtual_repo`, `member`, `reason` | A virtual member that could not contribute to a merged index (`format="conda"` for conda channels). |

`outcome` on `ak_conda_attestation_total`:

- `verified`: an attestation `PUT` whose bundle verified; it is stored.
- `rejected`: an attestation `PUT` whose bundle did not verify, refused because
  `CONDA_ATTESTATION_REQUIRE_VERIFIED` is on (the default). Nothing is stored.
- `failed`: an attestation `PUT` whose bundle did not verify, stored with its
  failed verification record because `CONDA_ATTESTATION_REQUIRE_VERIFIED` is
  explicitly off.
- `absent`: a package uploaded to a hosted channel. A package carries no
  attestation of its own; one is attached afterwards by `PUT`, which counts
  separately, so compare `absent` with `verified` for attestation coverage.

Allowlist drops are counted once per merge. A merged document served from the
merge cache, or by waiting on a merge already running, adds nothing, so the
rate follows merges, not requests.

Examples:

- Attestations refused in the last hour, by repository:
  `sum by (repository) (increase(ak_conda_attestation_total{outcome="rejected"}[1h]))`
- Any unverified attestation stored under the opt-out:
  `increase(ak_conda_attestation_total{outcome="failed"}[15m]) > 0`
- Packages with link-time hooks being published:
  `sum by (repository, kind) (rate(ak_conda_install_script_findings_total[1h]))`
- A member whose allowlist drops jump (an upstream adding packages, or an
  allowlist edit that went wrong):
  `sum by (repository, member) (increase(ak_conda_allowlist_dropped_total[1h]))`
