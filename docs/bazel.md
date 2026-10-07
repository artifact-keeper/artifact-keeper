# Bazel module registries

Artifact Keeper serves the Bazel module registry protocol (Bzlmod, the layout
of the Bazel Central Registry) at `/bazel/{repo_key}` (#2858). Point Bazel at a
repository with:

```bash
bazel build --registry=https://registry.example.com/bazel/<repo_key> //...
```

or put the same `--registry=` line in `.bazelrc`. Bazel queries registries in
the order given, so list the Artifact Keeper repository first and drop the
public BCR when a virtual repository proxies it for you.

## Repository types

| Type | What it serves |
|------|----------------|
| Hosted (`local`) | Modules published with `PUT /bazel/{repo}/modules/{name}/{version}/{file}` (`MODULE.bazel`, `source.json`, patches, overlays, source archives). `metadata.json` is generated from the versions that have a stored `MODULE.bazel`. Published files cannot be overwritten. |
| Remote | Proxies an upstream registry, normally `https://bcr.bazel.build`. Versioned files are cached permanently; `bazel_registry.json` and `metadata.json` are revalidated on the mutable TTL. |
| Virtual | Merges `metadata.json` across its members and resolves versioned files by member priority, subject to the shadowing rule below. |

Source archives named in a proxied `source.json` are still downloaded by Bazel
from their original URLs (GitHub and so on), as with the public BCR.

## Virtual repositories: a hosted module name hides the upstream module

When **any hosted member** of a virtual repository publishes a module name, the
virtual repository stops consulting its **remote** members for that name. This
applies to both the module's `metadata.json` and every versioned file under
`modules/{name}/`. It is the same dependency-confusion guard npm virtual
repositories use (#1217): an internal module cannot be silently replaced by a
public module that happens to share its name, whatever version numbers the
public one advertises.

The consequence: if you publish a private module under a name that also exists
on the BCR, every upstream version of that name disappears from the virtual
repository. Only the versions published to the hosted member(s) are advertised.

```text
virtual  bazel-all = [ bazel-internal (hosted), bazel-bcr (remote, BCR) ]

PUT bazel-internal/modules/rules_foo/0.0.1-internal/MODULE.bazel

GET bazel-all/modules/rules_foo/metadata.json
  -> {"versions": ["0.0.1-internal"], ...}      (no BCR versions of rules_foo)
```

Any module in your build graph, including **transitive** dependencies you do
not control, that asks for an upstream version of `rules_foo` (for example
`bazel_dep(name = "rules_foo", version = "1.2.0")` in some third-party
`MODULE.bazel`) then fails to resolve through the virtual repository, because
`1.2.0` is not among the advertised versions.

Ownership is decided over **all** members, not just those the caller can read.
A caller who cannot read a private hosted member that publishes `rules_foo`
gets `404` for that module from the virtual repository; it is never handed the
upstream copy in its place. Which hosted versions are advertised, and which
members serve content, follow the caller's read access.

### Recommendations

- **Give internal modules distinct names.** Use a prefix that cannot collide
  with a public module, such as `mycorp_rules_foo` or `internal_foo`, rather
  than reusing a BCR name.
- **To patch a public module, do not republish it under the same name in a
  hosted member of the shared virtual.** Prefer Bazel's own mechanisms:
  `single_version_override` with `patches = [...]` or `archive_override` /
  `git_override` in your root `MODULE.bazel`. These leave the registry view
  intact for every other consumer.
- **If you must fork a public module under its own name**, publish the forked
  versions to a hosted repository that sits in a *separate* virtual used only
  by the builds that want the fork, and accept that those builds see only the
  versions you published for that name.
- Before publishing a new internal module, check that the name is unused on
  the BCR (`https://bcr.bazel.build/modules/<name>/metadata.json` returns 404).

There is currently no per-repository switch to turn the shadowing off; a
per-repository opt-out may be added later (#4429).
