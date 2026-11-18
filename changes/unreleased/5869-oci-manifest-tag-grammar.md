---
section: Fixed
issues: [#5869]
---
- **An OCI manifest push with an invalid tag is now refused with `400 TAG_INVALID` instead of being stored** (#5869). `PUT /v2/<name>/manifests/<reference>` took any non-digest reference as a tag, so `bad!tag`, `-lead`, `.lead`, a name over 128 characters, or a percent-escaped name like `a%20b` answered `201`, appeared in `tags/list` and could not be pulled or deleted by `docker`, `crane` or `skopeo`. A reference must now be a `sha256:` digest or match the distribution-spec tag grammar `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`, and the check runs before the manifest is read or stored. Tags already stored under an invalid name are left as they are. `GET`, `HEAD` and `DELETE` of a manifest by tag are not changed.
