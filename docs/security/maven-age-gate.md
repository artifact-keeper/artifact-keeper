# Age gate for Maven and Gradle repositories

Since 1.12.0 (#4702) the publish-age gate that npm, PyPI, Go, Cargo and VS Code
Remotes have also covers Maven and Gradle Remotes, and the Virtuals over them.
The policy is the same everywhere: `PUT /api/v1/repositories/{key}/age-gate`
with `enabled`, `min_age_days` and `mode` (`upstream_publish_time` or
`first_seen`), reviews in `/api/v1/admin/age-gate/reviews` (or the
repository's own review routes), approve, reject and reopen. This page covers
what is specific to the Maven repository layout. sbt repositories have their
own handler and are not gated.

## What is gated

The package is `groupId:artifactId` (the identity curation and the proxy
catalog use) and the version is the path's version directory.

| Request | With the gate on |
|---|---|
| Any file in a version directory: `.pom`, `.jar`, `.war`, `.module`, `-sources.jar`, classifier archives | Served when the version is old enough or its review is approved; otherwise `451` with the shared `age_gate_blocked` body (`review_id`, `package`, `version`, `min_age_days`, `requested_age_days`) and a pending review. The `451` carries `Cache-Control: no-store` (RFC 7725 makes a `451` cacheable by default; this hold is lifted by a review or by time). A refused file is neither fetched nor cached; the gate only reads the version's POM, uncached, to date it. |
| That file's `.sha1`, `.md5`, `.sha256`, `.sha512`, `.asc` | Answers exactly as the file does (the same `451`). |
| GA-level `g/a/maven-metadata.xml` | Withheld versions are removed from `<versions>`; `<latest>` and `<release>` are re-pointed to the newest remaining version (release: newest non-SNAPSHOT). When nothing is withheld the upstream bytes are served unchanged. |
| `g/a/maven-metadata.xml.sha1` (and the other digests) | Computed from the served (filtered) metadata, so it always matches. |
| `-SNAPSHOT` versions and their metadata | Not gated, see below. |

There is no last-known-good substitution for Maven: a client asked for one
version's file, and another version's bytes under that file name would be a
different artifact. A refused version is always the `451`, as for Go.

A Virtual applies the gate of the Remote member a file comes from: a Remote
member whose gate withholds the version does not serve it, and when no other
member has the file the client gets that member's `451`. The merged
`maven-metadata.xml` lists a version from a gated Remote member only when that
member would serve it. Hosted members are never gated, and a GAV a hosted
member publishes disables the Remote members for that GAV as before.

## Where the publish time comes from

`upstream_publish_time` mode dates a version by the upstream `Last-Modified`
of its POM (`g/a/v/a-v.pom`):

- every Maven release has a POM, and the repository manager (Maven Central,
  Nexus, Artifactory) stamps it when the version is deployed;
- a released coordinate is immutable, so the date never moves once known.

The date is read from the proxy cache entry when the POM is already cached
(no upstream request), else from one upstream read of the POM, and is kept in
memory per repository and upstream for a day. A version whose POM carries
no parseable `Last-Modified` has no publish time and is withheld with the
`451` (the same rule every format follows). If your upstream sends no
`Last-Modified`, use `first_seen`.

A minimum age of 0 needs no date: nothing above is consulted for it, so an
unreadable POM does not refuse the download. A rejected review still blocks.

A version whose POM the upstream does not have (`404` or `410`) answers a
plain `404` and records no review, as an ungated Remote would: nothing is
served either way, and a resolver that tries several repositories in turn
moves on to the next one. When the upstream cannot be read to date a version
(a `5xx`, a timeout), the download answers `503 age_gate_unavailable` (fail
closed, retryable) and records no review.

Not used, and why:

- `maven-metadata.xml` `<lastUpdated>` is one timestamp for the whole
  `groupId:artifactId` (the last deploy of any version), not per version. It
  has one use: when it is older than the minimum age, every listed version is
  at least that old, so the metadata filter dates the whole list without
  reading any POM. It never admits a version on download.
- A search index (Maven Central's) belongs to one upstream and is not part of
  the layout other repository managers serve.

When `<lastUpdated>` is inside the gate window, the metadata filter reads up to
64 POMs per request (eight at a time, newest versions first) and caches each
date; undated versions beyond that are withheld from that listing and dated by
the next one. Downloads always decide each version on its own POM.

`first_seen` mode dates a version by the first time this server saw it
from that upstream, as for the other formats: the upstream metadata listing
and the upstream POM are the existence evidence that starts the clock.

## SNAPSHOT versions

`-SNAPSHOT` versions are not gated. A SNAPSHOT is rebuilt under the same
version by design, so "this version is N days old" has no meaning for it, and a
`first_seen` clock would age content that changes on every build. Keep
snapshots in a Remote of their own.
