# Maven submission policy for Dependency-Track

These options affect only the Artifact Keeper → Dependency-Track integration.
They require Dependency-Track 4.14.x for automatic collections. Enable the
integration separately with `DEPENDENCY_TRACK_ENABLED=true`, its API URL and key.
For the bundled deployment, also start the `dtrack` Compose profile.

```dotenv
# Backward-compatible defaults
DEPENDENCY_TRACK_MAVEN_EXCLUDED_CLASSIFIERS=
DEPENDENCY_TRACK_AUTO_COLLECTIONS=false
```

To exclude documentation, source and test archives and group Maven versions:

```dotenv
DEPENDENCY_TRACK_MAVEN_EXCLUDED_CLASSIFIERS=javadoc,sources,tests,test-sources,test-javadoc
DEPENDENCY_TRACK_AUTO_COLLECTIONS=true
```

Restart the backend after changing configuration. The CSV is parsed once at
startup: surrounding whitespace is trimmed, empty elements and duplicates are
discarded, and classifier comparisons are exact and case-insensitive. Hyphens
are part of the classifier (`test-sources` is distinct from `sources`). An empty
CSV excludes nothing; there are no implicit exclusions.

Only Maven repositories are filtered. Classifiers come from
`MavenHandler::parse_coordinates()`, including release, literal SNAPSHOT and
timestamped SNAPSHOT paths. `core-sources-1.0.jar` has artifactId `core-sources`
and no classifier; it is eligible. `core-1.0-sources.jar` has classifier `sources`.
Primary JARs, POMs and WARs have no classifier and remain eligible. Maven metadata,
checksums and signatures retain their existing processing; sidecars are never
interpreted as classifiers by this policy. Other repository formats are unchanged.

An excluded artifact is stored and served normally. Local Trivy/Grype scans,
inventory, findings, security scores, quality gates, quarantine and manual scans
continue through the existing pipeline. The exclusion runs only inside DT
submission, before dependency extraction, SBOM generation and every DT API call.
It does not remove previously generated local SBOMs, findings or DT projects.

## Collection identity and existing projects

Automatic collections use the Maven group, artifact ID and Artifact Keeper
repository UUID as the Dependency-Track project name. The two versions below
belong to the same repository.

```text
ru.molnet:MBOX_core [c307710c-8448-4850-87db-f716b332c64e]    collection, version = null
  ru.molnet:MBOX_core [c307710c-8448-4850-87db-f716b332c64e]  version 1.0.0
  ru.molnet:MBOX_core [c307710c-8448-4850-87db-f716b332c64e]  version 2.1.0
```

Different repositories, including those created on independent Artifact Keeper
installations sharing Dependency-Track, get separate collections and children
even when their coordinates and repository keys match. Replicas of one
installation share repository UUIDs. A database clone also retains those UUIDs.
When the name would exceed Dependency-Track's 255-character limit, it uses
`maven:sha256:<coordinate digest> [<repository UUID>]`.

Each project has the Maven group and PURL. The collection uses
`AGGREGATE_DIRECT_CHILDREN`. Each version has its own child and receives its
own SBOM. The integration finds projects through an exact name/version lookup.
Unscoped projects may match the Maven PURL while belonging to a different
repository, so enabling collections starts a scoped hierarchy and leaves those
projects and their history intact. To retain a previous project's history in
the hierarchy, verify which repository owns it and rename it in Dependency-Track
to the scoped name before the first eligible submission. A conflicting project
at the scoped name stops submission for that coordinate and logs a diagnostic.

An existing scoped child without a parent is attached with a partial PATCH that
carries its current `active`, `isLatest` and `collectionLogic` values. Parent
assignment checks ancestors for cycles. A child that already has a parent keeps
that relationship and continues to receive its SBOM.

JAR and POM publications with the same coordinates already address the same DT
name/version when these features are disabled. This remains one version project
with collections enabled. Each eligible artifact submits its own inventory using
the existing upload path: DT processes successive BOMs as project updates, not as
an automatic union of JAR and POM inventories. This feature does not implement
inventory merging. Excluding a classifier does not affect a primary JAR or POM.

## Permissions, concurrency and failures

The API key's team needs `VIEW_PORTFOLIO` for lookup and full-detail reads,
`PORTFOLIO_MANAGEMENT` for explicit project creation and parent updates, and
`BOM_UPLOAD` for submission. Existing finding/policy reads also require
`VIEW_VULNERABILITY` and `VIEW_POLICY_VIOLATION`. `PROJECT_CREATION_UPLOAD` alone
does not authorize explicit project creation or parent assignment.

Existing version projects with a parent are resolved through HTTP alone.
Hierarchy changes are serialized for the same repository and Maven group/artifact
pair. Replicas sharing a database take a PostgreSQL advisory lock on a dedicated
session. The 30-second deadline covers lookup, lock acquisition and HTTP
provisioning, and the session closes if the work is cancelled or times out.
Each client allows up to four concurrent lock sessions outside the request pool.
A creation HTTP 409 triggers exact lookups and validation of the winning project.

Parent assignment re-reads the child before PATCH. Coordinate manual edits to
the same hierarchy with automated provisioning because DT 4.14 applies parent
changes without a compare-and-set condition.

Transport errors, permission errors (401/403), unresolved conflicts and server
errors are logged with operation/status diagnostics. They stop that DT submission
and do not fail artifact publication or change local scan results. An interruption
can leave a valid empty collection or child, reused on the next scan. There is no
new background retry queue; rescan after restoring DT availability or permissions.
Logs never include the configured API key.

Disable collections independently with `DEPENDENCY_TRACK_AUTO_COLLECTIONS=false`.
Disable exclusions independently by setting the CSV to empty. Existing projects
and parent relationships remain in DT when either option is disabled. With both
defaults, the original project lookup/create/upload path is used unchanged.

API contract references: [DT REST API](https://docs.dependencytrack.org/integrations/rest-api/),
[4.14.0 project resource and OpenAPI annotations](https://github.com/DependencyTrack/dependency-track/blob/4.14.0/src/main/java/org/dependencytrack/resources/v1/ProjectResource.java),
[4.14.0 project model](https://github.com/DependencyTrack/dependency-track/blob/4.14.0/src/main/java/org/dependencytrack/model/Project.java),
and [collection projects](https://docs.dependencytrack.org/usage/collection-projects/).

The request/response contract was also verified against `/api/openapi.json`
generated by the official `dependency-track-apiserver.jar` 4.14.0 release
(SHA-256 `2e3d5bcfb7b5d4ad4daf789bc5ca3802ef05d012c516090e8bc5323f46585f53`).
That specification defines `Project.parent` as a project reference, `group` and
`purl` as strings, `collectionLogic` with `AGGREGATE_DIRECT_CHILDREN`, and
`PATCH /v1/project/{uuid}` as the partial-update operation.
