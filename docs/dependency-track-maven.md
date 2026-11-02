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

With automatic collections enabled, Maven coordinates determine identity:

```text
ru.molnet:MBOX_core                     collection, version = null
  ru.molnet:MBOX_core : 1.0.0            versioned project
  ru.molnet:MBOX_core : 2.1.0            versioned project
```

New collections and children use the exact qualified name `groupId:artifactId`,
the Maven `group` field and a Maven PURL. Both names include the group because DT
uniqueness is based on name/version, not group/name/version. Collections use
`collectionLogic=AGGREGATE_DIRECT_CHILDREN` and receive no SBOM. Each version
gets its own child and receives its own SBOM; different versions are never merged.

Existing exact qualified names, or artifactId names with matching group or Maven
PURL, are reused without renaming. A collection with an older arbitrary name can
be identified by its exact Maven PURL, including through an existing child's
parent. No fuzzy name matching is used. List/lookup responses are followed by
full project-detail reads before examining parent relationships.

If multiple collections or children match, an unversioned project is not a
direct-child collection, or an artifactId-only legacy project has neither group
nor PURL evidence, provisioning is skipped with a diagnostic. Existing data stays
intact. An operator can supply the correct group/PURL in DT after verifying the
identity, then rescan. The integration does not guess ownership or create a
duplicate as a fallback for ambiguous legacy data.

An existing child without a parent is attached using a partial PATCH containing
only the parent UUID. A child already linked to the correct parent needs no
update. A different existing parent is preserved, logged and remains the child's
parent; the child's normal SBOM upload continues. No project is deleted,
recreated, converted to a collection or stripped of its existing fields/history.
Ancestors are checked before adding a relationship to prevent cycles.

JAR and POM publications with the same coordinates already address the same DT
name/version when these features are disabled. This remains one version project
with collections enabled. Each eligible artifact submits its own inventory using
the existing upload path: DT processes successive BOMs as project updates, not as
an automatic union of JAR and POM inventories. This feature does not implement
inventory merging. Excluding a classifier does not affect a primary JAR or POM.

## Permissions, concurrency and failures

The API key's team needs `VIEW_PORTFOLIO` for list, lookup and full-detail reads,
`PORTFOLIO_MANAGEMENT` for explicit project creation and parent updates, and
`BOM_UPLOAD` for submission. Existing finding/policy reads also require
`VIEW_VULNERABILITY` and `VIEW_POLICY_VIOLATION`. `PROJECT_CREATION_UPLOAD` alone
does not authorize explicit project creation or parent assignment.

Maven provisioning is serialized within one client. Separate AK instances use
the same deterministic name/version identities; a creation HTTP 409 triggers
bounded exact lookups and full-detail validation of the winning project.
Parent assignment re-reads the child and never deliberately replaces a different
parent. DT 4.14 does not offer compare-and-set parent updates; coordinate manual
hierarchy edits with automated provisioning to avoid a concurrent operator edit
between the final read and PATCH. Different versions still upload separate BOMs.

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
