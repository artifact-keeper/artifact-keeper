# Curation E2E Tests Design

**Goal:** Validate the package curation workflow end-to-end using mock upstream repos and API-driven test scenarios.

**Approach:** API-only tests in the first pass. Client-side tests (yum/apt install behavior) come later when curation is wired into format handler index generation.

## Infrastructure

### Fixture Files

Static files in `scripts/native-tests/fixtures/curation/`:

- `rpm/repodata/repomd.xml` - Standard repomd pointing to primary.xml.gz
- `rpm/repodata/primary.xml.gz` - 6 test RPM packages (nginx, curl, telnet-server, wget, vim, nano)
- `deb/Packages` - 6 test DEB packages (nginx, curl, telnet, wget, vim, nano)
- `nginx.conf` - Serves RPM fixtures at `/rpm/` and DEB fixtures at `/deb/`

Package entries use realistic metadata (name, version, release, arch, checksum, location href) but do not need real binary files since curation only evaluates metadata.

### Docker Compose Additions

Add to `docker-compose.test.yml` under the `curation` profile:

- **mock-upstream**: `nginx:alpine` serving fixture files on port 80
- **curation-test**: `alpine/curl` (with jq) running the test script, depends on `setup` + `mock-upstream`

Integrates with `run-e2e-tests.sh` via `--profile curation`.

## Test Scenarios

The test script (`scripts/native-tests/test-curation.sh`) runs ~15 API-only tests:

1. Create remote repos pointing at mock-upstream (`http://mock-upstream/rpm/`, `http://mock-upstream/deb/`)
2. Create staging repos with `curation_enabled=true` linked to the remote repos
3. Trigger sync, poll until packages appear in the catalog
4. Verify initial state: packages evaluated based on default action
5. Create block rule (`telnet*` pattern), re-evaluate, verify telnet-server blocked
6. Create allow rule (`nginx` exact), re-evaluate, verify nginx approved
7. Test version constraints: block `curl < 8.0`, verify curl 8.5.0 passes
8. Test architecture filter: rule targeting `x86_64` only
9. Manual approve/block via single-package API endpoints
10. Bulk approve multiple packages, verify counts
11. Stats endpoint: verify status counts match expectations
12. Re-evaluate after rule changes, verify updated statuses
13. Global rules (no staging_repo_id): verify cross-repo application
14. Rule CRUD: update priority, delete rule, verify behavior
15. DEB format: repeat core flow (sync, rules, evaluate) for Debian repo

## Integration

- Profile name: `curation`
- Runs via: `./scripts/run-e2e-tests.sh --profile curation`
- Or standalone: `./scripts/native-tests/test-curation.sh`
- Follows same patterns as test-pypi.sh, test-npm.sh, etc.
