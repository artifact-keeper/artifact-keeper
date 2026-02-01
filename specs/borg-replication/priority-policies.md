# Replication Priority Policies

This document describes the four priority levels used by Borg Replication to
control when and how artifacts are distributed across edge nodes. For the
high-level architecture, see [README.md](README.md).


## Priority Levels

### P0 -- Immediate

**Integer value:** `0`

Artifacts replicate as soon as they are published. When a new artifact version
is pushed to a P0 repository, the central hub immediately notifies all assigned
edge nodes and initiates transfer sessions. This is the most aggressive policy
and is intended for critical artifacts that must be available everywhere within
seconds.

**Use cases:**
- Security patches and hotfixes
- Base container images used by CI/CD pipelines
- Shared libraries where build breakage is time-sensitive

**Behavior:**
1. Artifact is published to the central hub.
2. Central hub sends a push notification to all edges assigned to the
   repository.
3. Each edge immediately initializes a transfer session.
4. Transfers proceed with maximum concurrency, ignoring sync windows.
5. P0 transfers pre-empt lower-priority transfers already in progress.

**Sync window override:** P0 transfers ignore `sync_window_start` and
`sync_window_end`. They run at any time.

**Concurrency:** P0 transfers can use up to 100% of `max_transfer_concurrency`.
Lower-priority transfers are paused if necessary.

---

### P1 -- Scheduled

**Integer value:** `1`

Artifacts replicate on a cron schedule. This is the default priority for most
repositories. It provides a predictable replication cadence without saturating
the network during business hours.

**Use cases:**
- Application release artifacts (nightly builds)
- Documentation bundles
- Non-critical container images

**Behavior:**
1. Artifact is published to the central hub.
2. The artifact is queued for replication but no transfer starts immediately.
3. At the next cron trigger, the edge checks for pending artifacts and
   initiates transfer sessions for all of them.
4. Transfers respect sync windows and bandwidth limits.

**Cron schedule format:**

The schedule is a standard 5-field cron expression stored in
`edge_repo_assignments.replication_schedule`:

```
 +------------ minute (0-59)
 | +---------- hour (0-23)
 | | +-------- day of month (1-31)
 | | | +------ month (1-12)
 | | | | +---- day of week (0-6, 0=Sunday)
 | | | | |
 * * * * *
```

**Examples:**

| Expression      | Meaning                              |
|-----------------|--------------------------------------|
| `0 2 * * *`     | Every day at 02:00 UTC               |
| `0 */4 * * *`   | Every 4 hours                        |
| `30 1 * * 1-5`  | Weekdays at 01:30 UTC                |
| `0 3 * * 0`     | Every Sunday at 03:00 UTC            |
| `*/15 * * * *`  | Every 15 minutes                     |

If no `replication_schedule` is set on the edge-repo assignment but the
effective priority is P1, the system falls back to a default schedule of
`0 */6 * * *` (every 6 hours).

---

### P2 -- On-Demand

**Integer value:** `2`

Artifacts replicate only when an edge node explicitly requests them. No
automatic replication occurs. This is useful for large artifacts that are rarely
needed at every edge, or for repositories with high churn where only the latest
version matters.

**Use cases:**
- Large binary assets (machine learning models, datasets)
- Archival repositories
- Developer-facing tools that vary by region

**Behavior:**
1. Artifact is published to the central hub.
2. No automatic replication is triggered.
3. When an edge needs the artifact (e.g., a client requests it), the edge
   calls `POST /transfer/init` to start a transfer session.
4. The transfer proceeds normally using the swarm protocol.
5. Transfers respect sync windows and bandwidth limits.

**Cache eviction:** On-demand artifacts may be subject to cache eviction
policies on edge nodes. If an artifact has not been accessed within a
configurable TTL, the edge may delete its local copy to reclaim storage. The
artifact can always be re-fetched.

---

### P3 -- Local-Only

**Integer value:** `3`

Artifacts are never replicated. They exist only on the node where they were
originally published. This is used for artifacts that contain sensitive data,
are environment-specific, or simply do not need to be distributed.

**Use cases:**
- Node-specific configuration bundles
- Artifacts containing secrets or credentials
- Temporary / ephemeral build artifacts
- Region-locked content

**Behavior:**
1. Artifact is published to its origin node.
2. No replication metadata is created.
3. Requests for the artifact from other edges are rejected with
   `403 Forbidden` and a message indicating the artifact is local-only.
4. The artifact does not appear in chunk availability bitfields.


## Override Semantics

Priority is determined by a two-level hierarchy:

```
Effective Priority = edge_repo_assignments.priority_override
                     ?? repositories.replication_priority
```

### Repository default

Set via `PUT /api/v1/repositories/:id/replication-priority`. This is the
baseline priority for all edges assigned to the repository.

```json
{
  "priority": 1
}
```

### Edge-repo override

Set via `POST /api/v1/edge-nodes/:id/repositories` (on assignment) or updated
later. This overrides the repository default for a specific edge.

```json
{
  "repository_id": "...",
  "priority_override": 0,
  "replication_schedule": "0 2 * * *"
}
```

### Resolution rules

| Repo Default | Edge Override | Effective Priority |
|--------------|-------------|-------------------|
| P1           | NULL        | P1                |
| P1           | P0          | P0                |
| P2           | P1          | P1                |
| P0           | P3          | P3                |
| P3           | P0          | P0                |

The override always wins when present. There is no "floor" or "ceiling" -- an
edge override of P3 on a P0 repo is valid (prevents replication to that
specific edge), and an override of P0 on a P3 repo is also valid (forces
immediate replication to that specific edge even though the repo default says
local-only).

### Override use cases

**Scenario 1: Critical edge gets P0, others get P1**

A production edge in us-east-1 needs artifacts immediately, while development
edges can wait for the nightly sync.

```
Repository "core-libs": replication_priority = 1 (P1)

Edge "prod-us-east-1":  priority_override = 0 (P0)
Edge "dev-eu-west-1":   priority_override = NULL (inherits P1)
Edge "dev-ap-south-1":  priority_override = NULL (inherits P1)
```

**Scenario 2: Restrict a repository to specific edges**

A repository containing region-specific data should only replicate to edges in
that region.

```
Repository "eu-compliance-docs": replication_priority = 3 (P3, local-only by default)

Edge "prod-eu-west-1":  priority_override = 0 (P0)
Edge "prod-eu-central": priority_override = 0 (P0)
Edge "prod-us-east-1":  priority_override = NULL (inherits P3, no replication)
```

**Scenario 3: Bandwidth-constrained edge with custom schedule**

An edge on a slow link should only sync during off-peak hours with a specific
schedule.

```
Repository "ml-models": replication_priority = 1 (P1)

Edge "remote-site":
  priority_override = 1 (P1)
  replication_schedule = "0 3 * * 0"   (Sundays at 03:00)
  sync_window_start = "02:00"
  sync_window_end = "06:00"
  max_download_bps = 10485760          (10 MB/s)
```


## Mapping to sync_task.priority

Internally, the replication system creates `sync_task` records to schedule
work. The `sync_task.priority` column is an integer where lower values mean
higher priority. The mapping is:

| Replication Priority | sync_task.priority | Scheduling Behavior |
|---------------------|--------------------|---------------------|
| P0 (Immediate)      | 0                  | Executed immediately, pre-empts lower priorities |
| P1 (Scheduled)      | 10                 | Queued, executed at next cron trigger |
| P2 (On-Demand)      | 20                 | Queued only when explicitly requested |
| P3 (Local-Only)     | N/A                | No sync_task is created |

The 10-point gap between levels leaves room for future sub-priorities. For
example, a future "P1-urgent" could use `sync_task.priority = 5`.

### Priority pre-emption

When a P0 task is created, the scheduler checks if the edge is already running
lower-priority transfers. If the edge's `max_transfer_concurrency` is fully
utilized, the scheduler pauses the lowest-priority active transfer to make room
for the P0 task. The paused transfer resumes automatically when concurrency
becomes available.

Pre-emption order (first to be paused):
1. P2 on-demand transfers
2. P1 scheduled transfers (oldest first)
3. P0 transfers are never pre-empted

### Task lifecycle

```
sync_task states:
  pending -> running -> completed
                    \-> failed -> pending (retry)
                    \-> cancelled

P0: pending -> running (immediate)
P1: pending -> waiting (until cron) -> running -> completed
P2: pending (until requested) -> running -> completed
```


## Common Configuration Examples

### High-availability production cluster

All repositories replicate immediately to all production edges.

```sql
-- Set all repos to P0
UPDATE repositories SET replication_priority = 0
WHERE namespace IN ('production', 'platform');

-- All prod edges inherit P0, no overrides needed
```

### Development environment with nightly sync

Dev edges get artifacts once a day during off-peak hours.

```sql
-- Repos default to P1
UPDATE repositories SET replication_priority = 1
WHERE namespace = 'development';

-- Dev edges use nightly schedule
UPDATE edge_repo_assignments
SET replication_schedule = '0 2 * * *'
WHERE edge_node_id IN (
  SELECT id FROM edge_nodes WHERE name LIKE 'dev-%'
);
```

### Mixed production and archive

Production repos are immediate; archive repos are on-demand.

```sql
-- Production repos
UPDATE repositories SET replication_priority = 0
WHERE namespace = 'production';

-- Archive repos
UPDATE repositories SET replication_priority = 2
WHERE namespace = 'archive';

-- Exception: the compliance edge needs archives immediately
INSERT INTO edge_repo_assignments (edge_node_id, repository_id, priority_override)
SELECT
  (SELECT id FROM edge_nodes WHERE name = 'compliance-edge'),
  id,
  0
FROM repositories
WHERE namespace = 'archive';
```

### Air-gapped edge with manual sync

An edge behind an air gap never receives automatic replication. Artifacts must
be loaded manually (e.g., via USB drive import).

```sql
-- Override all repos to P3 for the air-gapped edge
INSERT INTO edge_repo_assignments (edge_node_id, repository_id, priority_override)
SELECT
  (SELECT id FROM edge_nodes WHERE name = 'airgap-site'),
  id,
  3
FROM repositories;
```
