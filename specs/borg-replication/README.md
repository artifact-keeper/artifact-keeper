# Borg Replication

## Overview

Borg Replication evolves artifact-keeper's hub-spoke edge node system into a
full mesh topology. In the original model, every edge node synchronized
exclusively through the central hub. Borg Replication removes that bottleneck:
any edge can replicate to and from any other edge, artifacts are distributed in
swarm fashion (pieces fetched from multiple peers simultaneously), and
network-aware scheduling ensures bandwidth is used efficiently.

Key capabilities:

- **Mesh topology** -- edges communicate directly, reducing central hub load
  and improving transfer speeds for geographically close nodes.
- **Swarm distribution** -- large artifacts are split into chunks that can be
  fetched from many peers in parallel, similar to BitTorrent.
- **Priority policies** -- four priority tiers (P0-P3) control when and how
  aggressively artifacts replicate.
- **Chunked transfers with resume** -- transfers survive network interruptions
  and resume from the last verified chunk.
- **Network-aware scheduling** -- bandwidth limits, sync windows, and
  concurrency caps prevent replication from saturating production links.


## Architecture

### The Four Pillars

```
+---------------------------+     +-----------------------------+
|  1. Priority Policies     |     |  2. Chunked Transfer Proto  |
|  P0 Immediate             |     |  Configurable chunk size    |
|  P1 Scheduled / Cron      |     |  Per-chunk SHA-256 verify   |
|  P2 On-demand             |     |  Resume on reconnect        |
|  P3 Local-only            |     |                             |
+---------------------------+     +-----------------------------+
+---------------------------+     +-----------------------------+
|  3. Swarm Distribution    |     |  4. Mesh Peer Discovery     |
|  Multi-peer parallel DL   |     |  Central registry + gossip  |
|  Rarest-chunk-first       |     |  Peer scoring algorithm     |
|  Instant seeding          |     |  Latency / BW tracking      |
+---------------------------+     +-----------------------------+
```

#### 1. Replication Priority Policies

Every repository carries a default replication priority. Each edge-repo
assignment can override that default. The four levels are:

| Priority | Name       | Behavior |
|----------|------------|----------|
| P0       | Immediate  | Replicate as soon as the artifact is published. Transfer begins within seconds. |
| P1       | Scheduled  | Replicate on a cron schedule (e.g., nightly at 02:00 UTC). |
| P2       | On-demand  | Replicate only when an edge explicitly requests the artifact. |
| P3       | Local-only | Never replicate. The artifact exists only on its origin node. |

A per-repo default is stored in `repositories.replication_priority`. A per-edge
override is stored in `edge_repo_assignments.priority_override`. When deciding
the effective priority for a given (edge, repo) pair, the override wins if
present; otherwise the repo default applies.

See [priority-policies.md](priority-policies.md) for the full deep dive.

#### 2. Chunked Transfer Protocol

Artifacts are split into fixed-size chunks before transfer. The default chunk
size is 1 MB (1,048,576 bytes). Each chunk carries its own SHA-256 digest so
corruption is detected immediately on receipt.

```
Artifact (47 MB)
 |
 +-- chunk 0   [0 .. 1048575]        sha256: a1b2c3...
 +-- chunk 1   [1048576 .. 2097151]   sha256: d4e5f6...
 +-- chunk 2   [2097152 .. 3145727]   sha256: 789abc...
 |   ...
 +-- chunk 46  [48234496 .. 49283071] sha256: def012...
 +-- chunk 47  [49283072 .. 49545217] sha256: 345678...  (partial, last chunk)
```

On reconnect after a failure, the receiving edge queries the transfer session
for the list of already-verified chunks and resumes from the first missing one.
No data is re-transferred unnecessarily.

See [swarm-protocol.md](swarm-protocol.md) for wire format details.

#### 3. Swarm Distribution

When an edge needs an artifact, it does not download every chunk from a single
source. Instead:

1. It queries the central registry for chunk availability across all active
   peers that hold any chunks of the target artifact.
2. It ranks peers using a scoring function (see Peer Scoring below).
3. It requests different chunks from different peers in parallel, up to
   `MAX_CONCURRENT_CHUNK_DOWNLOADS` simultaneous transfers.
4. As chunks arrive and pass verification, the receiving edge immediately
   updates its own chunk availability bitfield, becoming a seeder for those
   chunks.
5. Late in the transfer (past `RAREST_FIRST_THRESHOLD`), the edge switches to
   a rarest-chunk-first strategy to avoid a long tail where the last few chunks
   are only available from a single slow peer.

```
                          Central Registry
                         (chunk availability)
                               |
              +----------------+----------------+
              |                |                |
           Edge A           Edge B           Edge C
          (seeder)         (seeder)         (requester)
          has all          has chunks
          chunks           0-23
              |                |
              |   chunk 24     |   chunk 0
              +------->--------+------->--------+
              |   chunk 25     |   chunk 1      |
              +------->--------+------->--------+
              |   ...          |   ...          |
              |                |                v
              |                |          Edge C now has
              |                |          chunks 0-25 and
              |                |          is itself a seeder
```

#### 4. Mesh Peer Discovery

Edge nodes register themselves with the central hub on startup and send
periodic heartbeats. The central hub maintains a peer graph containing:

- Node identity and endpoint URL
- Last heartbeat timestamp
- Network metrics: measured latency (ms), estimated bandwidth (bytes/sec)
- Set of repositories the edge is assigned to

Edges can also probe each other directly (`POST /peers/probe`) to measure
point-to-point latency and bandwidth. Probe results are reported back to the
central registry so the peer graph stays current.

**Peer scoring formula:**

```
score = (chunks_needed * bandwidth_estimate) / latency
```

Where:
- `chunks_needed` is the number of chunks the candidate peer has that the
  requester still needs.
- `bandwidth_estimate` is the measured or estimated bandwidth to that peer in
  bytes/sec.
- `latency` is the round-trip time in milliseconds.

Higher scores are better. The requester assigns chunks to peers in descending
score order, distributing load proportionally to score.


## Database Schema

### repositories (modified)

```sql
ALTER TABLE repositories
  ADD COLUMN replication_priority SMALLINT NOT NULL DEFAULT 1;
-- 0 = P0 (immediate), 1 = P1 (scheduled), 2 = P2 (on-demand), 3 = P3 (local-only)
```

### edge_repo_assignments (modified)

```sql
ALTER TABLE edge_repo_assignments
  ADD COLUMN priority_override   SMALLINT,           -- NULL = use repo default
  ADD COLUMN replication_schedule TEXT;               -- cron expression, e.g. '0 2 * * *'
-- priority_override: same 0-3 scale as repositories.replication_priority
-- replication_schedule: only meaningful when effective priority = P1
```

### transfer_sessions (new)

Tracks an in-progress artifact transfer to a specific edge.

```sql
CREATE TABLE transfer_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id     UUID NOT NULL REFERENCES artifacts(id),
  target_node_id  UUID NOT NULL REFERENCES edge_nodes(id),
  total_chunks    INT  NOT NULL,
  chunk_size      INT  NOT NULL DEFAULT 1048576,
  status          TEXT NOT NULL DEFAULT 'in_progress',
    -- in_progress | complete | failed | cancelled
  artifact_sha256 TEXT NOT NULL,        -- whole-artifact checksum
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_transfer_sessions_target ON transfer_sessions(target_node_id, status);
```

### transfer_chunks (new)

Individual chunk state within a transfer session.

```sql
CREATE TABLE transfer_chunks (
  session_id     UUID    NOT NULL REFERENCES transfer_sessions(id) ON DELETE CASCADE,
  chunk_index    INT     NOT NULL,
  byte_offset    BIGINT  NOT NULL,
  byte_length    INT     NOT NULL,
  expected_sha256 TEXT   NOT NULL,
  source_node_id UUID   REFERENCES edge_nodes(id),  -- which peer served this chunk
  status         TEXT   NOT NULL DEFAULT 'pending',
    -- pending | downloading | verified | failed
  attempts       INT    NOT NULL DEFAULT 0,
  verified_at    TIMESTAMPTZ,
  PRIMARY KEY (session_id, chunk_index)
);
```

### chunk_availability (new)

Compact bitfield tracking which chunks each edge holds for a given artifact.

```sql
CREATE TABLE chunk_availability (
  edge_node_id  UUID   NOT NULL REFERENCES edge_nodes(id),
  artifact_id   UUID   NOT NULL REFERENCES artifacts(id),
  bitfield      BYTEA  NOT NULL,  -- big-endian, bit 0 = chunk 0 in byte 0 MSB
  total_chunks  INT    NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (edge_node_id, artifact_id)
);
```

### peer_connections (new)

Unidirectional link between two edge nodes with measured network metrics.

```sql
CREATE TABLE peer_connections (
  from_node_id      UUID   NOT NULL REFERENCES edge_nodes(id),
  to_node_id        UUID   NOT NULL REFERENCES edge_nodes(id),
  latency_ms        FLOAT,           -- last measured RTT
  bandwidth_bps     BIGINT,          -- estimated bytes/sec
  last_probed_at    TIMESTAMPTZ,
  probe_count       INT    NOT NULL DEFAULT 0,
  PRIMARY KEY (from_node_id, to_node_id)
);
```

### edge_nodes (modified)

Network profile columns for bandwidth controls and scheduling.

```sql
ALTER TABLE edge_nodes
  ADD COLUMN max_upload_bps       BIGINT,         -- NULL = unlimited
  ADD COLUMN max_download_bps     BIGINT,         -- NULL = unlimited
  ADD COLUMN sync_window_start    TIME,           -- NULL = anytime
  ADD COLUMN sync_window_end      TIME,           -- NULL = anytime
  ADD COLUMN max_transfer_concurrency INT NOT NULL DEFAULT 8;
```


## Transfer Flow

A step-by-step walkthrough of a swarm transfer:

```
Edge A                    Central Hub                 Edge B, Edge C
  |                           |                           |
  |  1. "I need artifact X"   |                           |
  |-------------------------->|                           |
  |                           |                           |
  |  2. Create transfer_session, generate chunk manifest  |
  |  <-- session_id + manifest (chunk count, sizes, hashes)
  |                           |                           |
  |  3. Query chunk_availability for artifact X           |
  |-------------------------->|                           |
  |  <-- bitfields for Edge B (all chunks), Edge C (chunks 0-30)
  |                           |                           |
  |  4. Score peers:                                      |
  |     Edge B: (47 * 50MB/s) / 12ms = 195833            |
  |     Edge C: (31 * 100MB/s) / 5ms = 620000            |
  |                           |                           |
  |  5. Request chunks in parallel                        |
  |  -- chunks 31-47 from Edge B (only B has them) ------>|
  |  -- chunks 0-30 from Edge C (C is faster) ----------->|
  |                           |                           |
  |  6. Verify each chunk SHA-256 on receipt              |
  |                           |                           |
  |  7. Update own chunk_availability after each chunk    |
  |     (Edge A is now a seeder for verified chunks)      |
  |                           |                           |
  |  8. All chunks received: verify whole-artifact SHA-256|
  |     Mark transfer_session status = 'complete'         |
  |                           |                           |
  |  9. On any chunk failure:                             |
  |     - Retry from alternate peer                       |
  |     - Exponential backoff: 1s, 2s, 4s, ... MAX_BACKOFF_SECS
  |     - After max retries, mark session 'failed'        |
```

Detailed steps:

1. **Edge A needs artifact X** -- triggered by P0 push notification, P1 cron
   schedule, or P2 on-demand request.
2. **Central creates transfer_session** -- computes the chunk manifest from the
   artifact size and `CHUNK_SIZE_BYTES`. Each chunk gets a byte range and
   expected SHA-256. Inserts rows into `transfer_sessions` and
   `transfer_chunks`.
3. **Edge A queries chunk availability** -- calls
   `GET /edge-nodes/:id/chunks/:artifact_id` to retrieve bitfields for all
   active peers that have at least one chunk of artifact X.
4. **Peer scoring** -- Edge A ranks peers using the formula
   `(chunks_needed * bandwidth_estimate) / latency` and assigns chunks to peers
   proportionally.
5. **Parallel chunk download** -- Edge A opens up to
   `MAX_CONCURRENT_CHUNK_DOWNLOADS` parallel connections, requesting different
   chunks from different peers.
6. **Per-chunk SHA-256 verification** -- each chunk is hashed on receipt. If the
   hash does not match, the chunk is discarded and retried from an alternate
   peer.
7. **Immediate seeding** -- as soon as a chunk is verified, Edge A updates its
   own `chunk_availability` bitfield. Other edges that need the same artifact
   can now fetch those chunks from Edge A.
8. **Completion** -- when all chunks are verified, the whole artifact checksum
   is computed and compared to `transfer_sessions.artifact_sha256`. If it
   matches, the session is marked complete.
9. **Failure handling** -- individual chunk failures trigger retries from
   alternate peers with exponential backoff (1s, 2s, 4s, ..., up to
   `MAX_BACKOFF_SECS`). If all peers are exhausted, the session is marked
   failed and an alert is raised.


## API Endpoints

### Repository Replication Priority

```
PUT /api/v1/repositories/:id/replication-priority
```

Set the default replication priority for a repository.

**Request body:**

```json
{
  "priority": 0
}
```

Values: `0` (P0 immediate), `1` (P1 scheduled), `2` (P2 on-demand), `3` (P3 local-only).

**Response:** `200 OK` with updated repository object.

---

### Edge-Repo Assignment (modified)

```
POST /api/v1/edge-nodes/:id/repositories
```

Assign a repository to an edge node. Now accepts optional priority override and
replication schedule.

**Request body:**

```json
{
  "repository_id": "550e8400-e29b-41d4-a716-446655440000",
  "priority_override": 0,
  "replication_schedule": "0 2 * * *"
}
```

Both `priority_override` and `replication_schedule` are optional. If omitted,
the repo default priority applies and no cron schedule is set.

---

### Initialize Transfer Session

```
POST /api/v1/edge-nodes/:id/transfer/init
```

Create a new chunked transfer session for an artifact.

**Request body:**

```json
{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:** `201 Created`

```json
{
  "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "total_chunks": 47,
  "chunk_size": 1048576,
  "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### Get Chunk Manifest

```
GET /api/v1/edge-nodes/:id/transfer/:session/chunks
```

Returns the full chunk manifest for a transfer session.

**Response:** `200 OK`

```json
{
  "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "chunks": [
    {
      "index": 0,
      "byte_offset": 0,
      "byte_length": 1048576,
      "expected_sha256": "a1b2c3d4...",
      "status": "pending"
    },
    {
      "index": 1,
      "byte_offset": 1048576,
      "byte_length": 1048576,
      "expected_sha256": "d4e5f6a7...",
      "status": "verified"
    }
  ]
}
```

---

### Download Chunk

```
GET /api/v1/edge-nodes/:id/transfer/:session/chunk/:n
```

Download chunk N as raw bytes. The response includes the expected hash in a
header for client-side verification.

**Response headers:**

```
Content-Type: application/octet-stream
X-Chunk-SHA256: a1b2c3d4...
Content-Length: 1048576
```

---

### Verify Chunk

```
POST /api/v1/edge-nodes/:id/transfer/:session/chunk/:n/verify
```

Report that a chunk has been received and verified (or failed verification).

**Request body:**

```json
{
  "sha256": "a1b2c3d4...",
  "verified": true
}
```

**Response:** `200 OK`

---

### Complete Transfer

```
POST /api/v1/edge-nodes/:id/transfer/:session/complete
```

Finalize the transfer session after all chunks are verified.

**Request body:**

```json
{
  "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb924..."
}
```

Server compares the provided hash against the expected whole-artifact hash. If
they match, the session is marked complete. If not, the session is marked failed.

**Response:** `200 OK` on success, `409 Conflict` on hash mismatch.

---

### List Known Peers

```
GET /api/v1/edge-nodes/:id/peers
```

Returns the list of peers known to this edge, including network metrics.

**Response:**

```json
{
  "peers": [
    {
      "node_id": "...",
      "name": "edge-us-west-2",
      "latency_ms": 12.5,
      "bandwidth_bps": 52428800,
      "last_probed_at": "2026-01-15T10:30:00Z",
      "status": "active"
    }
  ]
}
```

---

### Probe Peer

```
POST /api/v1/edge-nodes/:id/peers/probe
```

Initiate a network probe to measure latency and bandwidth to a target peer.

**Request body:**

```json
{
  "target_node_id": "..."
}
```

**Response:** `200 OK` with measured metrics.

---

### Get Chunk Availability

```
GET /api/v1/edge-nodes/:id/chunks/:artifact_id
```

Returns the chunk availability bitfield for this edge and artifact.

**Response:**

```json
{
  "artifact_id": "...",
  "total_chunks": 47,
  "bitfield": "//////////4=",
  "available_count": 47,
  "complete": true
}
```

The `bitfield` is base64-encoded. See [swarm-protocol.md](swarm-protocol.md)
for encoding details.

---

### Update Chunk Availability

```
PUT /api/v1/edge-nodes/:id/chunks/:artifact_id
```

Update the chunk availability bitfield after receiving new chunks.

**Request body:**

```json
{
  "bitfield": "//////////4=",
  "total_chunks": 47
}
```

---

### Set Network Profile

```
PUT /api/v1/edge-nodes/:id/network-profile
```

Configure bandwidth limits, sync windows, and transfer concurrency.

**Request body:**

```json
{
  "max_upload_bps": 104857600,
  "max_download_bps": 209715200,
  "sync_window_start": "02:00:00",
  "sync_window_end": "06:00:00",
  "max_transfer_concurrency": 4
}
```

All fields are optional. Pass `null` to remove a limit.


## Configuration

Environment variables controlling Borg Replication behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `CHUNK_SIZE_BYTES` | `1048576` (1 MB) | Size of each transfer chunk in bytes. Larger chunks reduce overhead but increase retry cost on failure. |
| `MAX_CONCURRENT_CHUNK_DOWNLOADS` | `8` | Maximum number of chunks an edge will download simultaneously across all peers. |
| `PEER_PROBE_INTERVAL_SECS` | `300` (5 min) | How often an edge probes its peers to refresh latency and bandwidth estimates. |
| `STALE_HEARTBEAT_MINUTES` | `5` | An edge is considered offline if no heartbeat has been received within this window. |
| `MAX_BACKOFF_SECS` | `3600` (1 hour) | Maximum exponential backoff delay for chunk retry attempts. |
| `RAREST_FIRST_THRESHOLD` | `0.8` | When a transfer is this fraction complete (0.0-1.0), switch to rarest-chunk-first selection to avoid long-tail delays. |

Example `.env` snippet:

```bash
CHUNK_SIZE_BYTES=2097152            # 2 MB chunks for high-bandwidth links
MAX_CONCURRENT_CHUNK_DOWNLOADS=16   # aggressive parallelism
PEER_PROBE_INTERVAL_SECS=120        # probe every 2 minutes
STALE_HEARTBEAT_MINUTES=3           # tight failure detection
MAX_BACKOFF_SECS=1800               # cap backoff at 30 minutes
RAREST_FIRST_THRESHOLD=0.7          # switch to rarest-first at 70%
```
