# Swarm Transfer Protocol

This document is the detailed specification for the swarm-based chunk transfer
protocol used by Borg Replication. For the high-level architecture, see
[README.md](README.md).


## Chunk Manifest Format

When a transfer session is initialized, the central hub computes a chunk
manifest from the artifact size and the configured `CHUNK_SIZE_BYTES`. The
manifest is returned as JSON:

```json
{
  "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "artifact_size": 49545218,
  "chunk_size": 1048576,
  "total_chunks": 48,
  "chunks": [
    {
      "index": 0,
      "byte_offset": 0,
      "byte_length": 1048576,
      "sha256": "a4f3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4"
    },
    {
      "index": 1,
      "byte_offset": 1048576,
      "byte_length": 1048576,
      "sha256": "b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5"
    },
    "...",
    {
      "index": 47,
      "byte_offset": 49283072,
      "byte_length": 262146,
      "sha256": "c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6"
    }
  ]
}
```

Notes:
- The last chunk may be smaller than `chunk_size` if the artifact size is not
  an exact multiple.
- `artifact_sha256` is the SHA-256 of the entire artifact (all chunks
  concatenated in order). It is used for final verification after all chunks
  have been assembled.
- Chunk indices are zero-based and contiguous.


## Bitfield Encoding

Chunk availability is represented as a compact bitfield. Each bit represents
one chunk. The encoding is **big-endian**: bit 0 of the bitfield corresponds to
chunk 0 and lives in the most significant bit (MSB) of byte 0.

### Layout

```
Byte 0:   [chunk 0] [chunk 1] [chunk 2] [chunk 3] [chunk 4] [chunk 5] [chunk 6] [chunk 7]
           bit 7      bit 6    bit 5      bit 4    bit 3      bit 2    bit 1      bit 0

Byte 1:   [chunk 8] [chunk 9] [chunk 10] [chunk 11] [chunk 12] [chunk 13] [chunk 14] [chunk 15]
           bit 7      bit 6    bit 5       bit 4      bit 3      bit 2      bit 1      bit 0

...
```

### Checking if chunk N is available

```
byte_index = N / 8
bit_index  = 7 - (N % 8)
has_chunk  = (bitfield[byte_index] >> bit_index) & 1
```

### Setting chunk N as available

```
byte_index = N / 8
bit_index  = 7 - (N % 8)
bitfield[byte_index] |= (1 << bit_index)
```

### Padding

If `total_chunks` is not a multiple of 8, the trailing bits in the last byte
are zero-padded and must be ignored.

### Wire format

Over the API, bitfields are transmitted as **base64-encoded** byte arrays. For
example, an artifact with 10 chunks where chunks 0-7 and chunk 9 are available:

```
Binary:   11111111 01000000
Hex:      0xFF 0x40
Base64:   /0A=
```

### Example: 48 chunks, all available

```
Binary:   11111111 11111111 11111111 11111111 11111111 11111111
          (6 bytes, 48 bits, all 1s)
Hex:      0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
Base64:   //////////8=
```


## Peer Selection Algorithm

When an edge needs to download an artifact, it must decide which chunks to
request from which peers. The algorithm runs on the requesting edge.

### Pseudocode

```
function select_peers(manifest, peer_bitfields, peer_metrics):
    # Build list of needed chunks
    needed = [c for c in manifest.chunks if not self.has_chunk(c.index)]

    # Score each peer
    for peer in peers:
        available = count_bits(peer.bitfield AND (NOT self.bitfield))
        peer.score = (available * peer.bandwidth_bps) / peer.latency_ms

    # Sort peers by score descending
    ranked_peers = sort(peers, by=score, descending=True)

    # Determine chunk selection strategy
    completion = (manifest.total_chunks - len(needed)) / manifest.total_chunks
    use_rarest_first = completion >= RAREST_FIRST_THRESHOLD

    if use_rarest_first:
        # Sort needed chunks by availability (ascending = rarest first)
        for chunk in needed:
            chunk.availability = count_peers_with_chunk(chunk.index, peer_bitfields)
        needed = sort(needed, by=availability, ascending=True)

    # Assign chunks to peers
    assignments = {}   # peer_id -> [chunk_indices]
    active_slots = {}  # peer_id -> number of assigned chunks

    for chunk in needed:
        # Find best peer that has this chunk and has capacity
        for peer in ranked_peers:
            if peer_has_chunk(peer, chunk.index):
                if active_slots.get(peer.id, 0) < proportional_share(peer):
                    assignments.setdefault(peer.id, []).append(chunk.index)
                    active_slots[peer.id] = active_slots.get(peer.id, 0) + 1
                    break

    return assignments


function proportional_share(peer):
    # A higher-scored peer gets more chunk assignments
    # Normalized so total assignments = MAX_CONCURRENT_CHUNK_DOWNLOADS
    return max(1, round(peer.score / total_score * MAX_CONCURRENT_CHUNK_DOWNLOADS))
```

### Walk-through

1. **Identify needed chunks** -- compare own bitfield against the manifest.
2. **Score peers** -- for each peer, compute how many needed chunks it has,
   weighted by bandwidth and penalized by latency.
3. **Rank peers** -- sort by score descending. Higher-scored peers get more
   assignments.
4. **Chunk ordering** -- before `RAREST_FIRST_THRESHOLD`, chunks are requested
   in sequential order (good for streaming / early use). After the threshold,
   switch to rarest-chunk-first to prevent long-tail scenarios.
5. **Assign chunks** -- iterate through needed chunks and assign each to the
   best available peer that has capacity.


## Rarest-Chunk-First Strategy

In a swarm, some chunks may be held by fewer peers than others. If every
requester asks for the same "easy" chunks first, the rare chunks become a
bottleneck at the end of the transfer.

The rarest-chunk-first strategy mitigates this:

```
Early in transfer (< 80% complete):
  Request chunks sequentially (0, 1, 2, ...).
  This is simple, predictable, and allows the artifact to be partially
  usable earlier (e.g., streaming a container layer).

Late in transfer (>= 80% complete):
  Switch to rarest-chunk-first.
  Count how many peers hold each remaining chunk.
  Request the rarest chunks first to maximize swarm health.
```

The threshold is controlled by `RAREST_FIRST_THRESHOLD` (default 0.8).

### Why not always rarest-first?

For the first 80% of a transfer, sequential ordering is preferred because:
- It enables streaming use cases (container layers, incremental archives).
- Network locality benefits from sequential reads on the source.
- The rarity signal is noisy early on when few peers have been queried.

### Rarity calculation

```
rarity(chunk_index) = count of peers whose bitfield has bit chunk_index set
```

Lower rarity = request sooner.

Ties are broken by chunk index (lower index first) to maintain a deterministic
ordering.


## Failure Handling and Retry Logic

### Per-chunk retry

When a chunk download fails (network error, hash mismatch, timeout), the
requesting edge:

1. Marks the chunk as `failed` in `transfer_chunks`.
2. Increments `transfer_chunks.attempts`.
3. Selects an alternate peer that also has the chunk.
4. Waits for an exponential backoff period before retrying.

### Backoff schedule

```
delay = min(2^(attempt - 1) seconds, MAX_BACKOFF_SECS)
```

| Attempt | Delay     |
|---------|-----------|
| 1       | 1 second  |
| 2       | 2 seconds |
| 3       | 4 seconds |
| 4       | 8 seconds |
| 5       | 16 seconds|
| ...     | ...       |
| 12      | 2048 seconds (capped at MAX_BACKOFF_SECS = 3600) |

### Peer blacklisting

If a peer fails to serve a chunk 3 times consecutively, it is temporarily
blacklisted for that transfer session. The requester will not request any
further chunks from that peer for the remainder of the session. The peer can
still serve other transfer sessions.

### Session-level failure

A transfer session is marked `failed` if:
- All peers have been blacklisted and there are still missing chunks.
- The whole-artifact checksum does not match after all chunks are assembled.
- A configurable maximum session duration is exceeded.

Failed sessions can be retried by creating a new transfer session. The new
session will recognize already-verified chunks via `chunk_availability` and
skip them.

### Diagram: retry flow

```
Edge A requests chunk 12 from Edge B
         |
         v
    Download chunk 12
         |
    +----+----+
    |         |
  Success   Failure
    |         |
    v         v
  Verify    Attempt < max?
  SHA-256      |
    |     +----+----+
    |     |         |
    v    Yes        No
  Mark    |         |
  verified|         v
    |     v      Blacklist Edge B
    |   Pick      for this session
    |   alternate    |
    |   peer         v
    |     |       Any peers
    |     v       remaining?
    |   Wait         |
    |   backoff  +---+---+
    |     |      |       |
    |     v     Yes      No
    |   Retry    |       |
    |   chunk    v       v
    |            (loop)  Mark session
    |                    failed
    v
  Update chunk_availability
  (Edge A is now seeder for chunk 12)
```


## Bandwidth Throttling Integration

Edges can configure upload and download bandwidth limits via the network
profile endpoint. The transfer engine respects these limits using a token bucket
algorithm.

### Token bucket

Each edge maintains two token buckets: one for upload, one for download.

```
bucket_capacity     = max_bps * 1 second (in bytes)
refill_rate         = max_bps bytes per second
tokens_per_chunk    = chunk.byte_length
```

Before initiating a chunk download, the edge checks if sufficient tokens are
available. If not, it waits until the bucket refills. This naturally throttles
concurrent transfers without requiring complex scheduling.

### Sync windows

If `sync_window_start` and `sync_window_end` are configured, transfers are
paused outside the window. The edge checks the current time (in its local
timezone) before starting each chunk download. If outside the window, it sleeps
until the window opens.

```
if current_time < sync_window_start or current_time > sync_window_end:
    sleep_until(sync_window_start)
```

### Interaction with concurrency limits

The `max_transfer_concurrency` setting on the edge node caps the total number
of simultaneous chunk transfers (across all sessions). Combined with bandwidth
throttling, this provides two layers of control:

1. **Concurrency** -- limits the number of parallel connections.
2. **Bandwidth** -- limits the total throughput in bytes/sec.

Both limits are enforced independently. A transfer must satisfy both before
proceeding.


## Multi-Peer Download Diagram

```
                    Artifact X (12 chunks)
                    =======================

    Edge B (seeder)          Edge C (seeder)          Edge D (seeder)
    has: all 12 chunks       has: chunks 0-7          has: chunks 4-11
    BW: 50 MB/s              BW: 100 MB/s             BW: 75 MB/s
    Latency: 20ms            Latency: 5ms             Latency: 10ms


    Edge A (requester, starting from 0 chunks)
    ==========================================

    Score calculation:
      Edge B: (12 * 50MB/s) / 20ms = 30,000,000
      Edge C: ( 8 * 100MB/s) / 5ms = 160,000,000
      Edge D: ( 8 * 75MB/s) / 10ms = 60,000,000

    Ranked: Edge C > Edge D > Edge B

    Assignment (MAX_CONCURRENT_CHUNK_DOWNLOADS = 8):
      Edge C: chunks 0, 1, 2, 3         (4 slots -- highest score)
      Edge D: chunks 4, 5, 6            (3 slots)
      Edge B: chunks 8                  (1 slot)

    After first wave completes:
      Edge A now has chunks 0-6, 8
      Edge A updates bitfield, becomes seeder for those chunks

    Second wave:
      Edge C: chunk 7                   (C still has it)
      Edge D: chunks 9, 10             (D has them)
      Edge B: chunk 11                  (B has it)

    After second wave:
      All 12 chunks verified
      Whole-artifact SHA-256 verified
      Session marked complete

    Timeline:
    =========
    t=0s    [C:0] [C:1] [C:2] [C:3] [D:4] [D:5] [D:6] [B:8]
    t=0.1s  ===== downloading =====================================
    t=0.2s  [done] chunks 0-6, 8 verified, bitfield updated
    t=0.2s  [C:7] [D:9] [D:10] [B:11]
    t=0.3s  ===== downloading =====================================
    t=0.4s  [done] all chunks verified, session complete
```
