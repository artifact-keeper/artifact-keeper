-- Swarm-based chunked transfer sessions with per-chunk peer sourcing
-- Part of Borg Replication: Resumable Chunked Transfer Protocol

-- Transfer session: tracks an artifact being transferred to a requesting node
CREATE TABLE transfer_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    requesting_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    total_size BIGINT NOT NULL,
    chunk_size INTEGER NOT NULL DEFAULT 1048576,  -- 1MB default
    total_chunks INTEGER NOT NULL,
    completed_chunks INTEGER NOT NULL DEFAULT 0,
    checksum_algo VARCHAR(20) NOT NULL DEFAULT 'sha256',
    artifact_checksum VARCHAR(128) NOT NULL,
    status sync_status NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (artifact_id, requesting_node_id)
);

-- Individual chunks within a transfer session
-- Each chunk tracks which peer served it (swarm distribution)
CREATE TABLE transfer_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES transfer_sessions(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length INTEGER NOT NULL,
    checksum VARCHAR(128) NOT NULL,  -- SHA-256 of this chunk
    status sync_status NOT NULL DEFAULT 'pending',
    source_node_id UUID REFERENCES edge_nodes(id) ON DELETE SET NULL,  -- which peer served this chunk (NULL = central)
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    downloaded_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (session_id, chunk_index)
);

-- Chunk availability: which edge nodes have which chunks of which artifacts
-- Uses a compact bitfield representation for efficiency
-- For a 500MB artifact with 1MB chunks: 500 bits = 63 bytes
CREATE TABLE chunk_availability (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    chunk_bitmap BYTEA NOT NULL,         -- bit N set = node has chunk N
    total_chunks INTEGER NOT NULL,
    available_chunks INTEGER NOT NULL,   -- cached count for fast queries
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (edge_node_id, artifact_id)
);

-- Indexes for efficient chunk transfer queries
CREATE INDEX idx_transfer_sessions_requesting ON transfer_sessions (requesting_node_id, status);
CREATE INDEX idx_transfer_sessions_artifact ON transfer_sessions (artifact_id);
CREATE INDEX idx_transfer_chunks_session_status ON transfer_chunks (session_id, status);
CREATE INDEX idx_transfer_chunks_pending ON transfer_chunks (session_id, chunk_index)
    WHERE status = 'pending';
CREATE INDEX idx_chunk_availability_artifact ON chunk_availability (artifact_id)
    WHERE available_chunks > 0;
CREATE INDEX idx_chunk_availability_node ON chunk_availability (edge_node_id);
