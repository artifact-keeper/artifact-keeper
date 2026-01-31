-- Mesh peer discovery and connection tracking
-- Part of Borg Replication: Mesh Peer Discovery
-- Unidirectional links: each row represents source → target with measured network metrics

DO $$ BEGIN
    CREATE TYPE peer_status AS ENUM ('active', 'probing', 'unreachable', 'disabled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS peer_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    target_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    status peer_status NOT NULL DEFAULT 'probing',
    latency_ms INTEGER,                      -- measured RTT in milliseconds
    bandwidth_estimate_bps BIGINT,           -- estimated bandwidth in bits/sec
    shared_artifacts_count INTEGER NOT NULL DEFAULT 0,  -- how many artifacts both nodes have
    shared_chunks_count INTEGER NOT NULL DEFAULT 0,     -- for swarm peer scoring
    last_probed_at TIMESTAMP WITH TIME ZONE,
    last_transfer_at TIMESTAMP WITH TIME ZONE,
    bytes_transferred_total BIGINT NOT NULL DEFAULT 0,
    transfer_success_count INTEGER NOT NULL DEFAULT 0,
    transfer_failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (source_node_id, target_node_id),
    CHECK (source_node_id != target_node_id)
);

-- Indexes for peer lookups
CREATE INDEX IF NOT EXISTS idx_peer_connections_source ON peer_connections (source_node_id, status)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_peer_connections_target ON peer_connections (target_node_id, status)
    WHERE status = 'active';
-- For finding best peers: order by latency, filter by bandwidth
CREATE INDEX IF NOT EXISTS idx_peer_connections_quality
    ON peer_connections (source_node_id, latency_ms, bandwidth_estimate_bps DESC)
    WHERE status = 'active';
