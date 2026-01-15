-- Create sync_status enum
CREATE TYPE sync_status AS ENUM ('pending', 'in_progress', 'completed', 'failed', 'cancelled');

-- Create sync_tasks table
CREATE TABLE sync_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    status sync_status NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 0,
    bytes_transferred BIGINT NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(edge_node_id, artifact_id)
);

-- Create edge_cache_entries table
CREATE TABLE edge_cache_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    size_bytes BIGINT NOT NULL,
    last_accessed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    access_count BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(edge_node_id, artifact_id)
);

-- Create indexes
CREATE INDEX idx_sync_tasks_edge_status ON sync_tasks(edge_node_id, status);
CREATE INDEX idx_sync_tasks_priority ON sync_tasks(status, priority DESC, created_at);
CREATE INDEX idx_edge_cache_entries_edge ON edge_cache_entries(edge_node_id);
CREATE INDEX idx_edge_cache_entries_lru ON edge_cache_entries(edge_node_id, last_accessed_at);
