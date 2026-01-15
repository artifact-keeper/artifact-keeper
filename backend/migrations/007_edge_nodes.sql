-- Create edge_status enum
CREATE TYPE edge_status AS ENUM ('online', 'offline', 'syncing', 'degraded');

-- Create edge_nodes table
CREATE TABLE edge_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    endpoint_url VARCHAR(2048) NOT NULL,
    status edge_status NOT NULL DEFAULT 'offline',
    region VARCHAR(100),
    cache_size_bytes BIGINT NOT NULL DEFAULT 10737418240, -- 10GB default
    cache_used_bytes BIGINT NOT NULL DEFAULT 0,
    last_heartbeat_at TIMESTAMP WITH TIME ZONE,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_filter JSONB, -- Filter criteria for what to sync
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create edge_repo_assignments table
CREATE TABLE edge_repo_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_node_id UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    sync_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(edge_node_id, repository_id)
);

-- Create indexes
CREATE INDEX idx_edge_nodes_status ON edge_nodes(status);
CREATE INDEX idx_edge_nodes_region ON edge_nodes(region);
CREATE INDEX idx_edge_repo_assignments_edge ON edge_repo_assignments(edge_node_id);
CREATE INDEX idx_edge_repo_assignments_repo ON edge_repo_assignments(repository_id);
