-- Peer Mesh Network Migration
-- Converts hub-and-spoke "edge nodes" model to decentralized peer mesh.
-- Phase 1: Schema changes for peer mesh networking.

-- 1. Create peer_instance_identity singleton table
CREATE TABLE peer_instance_identity (
    peer_instance_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    endpoint_url VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Ensure only one row can ever exist (singleton)
CREATE UNIQUE INDEX idx_peer_instance_identity_singleton ON peer_instance_identity ((1));

-- 2. Rename edge_status enum to instance_status
ALTER TYPE edge_status RENAME TO instance_status;

-- 3. Rename edge_nodes table to peer_instances and add new columns
ALTER TABLE edge_nodes RENAME TO peer_instances;

ALTER TABLE peer_instances
    ADD COLUMN api_key VARCHAR(255) NOT NULL DEFAULT gen_random_uuid()::text,
    ADD COLUMN is_local BOOLEAN NOT NULL DEFAULT false;

-- Rename constraints and indexes
ALTER TABLE peer_instances RENAME CONSTRAINT edge_nodes_pkey TO peer_instances_pkey;
ALTER TABLE peer_instances RENAME CONSTRAINT edge_nodes_name_key TO peer_instances_name_key;
ALTER INDEX idx_edge_nodes_status RENAME TO idx_peer_instances_status;
ALTER INDEX idx_edge_nodes_region RENAME TO idx_peer_instances_region;

-- 4. Rename edge_repo_assignments to peer_repo_subscriptions
ALTER TABLE edge_repo_assignments RENAME TO peer_repo_subscriptions;
ALTER TABLE peer_repo_subscriptions RENAME COLUMN edge_node_id TO peer_instance_id;

-- Rename constraints and indexes for peer_repo_subscriptions
DO $$ BEGIN
    ALTER TABLE peer_repo_subscriptions RENAME CONSTRAINT edge_repo_assignments_pkey TO peer_repo_subscriptions_pkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_repo_subscriptions RENAME CONSTRAINT edge_repo_assignments_edge_node_id_fkey TO peer_repo_subscriptions_peer_instance_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_repo_subscriptions RENAME CONSTRAINT edge_repo_assignments_repository_id_fkey TO peer_repo_subscriptions_repository_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_repo_subscriptions RENAME CONSTRAINT edge_repo_assignments_edge_node_id_repository_id_key TO peer_repo_subscriptions_peer_instance_id_repository_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER INDEX IF EXISTS idx_edge_repo_assignments_edge RENAME TO idx_peer_repo_subscriptions_peer;
ALTER INDEX IF EXISTS idx_edge_repo_assignments_repo RENAME TO idx_peer_repo_subscriptions_repo;
ALTER INDEX IF EXISTS idx_edge_repo_assignments_schedule RENAME TO idx_peer_repo_subscriptions_schedule;

-- 5. Create replication_mode enum and migrate from priority_override
DO $$ BEGIN
    CREATE TYPE replication_mode AS ENUM ('push', 'pull', 'mirror', 'none');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE peer_repo_subscriptions
    ADD COLUMN replication_mode replication_mode NOT NULL DEFAULT 'pull';

-- Migrate data from priority_override to replication_mode
UPDATE peer_repo_subscriptions SET replication_mode = CASE
    WHEN priority_override = 'immediate' THEN 'push'::replication_mode
    WHEN priority_override = 'on_demand' THEN 'pull'::replication_mode
    WHEN priority_override = 'local_only' THEN 'none'::replication_mode
    ELSE 'pull'::replication_mode
END
WHERE priority_override IS NOT NULL;

-- Drop the old priority_override column
ALTER TABLE peer_repo_subscriptions DROP COLUMN IF EXISTS priority_override;

-- 6. Update sync_tasks: rename edge_node_id to peer_instance_id, update FK
ALTER TABLE sync_tasks RENAME COLUMN edge_node_id TO peer_instance_id;

DO $$ BEGIN
    ALTER TABLE sync_tasks DROP CONSTRAINT IF EXISTS sync_tasks_edge_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE sync_tasks
        ADD CONSTRAINT sync_tasks_peer_instance_id_fkey
        FOREIGN KEY (peer_instance_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE sync_tasks RENAME CONSTRAINT sync_tasks_edge_node_id_artifact_id_key TO sync_tasks_peer_instance_id_artifact_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER INDEX IF EXISTS idx_sync_tasks_edge_status RENAME TO idx_sync_tasks_peer_status;

-- 7. Rename edge_cache_entries to peer_cache_entries
ALTER TABLE edge_cache_entries RENAME TO peer_cache_entries;
ALTER TABLE peer_cache_entries RENAME COLUMN edge_node_id TO peer_instance_id;

DO $$ BEGIN
    ALTER TABLE peer_cache_entries DROP CONSTRAINT IF EXISTS edge_cache_entries_edge_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_cache_entries
        ADD CONSTRAINT peer_cache_entries_peer_instance_id_fkey
        FOREIGN KEY (peer_instance_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_cache_entries RENAME CONSTRAINT edge_cache_entries_pkey TO peer_cache_entries_pkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_cache_entries RENAME CONSTRAINT edge_cache_entries_edge_node_id_artifact_id_key TO peer_cache_entries_peer_instance_id_artifact_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER INDEX IF EXISTS idx_edge_cache_entries_edge RENAME TO idx_peer_cache_entries_peer;
ALTER INDEX IF EXISTS idx_edge_cache_entries_lru RENAME TO idx_peer_cache_entries_lru;

-- 8. Update transfer_sessions: rename requesting_node_id to requesting_peer_id
ALTER TABLE transfer_sessions RENAME COLUMN requesting_node_id TO requesting_peer_id;

DO $$ BEGIN
    ALTER TABLE transfer_sessions DROP CONSTRAINT IF EXISTS transfer_sessions_requesting_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE transfer_sessions
        ADD CONSTRAINT transfer_sessions_requesting_peer_id_fkey
        FOREIGN KEY (requesting_peer_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE transfer_sessions RENAME CONSTRAINT transfer_sessions_artifact_id_requesting_node_id_key TO transfer_sessions_artifact_id_requesting_peer_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER INDEX IF EXISTS idx_transfer_sessions_requesting RENAME TO idx_transfer_sessions_requesting_peer;

-- 9. Update transfer_chunks: rename source_node_id to source_peer_id
ALTER TABLE transfer_chunks RENAME COLUMN source_node_id TO source_peer_id;

DO $$ BEGIN
    ALTER TABLE transfer_chunks DROP CONSTRAINT IF EXISTS transfer_chunks_source_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE transfer_chunks
        ADD CONSTRAINT transfer_chunks_source_peer_id_fkey
        FOREIGN KEY (source_peer_id) REFERENCES peer_instances(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 10. Update chunk_availability: rename edge_node_id to peer_instance_id
ALTER TABLE chunk_availability RENAME COLUMN edge_node_id TO peer_instance_id;

DO $$ BEGIN
    ALTER TABLE chunk_availability DROP CONSTRAINT IF EXISTS chunk_availability_edge_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE chunk_availability
        ADD CONSTRAINT chunk_availability_peer_instance_id_fkey
        FOREIGN KEY (peer_instance_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE chunk_availability RENAME CONSTRAINT chunk_availability_edge_node_id_artifact_id_key TO chunk_availability_peer_instance_id_artifact_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER INDEX IF EXISTS idx_chunk_availability_node RENAME TO idx_chunk_availability_peer;

-- 11. Update peer_connections: rename source_node_id and target_node_id
ALTER TABLE peer_connections RENAME COLUMN source_node_id TO source_peer_id;
ALTER TABLE peer_connections RENAME COLUMN target_node_id TO target_peer_id;

-- Drop old constraints and recreate with new column names
DO $$ BEGIN
    ALTER TABLE peer_connections DROP CONSTRAINT IF EXISTS peer_connections_source_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections DROP CONSTRAINT IF EXISTS peer_connections_target_node_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections
        ADD CONSTRAINT peer_connections_source_peer_id_fkey
        FOREIGN KEY (source_peer_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections
        ADD CONSTRAINT peer_connections_target_peer_id_fkey
        FOREIGN KEY (target_peer_id) REFERENCES peer_instances(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Drop old unique constraint and check, recreate with new names
DO $$ BEGIN
    ALTER TABLE peer_connections DROP CONSTRAINT IF EXISTS peer_connections_source_node_id_target_node_id_key;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections DROP CONSTRAINT IF EXISTS peer_connections_check;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections
        ADD CONSTRAINT peer_connections_source_peer_id_target_peer_id_key
        UNIQUE (source_peer_id, target_peer_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE peer_connections
        ADD CONSTRAINT peer_connections_no_self_link
        CHECK (source_peer_id != target_peer_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Rename peer_connections indexes
ALTER INDEX IF EXISTS idx_peer_connections_source RENAME TO idx_peer_connections_source_peer;
ALTER INDEX IF EXISTS idx_peer_connections_target RENAME TO idx_peer_connections_target_peer;

-- Recreate quality index with new column names
DROP INDEX IF EXISTS idx_peer_connections_quality;
CREATE INDEX IF NOT EXISTS idx_peer_connections_quality
    ON peer_connections (source_peer_id, latency_ms, bandwidth_estimate_bps DESC)
    WHERE status = 'active';
