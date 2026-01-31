-- Replication priority policies for repositories and edge assignments
-- Part of Borg Replication: Mesh Edge Sync

-- Priority tiers for replication:
--   P0 = immediate: replicated to all assigned edges on upload
--   P1 = scheduled: replicated on configurable cron schedule
--   P2 = on_demand: replicated only when first requested by an edge
--   P3 = local_only: never replicated, central-only

DO $$ BEGIN
    CREATE TYPE replication_priority AS ENUM ('immediate', 'scheduled', 'on_demand', 'local_only');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Add replication_priority to repositories (global default)
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS replication_priority replication_priority NOT NULL DEFAULT 'on_demand';

-- Extend edge_repo_assignments with per-edge priority override and schedule
ALTER TABLE edge_repo_assignments
    ADD COLUMN IF NOT EXISTS priority_override replication_priority,
    ADD COLUMN IF NOT EXISTS replication_schedule VARCHAR(100),
    ADD COLUMN IF NOT EXISTS last_replicated_at TIMESTAMP WITH TIME ZONE;

-- Index for querying repos by replication priority (used by sync scheduler)
CREATE INDEX IF NOT EXISTS idx_repositories_replication_priority ON repositories (replication_priority)
    WHERE replication_priority != 'local_only';

-- Index for finding assignments due for scheduled replication
CREATE INDEX IF NOT EXISTS idx_edge_repo_assignments_schedule
    ON edge_repo_assignments (edge_node_id, last_replicated_at)
    WHERE replication_schedule IS NOT NULL;
