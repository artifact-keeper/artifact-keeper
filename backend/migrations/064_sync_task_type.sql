-- Add task_type to sync_tasks for deletion support.
-- 'push' (default) = push artifact to peer, 'delete' = tell peer to delete artifact.
-- Widen the unique constraint to include task_type so push and delete tasks
-- for the same artifact+peer can coexist in the queue.

ALTER TABLE sync_tasks ADD COLUMN task_type VARCHAR(10) NOT NULL DEFAULT 'push';

ALTER TABLE sync_tasks DROP CONSTRAINT sync_tasks_peer_instance_id_artifact_id_key;
ALTER TABLE sync_tasks ADD CONSTRAINT sync_tasks_peer_artifact_type_key
    UNIQUE (peer_instance_id, artifact_id, task_type);
