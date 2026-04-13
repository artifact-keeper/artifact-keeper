-- Notification subscriptions for repository-scoped and global event notifications.
-- Supports email and webhook delivery channels with configurable event type filters.
CREATE TABLE notification_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    channel VARCHAR(50) NOT NULL CHECK (channel IN ('email', 'webhook')),
    event_types TEXT[] NOT NULL DEFAULT '{}',
    config JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_subs_repo ON notification_subscriptions(repository_id) WHERE repository_id IS NOT NULL;
CREATE INDEX idx_notification_subs_enabled ON notification_subscriptions(enabled) WHERE enabled = true;
