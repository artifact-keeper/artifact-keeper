-- Add payload_template column to webhooks table.
-- Allows configuring platform-specific payload layouts (Slack, Teams, Discord, etc.).
ALTER TABLE webhooks ADD COLUMN payload_template VARCHAR(50) NOT NULL DEFAULT 'generic';
