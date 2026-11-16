-- Add unhealthy state for peer instances stuck failing probes/transfers (#6030).
ALTER TYPE instance_status ADD VALUE IF NOT EXISTS 'unhealthy';
