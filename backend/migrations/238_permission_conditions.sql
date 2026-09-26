-- Request-IP conditions on permission rules (#1849).
--
-- A rule may carry an optional `conditions` object; today the only key is
-- `allowed_cidrs` (an array of CIDR strings). Evaluation happens at the
-- canonical permission choke-points: a rule whose `allowed_cidrs` does not
-- contain the request's client IP is not applicable, which is also the
-- answer for an unknown IP (fail closed). Rules without the key (or without
-- conditions at all, the default for every existing row) apply exactly as
-- before. The shape is a JSONB object so future condition kinds (artifact,
-- version, ...) can be added without another column.
ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS conditions JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE permissions
    ADD CONSTRAINT permissions_conditions_is_object
    CHECK (jsonb_typeof(conditions) = 'object');
