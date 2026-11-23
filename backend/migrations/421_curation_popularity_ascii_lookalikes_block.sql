-- #5840: keep the 1.12 behaviour of existing `popularity` rules on upgrade.
--
-- 1.13.0 adds the `popularity` config key `ascii_lookalikes` ("block" or
-- "flag"). It decides whether a Remote or Virtual download is refused when the
-- name is all ASCII and its confusable skeleton matches a popular name (`c1ick`
-- for `click`, `paypa1` for `paypal`). New rules default to "flag". Through
-- 1.12 a `block_typosquat: true` rule refused those names, so this stamps
-- "block" on every existing rule with `block_typosquat: true` that has no
-- `ascii_lookalikes` yet. The upgrade then changes no download. Lookalikes that
-- contain a non-ASCII character are refused either way.
--
-- Data only: no DDL. It is one UPDATE that takes row locks on the few typed
-- rules it touches, and it is idempotent (a stamped rule no longer matches).
-- A replica on the previous release ignores the key. `updated_at` is left as
-- it is: this is not an operator edit.
SET LOCAL lock_timeout = '5s';

UPDATE curation_rules
SET config = config || '{"ascii_lookalikes": "block"}'::jsonb
WHERE rule_type = 'popularity'
  AND jsonb_typeof(config) = 'object'
  AND config -> 'block_typosquat' = 'true'::jsonb
  AND NOT (config ? 'ascii_lookalikes');
