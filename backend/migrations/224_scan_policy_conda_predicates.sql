-- #4058: conda-specific policy predicates on scan_policies.
--
-- The existing policy model is one row per policy with fixed columns
-- (max_severity, block_unscanned, block_on_fail, ...). Conda facts do not fit
-- that shape: there are five of them, they are list/enum-valued, and more will
-- arrive as the #4033 facts epic lands, so one column per predicate would
-- repeat migration 055's ALTER-per-knob pattern for every fact. A single JSONB
-- document keeps the predicate set extensible without further DDL.
--
-- Shape (all keys optional; an absent key means the predicate is not
-- enforced):
--
--   {
--     "conda": {
--       "allowed_channels": ["my-channel"],
--       "denied_channels": ["conda-forg"],
--       "denied_licenses": ["gpl-3.0"],
--       "denied_license_families": ["gpl"],
--       "block_install_scripts": true,
--       "max_install_script_severity": "high",
--       "min_attestation_state": "verified"
--     }
--   }
--
-- The lists are EMPTY by default and the booleans/toggles are unset, so every
-- existing policy row reads back as "no conda predicates" and evaluation is
-- byte-for-byte unchanged. Values are the organisation's own allow/deny
-- lists -- nothing is seeded here; the product ships the mechanism, not a
-- policy (#4058 scope boundary).
--
-- CONCURRENTLY N/A: ADD COLUMN with a constant, non-volatile default is a
-- catalog-only change on modern Postgres (no table rewrite, no long lock).

ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS predicates JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN scan_policies.predicates IS
    'Format-specific policy predicates (#4058). Empty object = no predicates. '
    'The "conda" object gates on conda facts: channel of origin, license / '
    'license_family, install-script presence and finding severity, and '
    'attestation state (absent / present-unverified / verified).';
