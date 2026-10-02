-- #3645: admit `record_only` as a scan_configs.proxy_scan_action.
--
-- Record-only scans proxied bytes and records the verdict, findings and SBOM
-- data exactly as fail-open does, but never withholds a pull: a vulnerable
-- verdict is served with `X-AK-Scan: recorded`, and an over-cap or
-- inconclusive scan serves pending. It gives operators proxy vulnerability
-- visibility without arming the blocking gate.
--
-- Widens the inline CHECK migration 181 created (Postgres named it
-- `scan_configs_proxy_scan_action_check`). Online shape, as in 220: the DROP
-- and the NOT VALID ADD are catalog-only, and VALIDATE takes only SHARE
-- UPDATE EXCLUSIVE. Widening a CHECK cannot fail against rows that satisfy
-- the narrower predicate. Existing rows keep their value; the column default
-- stays `fail_open`.
ALTER TABLE scan_configs DROP CONSTRAINT IF EXISTS scan_configs_proxy_scan_action_check;
ALTER TABLE scan_configs ADD CONSTRAINT scan_configs_proxy_scan_action_check
    CHECK (proxy_scan_action IN ('fail_open', 'fail_closed', 'record_only'))
    NOT VALID;
ALTER TABLE scan_configs VALIDATE CONSTRAINT scan_configs_proxy_scan_action_check;
