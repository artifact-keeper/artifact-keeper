-- #2414: audit events must preserve the request correlation ID established
-- by the correlation middleware. Request correlation IDs are strings — a
-- caller-supplied X-Correlation-ID header value, a W3C traceparent trace-id,
-- or a generated UUID — so the UUID column type cannot store them. Existing
-- rows keep their UUID value, re-encoded as text; idx_audit_log_correlation
-- (B-tree) is rebuilt automatically by the type change.
ALTER TABLE audit_log
    ALTER COLUMN correlation_id TYPE TEXT
    USING correlation_id::text;

-- Defense-in-depth for the application-level 256-byte cap the correlation
-- middleware enforces (the header is caller-controlled and unauthenticated;
-- audited public paths persist it per event, so an unbounded value would let
-- an attacker write hundreds of KB per request). The cap also keeps every
-- value well under the B-tree index entry limit, so an oversized value can
-- never fail the audit INSERT itself (fire-and-forget emitters swallow write
-- failures — an insert-breaking value would be a caller-controlled audit
-- bypass). 36-char UUIDs already stored as text pass trivially.
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_correlation_id_len
    CHECK (octet_length(correlation_id) <= 256);
