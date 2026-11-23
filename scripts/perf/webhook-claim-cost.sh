#!/usr/bin/env bash
# =============================================================================
# scripts/perf/webhook-claim-cost.sh - what one webhook delivery claim costs
# the database, before and after #5195
# =============================================================================
# Starts a throwaway Postgres, applies backend/migrations with sqlx-cli, and
# seeds `webhook_deliveries` the way a long-running instance looks:
#   * HOOKS webhooks; one of them is a dead endpoint with DEAD_PENDING due
#     rows (an outage backlog), every other one has one due row;
#   * HISTORY delivered or dead-lettered rows spread over all webhooks.
# Then it runs, each inside a transaction that is rolled back, EXPLAIN
# (ANALYZE, BUFFERS) of:
#   old  - the pre-#5195 claim (rank every due row per webhook, take 50),
#          without the migration 417 index, as on main;
#   new  - the #5195 claim as the backend runs it: pick up to 8 webhooks and
#          take their advisory claim locks, then claim each one's oldest due
#          rows (at most 10) from idx_webhook_deliveries_pending_by_webhook,
#          locked by primary key; times are summed over both statements;
#   new-noidx - the #5195 claim with that index dropped (what it would cost
#          without migration 417).
# and prints execution time, shared buffers touched and rows claimed for each.
#
# Usage: scripts/perf/webhook-claim-cost.sh [HOOKS] [DEAD_PENDING] [HISTORY]
# Env:   PG_PORT=55496  RUNS=5 (best-of)  KEEP=1 (leave Postgres up)
# Needs docker and sqlx-cli; run from the repository root.
# =============================================================================
set -euo pipefail

HOOKS="${1:-50}"
DEAD_PENDING="${2:-50000}"
HISTORY="${3:-1000000}"
PG_PORT="${PG_PORT:-55496}"
RUNS="${RUNS:-5}"
CTR="perf-webhook-claim-$$"

cleanup(){ [ "${KEEP:-0}" = 1 ] || docker rm -f "$CTR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$CTR" -p "127.0.0.1:${PG_PORT}:5432" \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry \
  postgres:18-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$CTR" pg_isready -U registry -d artifact_registry >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
export DATABASE_URL="postgresql://registry:registry@127.0.0.1:${PG_PORT}/artifact_registry"
sqlx migrate run --source backend/migrations >/dev/null

psql_(){ docker exec -i "$CTR" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -qAt "$@"; }

psql_ <<SQL
INSERT INTO webhooks (id, name, url, events, is_enabled)
SELECT gen_random_uuid(), 'perf-' || g, 'http://198.51.100.7/' || g, ARRAY['artifact_uploaded'], true
FROM generate_series(1, ${HOOKS}) g;
CREATE TEMP TABLE h AS SELECT id, row_number() OVER (ORDER BY name) AS n FROM webhooks;
-- history: delivered (most) and dead-lettered rows
INSERT INTO webhook_deliveries (webhook_id, event, payload, success, attempts, max_attempts,
                                next_retry_at, created_at, delivered_at)
SELECT (SELECT id FROM h WHERE n = 1 + (g % ${HOOKS})), 'artifact_uploaded', '{}'::jsonb,
       (g % 10 <> 0), 1, 12, NULL, NOW() - make_interval(secs => g), NOW() - make_interval(secs => g)
FROM generate_series(1, ${HISTORY}) g;
-- the dead endpoint's outage backlog
INSERT INTO webhook_deliveries (webhook_id, event, payload, success, attempts, max_attempts, next_retry_at)
SELECT (SELECT id FROM h WHERE n = 1), 'artifact_uploaded', '{}'::jsonb, false, 1, 12,
       NOW() - make_interval(secs => 3600 + g)
FROM generate_series(1, ${DEAD_PENDING}) g;
-- one fresh due row for every other webhook
INSERT INTO webhook_deliveries (webhook_id, event, payload, success, attempts, max_attempts, next_retry_at)
SELECT id, 'artifact_uploaded', '{}'::jsonb, false, 0, 12, NOW() - INTERVAL '1 second' FROM h WHERE n > 1;
SQL
psql_ -c "VACUUM ANALYZE webhook_deliveries" -c "VACUUM ANALYZE webhooks"

OLD_CLAIM="$(cat <<'SQL'
WITH ranked AS (
    SELECT id, attempts, next_retry_at,
           ROW_NUMBER() OVER (PARTITION BY webhook_id ORDER BY next_retry_at ASC, id ASC) AS webhook_rank
    FROM webhook_deliveries
    WHERE success = false AND next_retry_at IS NOT NULL AND next_retry_at <= NOW()
      AND attempts < max_attempts
      AND (claim_expires_at IS NULL OR claim_expires_at <= NOW())
),
fair AS (
    SELECT id FROM ranked
    ORDER BY webhook_rank ASC, (attempts = 0) DESC, next_retry_at ASC, id ASC
    LIMIT 50
),
candidate AS (
    SELECT id FROM webhook_deliveries
    WHERE id IN (SELECT id FROM fair)
      AND success = false AND next_retry_at IS NOT NULL AND next_retry_at <= NOW()
      AND attempts < max_attempts
      AND (claim_expires_at IS NULL OR claim_expires_at <= NOW())
    FOR UPDATE SKIP LOCKED
)
UPDATE webhook_deliveries d
SET claimed_by = 'perf', claim_token = gen_random_uuid(), claim_expires_at = NOW() + INTERVAL '120 seconds'
FROM candidate WHERE d.id = candidate.id
RETURNING d.id
SQL
)"

# The #5195 claim, as the backend runs it (two statements in one transaction;
# generated from WEBHOOK_CLAIM_LANES_SQL and WEBHOOK_CLAIM_ROWS_SQL in
# backend/src/api/handlers/webhooks.rs with 8 free lanes).
NEW_LANES="$(cat <<'SQL'
WITH hooks AS (
    SELECT w.id, w.delivery_failures > 0 AS failing
    FROM webhooks w
    WHERE (w.delivery_backoff_until IS NULL OR w.delivery_backoff_until <= NOW())
      AND (NULL::uuid[] IS NULL OR w.id = ANY(NULL::uuid[]))
),
heads AS (
    SELECT h.id AS webhook_id, h.failing, r.id, r.next_retry_at
    FROM hooks h
    CROSS JOIN LATERAL (
        SELECT d.id, d.next_retry_at
        FROM webhook_deliveries d
        WHERE d.webhook_id = h.id
          AND d.success = false
          AND d.attempts < d.max_attempts
          AND d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
        ORDER BY d.next_retry_at ASC, d.id ASC
        LIMIT 10
    ) r
),
eligible AS (
    SELECT heads.webhook_id,
           bool_or(heads.failing) AS failing,
           MIN(heads.next_retry_at) AS oldest
    FROM heads
    JOIN webhook_deliveries d ON d.id = heads.id
    GROUP BY heads.webhook_id
    HAVING NOT bool_or(d.claim_expires_at IS NOT NULL AND d.claim_expires_at > NOW())
),
picked AS MATERIALIZED (
    SELECT webhook_id
    FROM (
        SELECT webhook_id, failing, oldest,
               ROW_NUMBER() OVER (PARTITION BY failing ORDER BY oldest, webhook_id) AS nth
        FROM eligible
    ) e
    WHERE NOT failing OR nth <= 6
    ORDER BY oldest ASC, webhook_id ASC
    LIMIT 8
)
SELECT webhook_id
FROM picked
WHERE pg_try_advisory_xact_lock(5195, hashtext(webhook_id::text))
SQL
)"
NEW_ROWS="$(cat <<'SQL'
WITH heads AS (
    SELECT w.id AS webhook_id, r.id, r.next_retry_at
    FROM webhooks w
    CROSS JOIN LATERAL (
        SELECT d.id, d.next_retry_at
        FROM webhook_deliveries d
        WHERE d.webhook_id = w.id
          AND d.success = false
          AND d.attempts < d.max_attempts
          AND d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
        ORDER BY d.next_retry_at ASC, d.id ASC
        LIMIT 10
    ) r
    WHERE w.id = ANY(ARRAY(SELECT webhook_id FROM picked_perf))
      AND (w.delivery_backoff_until IS NULL OR w.delivery_backoff_until <= NOW())
),
lanes AS (
    SELECT heads.webhook_id
    FROM heads
    JOIN webhook_deliveries d ON d.id = heads.id
    GROUP BY heads.webhook_id
    HAVING NOT bool_or(d.claim_expires_at IS NOT NULL AND d.claim_expires_at > NOW())
),
candidate AS (
    SELECT l.id
    FROM (SELECT heads.id FROM heads JOIN lanes USING (webhook_id)) p
    CROSS JOIN LATERAL (
        SELECT d.id
        FROM webhook_deliveries d
        WHERE d.id = p.id
          AND d.success = false
          AND d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
          AND d.attempts < d.max_attempts
          AND (d.claim_expires_at IS NULL OR d.claim_expires_at <= NOW())
        FOR UPDATE SKIP LOCKED
    ) l
),
claimed AS (
    UPDATE webhook_deliveries d
    SET claimed_by = 'perf',
        claim_token = gen_random_uuid(),
        claim_expires_at = NOW() + make_interval(secs => 120)
    FROM candidate
    WHERE d.id = candidate.id
    RETURNING d.id, d.webhook_id, d.event, d.payload, d.attempts, d.max_attempts,
              d.claim_token, d.claimed_by, d.claim_expires_at, d.next_retry_at
)
SELECT id, webhook_id, event, payload, attempts, max_attempts,
       claim_token, claimed_by, claim_expires_at
FROM claimed
ORDER BY next_retry_at ASC, id ASC
SQL
)"

# measure <label> <prelude> <claim> [<second statement>]: best-of-RUNS
# execution time and buffers, summed over the statements. With a second
# statement, the first one's rows are kept in picked_perf for it.
measure(){
  local label="$1" prelude="$2" claim="$3" second="${4:-}" best="" bufs="" rows="" out t b r body
  if [ -n "$second" ]; then
    body="EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${claim};
CREATE TEMP TABLE picked_perf ON COMMIT DROP AS ${claim};
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${second};"
  else
    body="EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${claim};"
  fi
  for _ in $(seq 1 "$RUNS"); do
    out="$(psql_ <<SQL
BEGIN;
${prelude}
${body}
ROLLBACK;
SQL
)"
    read -r t b r < <(python3 - "$out" <<'PY'
import json, re, sys
plans = []
dec = json.JSONDecoder()
text = sys.argv[1]
i = 0
while True:
    j = text.find('[', i)
    if j < 0:
        break
    try:
        obj, end = dec.raw_decode(text, j)
    except ValueError:
        i = j + 1
        continue
    if isinstance(obj, list) and obj and isinstance(obj[0], dict) and "Plan" in obj[0]:
        plans.append(obj[0])
    i = end
ms = sum(p["Execution Time"] for p in plans)
bufs = sum(p["Plan"].get("Shared Hit Blocks", 0) + p["Plan"].get("Shared Read Blocks", 0) for p in plans)
print(f"{ms:.2f}", bufs, plans[-1]["Plan"].get("Actual Rows", 0))
PY
)
    if [ -z "$best" ] || python3 -c "import sys; sys.exit(0 if float('$t') < float('$best') else 1)"; then
      best="$t"; bufs="$b"; rows="$r"
    fi
  done
  printf '%-10s exec_ms=%-9s shared_buffers=%-8s rows_claimed=%s\n' "$label" "$best" "$bufs" "$rows"
}

echo "hooks=${HOOKS} dead_pending=${DEAD_PENDING} history=${HISTORY} (best of ${RUNS})"
measure old "DROP INDEX idx_webhook_deliveries_pending_by_webhook;" "$OLD_CLAIM"
measure new "" "$NEW_LANES" "$NEW_ROWS"
measure new-noidx "DROP INDEX idx_webhook_deliveries_pending_by_webhook;" "$NEW_LANES" "$NEW_ROWS"
