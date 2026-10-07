#!/usr/bin/env bash
# Pure assertion helpers for the single-flight race harness (#1624).
#
# Factored out of run-singleflight-race.sh so the digest/counter/blob-count
# assertion logic can be unit-tested with a local stub (test_assert_lib.sh)
# WITHOUT standing up the full multi-container stack. Keep these functions
# side-effect-free apart from echoing PASS/FAIL/result tokens.

# sha256_of_file <path> -> prints the lowercase hex sha256, or empty on error.
sha256_of_file() {
    local f="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" 2>/dev/null | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1
    else
        echo ""
    fi
}

# LARGE profile threshold: objects bigger than the backend's in-process
# streaming fan-out window (FANOUT_CAPTURE_MAX_BYTES, 16 MiB) are not fanned
# out live; their followers wait for the leader and read the cache.
LARGE_OBJECT_BYTES=16777216

# default_fetch_tolerance <artifact_size_bytes> <replicas> -> prints a number
# A1's default allowance (#4013). The target stays "exactly one upstream fetch".
# For a LARGE object the cross-replica coordinator's waiters block on the
# leader for at most PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS and then fetch
# once per replica, so the documented floor is <= replicas fetches:
# tolerance = replicas - 1. A small object is fanned out in-process and must
# stay strictly at 1.
default_fetch_tolerance() {
    local size="${1:-0}" replicas="${2:-1}"
    if [ "$size" -gt "$LARGE_OBJECT_BYTES" ] && [ "$replicas" -gt 1 ]; then
        echo $((replicas - 1))
    else
        echo 0
    fi
}

# assert_fetch_counter_one <count> -> "PASS"/"FAIL <reason>"
# A1: exactly one upstream fetch (strict ==1 unless a documented passthrough
# tolerance is configured via FETCH_TOLERANCE).
assert_fetch_counter_one() {
    local count="$1"
    local tolerance="${FETCH_TOLERANCE:-0}"
    local max=$((1 + tolerance))
    if [ "$count" -lt 1 ]; then
        echo "FAIL upstream fetch counter is $count (<1): artifact was never fetched"
        return 1
    fi
    if [ "$count" -gt "$max" ]; then
        echo "FAIL upstream fetch counter is $count (>$max): cross-process single-flight failed (#1606); each replica fetched independently"
        return 1
    fi
    echo "PASS upstream fetch counter == $count (<= $max)"
    return 0
}

# fetch_count_warning <count> <storm_secs> <wait_timeout_secs> -> prints a WARN
# line, or nothing. A1 may PASS with more than one fetch under the LARGE
# tolerance (#4013), which would also hide a regression that adds one fetch
# per replica. Keep such a result visible: more than one fetch in a storm that
# ended before PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS cannot be the timeout
# floor and is almost certainly a coordination bug.
fetch_count_warning() {
    local count="$1" storm="$2" wait="$3"
    [ "$count" -gt 1 ] || return 0
    if [ "$storm" -lt "$wait" ]; then
        echo "WARN $count upstream fetches although the storm (${storm}s) ended before the lock wait timeout (${wait}s): not the per-replica floor, likely a single-flight regression"
    else
        echo "WARN $count upstream fetches: within tolerance; the storm (${storm}s) outlived the lock wait timeout (${wait}s), so the per-replica floor applies"
    fi
}

# assert_all_responses_ok <results_csv> <expected_sha256>
# A2: EVERY response is HTTP 200 and its sha256 == the published digest.
# CSV columns: idx,status,sha256,bytes
assert_all_responses_ok() {
    local csv="$1" expected="$2"
    local total=0 bad_status=0 bad_digest=0
    local idx status sha _bytes
    while IFS=',' read -r idx status sha _bytes; do
        [ "$idx" = "idx" ] && continue   # skip header
        [ -z "$idx" ] && continue
        total=$((total + 1))
        if [ "$status" != "200" ]; then
            bad_status=$((bad_status + 1))
            continue
        fi
        if [ "$sha" != "$expected" ]; then
            bad_digest=$((bad_digest + 1))
        fi
    done < "$csv"

    if [ "$total" -eq 0 ]; then
        echo "FAIL no responses recorded"
        return 1
    fi
    if [ "$bad_status" -gt 0 ] || [ "$bad_digest" -gt 0 ]; then
        echo "FAIL of $total responses: $bad_status non-200, $bad_digest digest-mismatch (truncated/torn bodies = #1606)"
        return 1
    fi
    echo "PASS all $total responses HTTP 200 with correct sha256"
    return 0
}

# assert_single_cached_blob <count> -> "PASS"/"FAIL"
# A3: exactly one cached blob object after the storm.
assert_single_cached_blob() {
    local count="$1"
    if [ "$count" = "1" ]; then
        echo "PASS exactly one cached blob in object store"
        return 0
    fi
    echo "FAIL expected exactly 1 cached blob, found $count"
    return 1
}
