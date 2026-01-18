#!/bin/bash
# Stress test: Concurrent upload operations
# Tests the backend's ability to handle 100 concurrent artifact uploads
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
CONCURRENT_UPLOADS="${CONCURRENT_UPLOADS:-100}"
PACKAGE_SIZE="${PACKAGE_SIZE:-small}"  # small, medium, large
TEST_FORMAT="${TEST_FORMAT:-pypi}"  # pypi, npm, cargo, maven, go
RESULTS_DIR="${RESULTS_DIR:-/tmp/stress-results}"

echo "=============================================="
echo "Stress Test: Concurrent Uploads"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Concurrent uploads: $CONCURRENT_UPLOADS"
echo "Package size: $PACKAGE_SIZE"
echo "Test format: $TEST_FORMAT"
echo "Results dir: $RESULTS_DIR"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/*.log "$RESULTS_DIR"/*.json 2>/dev/null || true

# Generate test packages
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating $CONCURRENT_UPLOADS test packages..."

generate_package() {
    local idx=$1
    local pkg_dir="$WORK_DIR/pkg-$idx"
    mkdir -p "$pkg_dir"

    # Create package content based on size
    case "$PACKAGE_SIZE" in
        small)
            dd if=/dev/urandom of="$pkg_dir/data.bin" bs=1K count=100 2>/dev/null
            ;;
        medium)
            dd if=/dev/urandom of="$pkg_dir/data.bin" bs=1M count=10 2>/dev/null
            ;;
        large)
            dd if=/dev/urandom of="$pkg_dir/data.bin" bs=1M count=100 2>/dev/null
            ;;
    esac

    # Create checksum
    sha256sum "$pkg_dir/data.bin" | cut -d' ' -f1 > "$pkg_dir/checksum.txt"

    # Create package metadata based on format
    case "$TEST_FORMAT" in
        pypi)
            cat > "$pkg_dir/pyproject.toml" << EOF
[project]
name = "stress-test-pkg-$idx"
version = "1.0.$idx"
description = "Stress test package $idx"
EOF
            tar -czf "$pkg_dir/stress-test-pkg-$idx-1.0.$idx.tar.gz" -C "$pkg_dir" data.bin pyproject.toml
            ;;
        npm)
            cat > "$pkg_dir/package.json" << EOF
{
  "name": "@stress-test/pkg-$idx",
  "version": "1.0.$idx",
  "description": "Stress test package $idx"
}
EOF
            tar -czf "$pkg_dir/stress-test-pkg-$idx-1.0.$idx.tgz" -C "$pkg_dir" data.bin package.json
            ;;
        cargo)
            mkdir -p "$pkg_dir/src"
            echo "// stress test" > "$pkg_dir/src/lib.rs"
            cat > "$pkg_dir/Cargo.toml" << EOF
[package]
name = "stress-test-pkg-$idx"
version = "1.0.$idx"
edition = "2021"
EOF
            tar -czf "$pkg_dir/stress-test-pkg-$idx-1.0.$idx.crate" -C "$pkg_dir" data.bin Cargo.toml src
            ;;
        *)
            tar -czf "$pkg_dir/stress-test-pkg-$idx-1.0.$idx.tar.gz" -C "$pkg_dir" data.bin
            ;;
    esac

    echo "$pkg_dir"
}

# Generate packages in parallel (batches of 10)
for i in $(seq 1 $CONCURRENT_UPLOADS); do
    generate_package $i &
    if (( i % 10 == 0 )); then
        wait
        echo "  Generated $i packages..."
    fi
done
wait
echo "  Generated all $CONCURRENT_UPLOADS packages"

# Upload function
upload_package() {
    local idx=$1
    local pkg_dir="$WORK_DIR/pkg-$idx"
    local start_time end_time duration status_code

    start_time=$(date +%s.%N)

    # Find the package file
    local pkg_file
    pkg_file=$(find "$pkg_dir" -name "*.tar.gz" -o -name "*.tgz" -o -name "*.crate" 2>/dev/null | head -1)

    if [ -z "$pkg_file" ]; then
        echo "ERROR: No package file found in $pkg_dir" >> "$RESULTS_DIR/upload-$idx.log"
        echo "$idx,error,0,no_package_file" >> "$RESULTS_DIR/results.csv"
        return 1
    fi

    # Upload the package
    status_code=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/upload-$idx.log" \
        -X PUT \
        -u admin:admin123 \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$pkg_file" \
        "$REGISTRY_URL/api/v1/repositories/stress-test-$TEST_FORMAT/artifacts/$(basename $pkg_file)" \
        2>&1 || echo "000")

    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)

    echo "$idx,$status_code,$duration,$(cat "$pkg_dir/checksum.txt")" >> "$RESULTS_DIR/results.csv"

    if [ "$status_code" -ge 200 ] && [ "$status_code" -lt 300 ]; then
        return 0
    else
        return 1
    fi
}

echo ""
echo "==> Starting $CONCURRENT_UPLOADS concurrent uploads..."
echo "idx,status_code,duration_sec,checksum" > "$RESULTS_DIR/results.csv"

START_TIME=$(date +%s.%N)

# Run uploads concurrently (in batches based on system limits)
BATCH_SIZE="${BATCH_SIZE:-20}"
for batch_start in $(seq 1 $BATCH_SIZE $CONCURRENT_UPLOADS); do
    batch_end=$((batch_start + BATCH_SIZE - 1))
    if [ $batch_end -gt $CONCURRENT_UPLOADS ]; then
        batch_end=$CONCURRENT_UPLOADS
    fi

    for i in $(seq $batch_start $batch_end); do
        upload_package $i &
    done
    wait
    echo "  Completed uploads $batch_start-$batch_end"
done

END_TIME=$(date +%s.%N)
TOTAL_DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==> Upload phase complete"
echo ""

# Calculate statistics
SUCCESS_COUNT=$(grep -c ",20[0-9]," "$RESULTS_DIR/results.csv" || echo "0")
FAIL_COUNT=$(grep -c -v ",20[0-9]," "$RESULTS_DIR/results.csv" | tail -1 || echo "0")
# Subtract header line
FAIL_COUNT=$((FAIL_COUNT - 1))
if [ $FAIL_COUNT -lt 0 ]; then FAIL_COUNT=0; fi

AVG_DURATION=$(awk -F',' 'NR>1 {sum+=$3; count++} END {if(count>0) printf "%.3f", sum/count; else print "0"}' "$RESULTS_DIR/results.csv")
MAX_DURATION=$(awk -F',' 'NR>1 {if($3>max) max=$3} END {printf "%.3f", max}' "$RESULTS_DIR/results.csv")
MIN_DURATION=$(awk -F',' 'NR>1 {if(min=="" || $3<min) min=$3} END {printf "%.3f", min}' "$RESULTS_DIR/results.csv")

# Write summary
cat > "$RESULTS_DIR/summary.json" << EOF
{
  "test": "concurrent_uploads",
  "timestamp": "$(date -Iseconds)",
  "config": {
    "registry_url": "$REGISTRY_URL",
    "concurrent_uploads": $CONCURRENT_UPLOADS,
    "package_size": "$PACKAGE_SIZE",
    "test_format": "$TEST_FORMAT",
    "batch_size": $BATCH_SIZE
  },
  "results": {
    "total": $CONCURRENT_UPLOADS,
    "success": $SUCCESS_COUNT,
    "failed": $FAIL_COUNT,
    "success_rate": $(echo "scale=2; $SUCCESS_COUNT * 100 / $CONCURRENT_UPLOADS" | bc),
    "total_duration_sec": $TOTAL_DURATION,
    "avg_upload_sec": $AVG_DURATION,
    "min_upload_sec": $MIN_DURATION,
    "max_upload_sec": $MAX_DURATION,
    "throughput_uploads_per_sec": $(echo "scale=2; $CONCURRENT_UPLOADS / $TOTAL_DURATION" | bc)
  }
}
EOF

echo "=============================================="
echo "Stress Test Results"
echo "=============================================="
echo ""
echo "Total uploads: $CONCURRENT_UPLOADS"
echo "Successful: $SUCCESS_COUNT"
echo "Failed: $FAIL_COUNT"
echo "Success rate: $(echo "scale=2; $SUCCESS_COUNT * 100 / $CONCURRENT_UPLOADS" | bc)%"
echo ""
echo "Total duration: ${TOTAL_DURATION}s"
echo "Average upload time: ${AVG_DURATION}s"
echo "Min upload time: ${MIN_DURATION}s"
echo "Max upload time: ${MAX_DURATION}s"
echo "Throughput: $(echo "scale=2; $CONCURRENT_UPLOADS / $TOTAL_DURATION" | bc) uploads/sec"
echo ""
echo "Results saved to: $RESULTS_DIR/summary.json"
echo "Detailed results: $RESULTS_DIR/results.csv"
echo ""

# Exit with error if success rate is below threshold
THRESHOLD="${SUCCESS_THRESHOLD:-95}"
SUCCESS_RATE=$(echo "scale=0; $SUCCESS_COUNT * 100 / $CONCURRENT_UPLOADS" | bc)
if [ "$SUCCESS_RATE" -lt "$THRESHOLD" ]; then
    echo "❌ FAILED: Success rate $SUCCESS_RATE% is below threshold $THRESHOLD%"
    exit 1
fi

echo "✅ Stress test PASSED"
