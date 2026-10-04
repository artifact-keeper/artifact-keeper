#!/usr/bin/env bash
# Whole-repository jscpd scan (#1619). Run by scheduled-tests.yml's
# `duplication-report` job; also runnable locally with jscpd@4 on PATH.
#
#   bash scripts/ci/jscpd-repo-scan.sh [OUT_DIR]
#
# Measures every non-ignored Rust source under backend/src the way the per-PR
# "Code duplication gate" in ci.yml measures changed ones: same .jscpd.json
# ignore list and size limits (#3495), inline #[cfg(test)] modules stripped by
# jscpd-prepare-sources.py, --min-lines 10. Writes the jscpd JSON report and a
# Markdown summary under OUT_DIR (default: jscpd-repo-report), appends the
# summary to $GITHUB_STEP_SUMMARY when set, and exits with
# jscpd-repo-report.py's status: 0 ok, 1 regression past
# .github/duplication-baseline.json, 2 not a measurement.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="${1:-jscpd-repo-report}"
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac
REPORT_PY="scripts/ci/jscpd-repo-report.py"

rm -rf "$OUT"
mkdir -p "$OUT/src"

python3 "$REPORT_PY" list-sources .jscpd.json backend/src > "$OUT/sources.txt"
echo "Sources in scope: $(wc -l < "$OUT/sources.txt")"

# xargs, not "$(cat ...)": several hundred paths, and the preparer takes them
# all in one call so it writes a single line map.
xargs python3 scripts/ci/jscpd-prepare-sources.py "$OUT/src" "$OUT/linemap.json" \
  < "$OUT/sources.txt" > "$OUT/prepare.log"

read -r MAX_LINES MAX_SIZE <<<"$(python3 -c "
import json
cfg = json.load(open('.jscpd.json'))
print(cfg['maxLines'], cfg['maxSize'])
")"
echo "jscpd limits from .jscpd.json: max-lines=${MAX_LINES} max-size=${MAX_SIZE}"

# No --threshold: this is a report, the baseline comparison below decides.
# `cd` so the report names the real repo-relative paths.
( cd "$OUT/src" && xargs jscpd --min-lines 10 \
    --max-lines "$MAX_LINES" --max-size "$MAX_SIZE" --reporters json \
    --format rust --output "$OUT/jscpd" --silent \
    < "$OUT/sources.txt" ) || true

status=0
python3 "$REPORT_PY" summarize "$OUT/jscpd/jscpd-report.json" "$OUT/linemap.json" \
  "$OUT/sources.txt" .github/duplication-baseline.json \
  --prepared "$OUT/src" --top "${JSCPD_TOP:-15}" \
  --summary "$OUT/summary.md" || status=$?

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi
case "$status" in
  0) ;;
  1) echo "::error title=Duplication regression::whole-repo duplication is above .github/duplication-baseline.json (see the job summary)" ;;
  *) echo "::error title=Duplication scan::the scan did not measure the whole tree (see the job summary)" ;;
esac
exit "$status"
