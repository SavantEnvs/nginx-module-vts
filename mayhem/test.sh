#!/usr/bin/env bash
#
# mayhem/test.sh — functional oracle for nginx-module-vts. Starts the normal-flags nginx that
# mayhem/build.sh built (mayhem/build/normal/nginx), sends exact HTTP requests and asserts the exact
# counters / byte totals / control-API / prometheus output the module reports (mayhem/oracle.py).
# Prints one PASS/FAIL line per assertion and a CTRF summary; exit 0 iff every assertion passed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

NGINX="$SRC/mayhem/build/normal/nginx"
if [ ! -x "$NGINX" ]; then
  echo "missing $NGINX: mayhem/build.sh did not build it" >&2
  emit_ctrf "nginx-module-vts" 0 1
  exit 1
fi

out="$(python3 "$SRC/mayhem/oracle.py" "$NGINX" 2>&1)"
printf '%s\n' "$out" | grep -v '^CTRFCOUNTS'
counts="$(printf '%s\n' "$out" | sed -n 's/^CTRFCOUNTS //p' | tail -1)"
if [ -z "$counts" ]; then
  echo "oracle did not complete" >&2
  emit_ctrf "nginx-module-vts" 0 1
  exit 1
fi
set -- $counts
emit_ctrf "nginx-module-vts" "$1" "$2"
