#!/usr/bin/env bash
#
# mayhem/test.sh — runs the known-answer selftest that mayhem/build.sh built: committed PE/PE32+/TE/UEFI
# firmware images go through the real efiXloader code and the resulting segments, entry points,
# relocated bytes and extracted modules are compared with values derived independently in gen_seeds.py
# (mayhem/oracle/expected.txt). A binary that is missing, exits 0 without checking, or loads the images
# differently fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

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

BIN="$SRC/build/tests/selftest"
EXPECTED_TESTS=9
if [ ! -x "$BIN" ]; then
  echo "test.sh: $BIN missing — mayhem/build.sh should have produced it" >&2
  emit_ctrf "efixloader-selftest" 0 1 0
  exit 1
fi

out="$("$BIN" "$SRC/mayhem" 2>&1)"
rc=$?
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | grep -c '^PASS ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL ')
summary=$(printf '%s\n' "$out" | grep -c "^SELFTEST passed=$passed failed=$failed\$")

# rc != 0, a missing summary line, or fewer tests than expected all count as failures
if [ "$rc" -ne 0 ] || [ "$summary" -ne 1 ] || [ "$passed" -lt "$EXPECTED_TESTS" ]; then
  [ "$failed" -gt 0 ] || failed=1
fi
emit_ctrf "efixloader-selftest" "$passed" "$failed" 0
