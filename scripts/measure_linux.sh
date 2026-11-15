#!/usr/bin/env bash
# Linux measurement for the streaming single-shot table-privacy engine.
#
# Verifies, on this machine:
#   1. differential parity: randomized small tables vs the in-memory reference
#      model.analyze (field order shuffling, records before parameters,
#      cross-chunk duplicate keys/ids, trailing bad records, encodings);
#   2. a ~60k-row medium run compared byte for byte with the reference;
#   3. contract limits: 1,000,001 rows rejected, >1 GiB source rejected,
#      k/max_suppressed bounds (inside the small battery);
#   4. disk-write failures: exit 2, previous report preserved, no partial
#      stdout, private temp data removed;
#   5. the 1,000,000-row high-cardinality big run inside a 256 MiB address
#      space (ulimit -v), with source and report both larger than 256 MiB.
#
# Usage: scripts/measure_linux.sh [workdir]
# Everything is written under a fresh workdir (default: mktemp -d) and the
# private scratch area is removed afterwards.  Runtime: several minutes.
set -euo pipefail

PROJ=$(cd "$(dirname "$0")/.." && pwd)
SRC="$PROJ/src"
HELPERS="$PROJ/scripts/measure_helpers.py"
if [ $# -ge 1 ]; then
    WORK="$1"
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/table-privacy-measure-XXXXXXXX")
fi
BIGTMP="$WORK/scratch"
mkdir -p "$BIGTMP" "$WORK/small" "$WORK/medium" "$WORK/diskfail" "$WORK/big"
export TMPDIR="$BIGTMP"
export SQLITE_TMPDIR="$BIGTMP"

echo "== environment =="
python3 --version
python3 -c 'import sqlite3,sys; print("sqlite", sqlite3.sqlite_version); assert sys.version_info >= (3,11)'
echo "workdir: $WORK"

RUNNER="$WORK/run_cli.py"
cat > "$RUNNER" <<EOF
import sys
sys.path.insert(0, '$SRC')
from table_privacy.cli import main
raise SystemExit(main())
EOF

echo "== 1/5 small differential battery =="
python3 -I "$HELPERS" small --src "$SRC" --work "$WORK/small"

echo "== 2/5 medium byte-parity run =="
python3 -I "$HELPERS" medium --src "$SRC" --work "$WORK/medium"

echo "== 3/5 disk-write failure battery =="
python3 -I "$HELPERS" diskfail --src "$SRC" --work "$WORK/diskfail"

echo "== 4/5 contract limits =="
python3 -I "$HELPERS" gen-overflow --path "$WORK/overflow.json"
set +e
python3 -I "$RUNNER" --source "$WORK/overflow.json" --output "$WORK/overflow.report.json" > "$WORK/overflow.stdout" 2> "$WORK/overflow.stderr"
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "FAIL: 1,000,001 rows: expected exit 2, got $rc"; exit 1; }
grep -q 'expected bounded array' "$WORK/overflow.stderr" || { echo "FAIL: row-limit message"; cat "$WORK/overflow.stderr"; exit 1; }
[ ! -s "$WORK/overflow.stdout" ] || { echo "FAIL: stdout not empty on row-limit rejection"; exit 1; }
echo ".... 1,000,001 rows rejected with exit 2"

truncate -s 1073741825 "$WORK/too-big.json"
set +e
python3 -I "$RUNNER" --source "$WORK/too-big.json" --output "$WORK/too-big.report.json" > "$WORK/too-big.stdout" 2> "$WORK/too-big.stderr"
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "FAIL: >1 GiB source: expected exit 2, got $rc"; exit 1; }
grep -q 'JSON exceeds 1 GiB' "$WORK/too-big.stderr" || { echo "FAIL: size-limit message"; cat "$WORK/too-big.stderr"; exit 1; }
echo ".... 1 GiB + 1 byte source rejected with exit 2"

truncate -s 1073741824 "$WORK/exactly-1g.json"
set +e
python3 -I "$RUNNER" --source "$WORK/exactly-1g.json" --output "$WORK/exactly-1g.report.json" > "$WORK/exactly-1g.stdout" 2> "$WORK/exactly-1g.stderr"
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "FAIL: exactly-1 GiB invalid source: expected exit 2, got $rc"; exit 1; }
if grep -q 'JSON exceeds 1 GiB' "$WORK/exactly-1g.stderr"; then
    echo "FAIL: exactly 1 GiB must not trip the size limit"; exit 1
fi
echo ".... exactly 1 GiB stays inside the limit (fails later as invalid JSON)"
rm -f "$WORK/too-big.json" "$WORK/exactly-1g.json" "$WORK/overflow.json"

echo "== 5/5 big run: 1,000,000 rows in a 256 MiB address space =="
AVAIL_KB=$(df -k --output=avail "$WORK" | tail -1 | tr -d ' ')
NEED_KB=4194304
if [ "$AVAIL_KB" -lt "$NEED_KB" ]; then
    echo "SKIP: need ~4 GiB free in $WORK for the big run, have $((AVAIL_KB / 1024)) MiB"
    echo "MEASUREMENT DONE (big run skipped)"
    exit 0
fi

BIGSRC="$WORK/big/big.json"
BIGREPORT="$WORK/big/report.json"
BIGSTDOUT="$WORK/big/stdout.json"
python3 -I "$HELPERS" gen-big --path "$BIGSRC"

start=$(date +%s)
if [ -x /usr/bin/time ]; then
    (
        ulimit -v 262144   # 256 MiB of virtual address space
        /usr/bin/time -v python3 -I "$RUNNER" --source "$BIGSRC" --output "$BIGREPORT" \
            > "$BIGSTDOUT" 2> "$WORK/big/time.txt"
    )
    RSS_KB=$(grep 'Maximum resident set size' "$WORK/big/time.txt" | grep -o '[0-9]*')
else
    echo ".... /usr/bin/time not found: measuring peak RSS via wait4 rusage"
    (
        ulimit -v 262144   # 256 MiB of virtual address space
        python3 -I "$HELPERS" rusage-run --out "$WORK/big/rusage.txt" -- \
            python3 -I "$RUNNER" --source "$BIGSRC" --output "$BIGREPORT" \
            > "$BIGSTDOUT"
    )
    RSS_KB=$(awk '{print $2}' "$WORK/big/rusage.txt")
fi
end=$(date +%s)
echo ".... big run finished in $((end - start))s under ulimit -v 262144"
echo ".... peak RSS: $((RSS_KB / 1024)) MiB"
[ "$RSS_KB" -lt 262144 ] || { echo "FAIL: peak RSS exceeds 256 MiB"; exit 1; }

python3 -I "$HELPERS" check-big --source "$BIGSRC" --report "$BIGREPORT" --stdout "$BIGSTDOUT"

rm -rf "$BIGTMP"
echo "MEASUREMENT PASS"
