#!/usr/bin/env bash
# Compare failed runtime transactions with the pinned musl 1.2.6 loader.
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly fixtures="$ROOT/compat/x86_64"
[ "$#" -eq 1 ] || { printf 'usage: %s INSTALLED_DYNAMIC_SYSROOT\n' "$0" >&2; exit 2; }
readonly installed="$1"
python3 -B - "$ROOT" "${TMPDIR:-}" "$installed" <<'PY'
from pathlib import Path
import sys
root, temporary, installed = map(Path, sys.argv[1:])
if (not temporary.is_dir() or temporary.resolve() != temporary
        or not temporary.is_relative_to(root / '.work')
        or not installed.is_dir() or installed.resolve() != installed
        or not installed.is_relative_to(root / '.work')):
    raise SystemExit('failed-open runner requires physical checkout .work paths')
PY
bash "$fixtures/run_musl_oracle.sh"
work="$(mktemp -d "$TMPDIR/general-dynamic-failed-open.XXXXXX")"
readonly work
mkdir "$work/candidate" "$work/oracle"
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly source="$fixtures/general_dynamic_failed_open_dso.c"
"$driver" --dynamic-shared-object -DFAILED_OPEN_TLS "$source" -o "$work/candidate/libfo_tls.so"
"$driver" --dynamic-shared-object -DFAILED_OPEN_LATE "$source" -o "$work/candidate/libfo_late.so"
"$driver" --dynamic-shared-object -DFAILED_OPEN_ROOT "$source" \
    --application-dso "$work/candidate/libfo_tls.so" --application-dso "$work/candidate/libfo_late.so" \
    -o "$work/candidate/libfo_root.so"
mv "$work/candidate/libfo_late.so" "$work/candidate/libfo_late-good.so"
"$driver" --dynamic-shared-object -DFAILED_OPEN_LATE -DFAILED_OPEN_MISSING_SYMBOL "$source" -o "$work/candidate/libfo_late-unresolved.so"
"$driver" --dynamic-pie "$fixtures/general_dynamic_failed_open.c" -o "$work/candidate/consumer"
"$oracle_cc" -fPIC -shared -DFAILED_OPEN_TLS "$source" -Wl,-soname,libfo_tls.so -o "$work/oracle/libfo_tls.so"
"$oracle_cc" -fPIC -shared -DFAILED_OPEN_LATE "$source" -Wl,-soname,libfo_late.so -o "$work/oracle/libfo_late.so"
"$oracle_cc" -fPIC -shared -DFAILED_OPEN_ROOT "$source" -L"$work/oracle" \
    -Wl,--no-as-needed -l:libfo_tls.so -l:libfo_late.so -Wl,-z,now,-soname,libfo_root.so \
    -o "$work/oracle/libfo_root.so"
mv "$work/oracle/libfo_late.so" "$work/oracle/libfo_late-good.so"
"$oracle_cc" -fPIC -shared -DFAILED_OPEN_LATE -DFAILED_OPEN_MISSING_SYMBOL "$source" -Wl,-soname,libfo_late.so -o "$work/oracle/libfo_late-unresolved.so"
"$oracle_cc" -fPIE -pie "$fixtures/general_dynamic_failed_open.c" -o "$work/oracle/consumer"
for directory in "$work/candidate" "$work/oracle"; do
    python3 -B "$fixtures/general_dynamic_failed_open_malformed.py" \
        "$directory/libfo_late-good.so" "$directory/libfo_late.so"
done
cp -a "$installed" "$work/execution-root"
cp "$work/candidate/consumer" "$work/execution-root/consumer"
cp "$work/candidate"/*.so "$work/execution-root/usr/lib/"
status=0
LD_LIBRARY_PATH=/usr/lib timeout 20 chroot "$work/execution-root" /consumer \
    /usr/lib/libfo_late-unresolved.so /usr/lib/libfo_late-good.so /usr/lib/libfo_late.so \
    >"$work/candidate.stdout" 2>"$work/candidate.stderr" || status=$?
oracle_status=0
LD_LIBRARY_PATH="$work/oracle" timeout 20 "$work/oracle/consumer" \
    "$work/oracle/libfo_late-unresolved.so" "$work/oracle/libfo_late-good.so" "$work/oracle/libfo_late.so" \
    >"$work/oracle.stdout" 2>"$work/oracle.stderr" || oracle_status=$?
if [ "$status" -ne 0 ] || [ "$oracle_status" -ne 0 ] \
    || ! cmp -s "$work/candidate.stdout" "$work/oracle.stdout"; then
    printf 'failed-open transaction: FAIL candidate=%s oracle=%s; evidence: %s\n' \
        "$status" "$oracle_status" "$work" >&2
    diff -u "$work/oracle.stdout" "$work/candidate.stdout" >&2 || true
    exit 1
fi
grep -Fxq 'failed-open transaction: complete' "$work/candidate.stdout"
grep -Fxq 'T' "$work/candidate.stdout"
[ "$(grep -Fxc 'T' "$work/candidate.stdout")" -eq 1 ]
printf 'failed-open transaction: PASS (pinned-musl malformed, relocation and retry differential); evidence: %s\n' "$work"
