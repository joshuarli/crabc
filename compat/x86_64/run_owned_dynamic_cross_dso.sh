#!/usr/bin/env bash
# Installed cross-DSO composition: an initial IE-TLS dependency and a runtime
# plugin share TLS, allocation, errno, stdio, TSD, signals and exit with the
# main program. Both installed entry modes must match pinned musl byte for byte.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('cross-dso TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-dynamic-cross-dso.XXXXXX")"
readonly work
# The container writes as root; the host reviewer must be able to read it.
chmod 0755 "$work"
trap 'printf "owned dynamic cross-DSO: FAIL; evidence: %s\n" "$work" >&2' ERR
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly fixtures="$ROOT/compat/x86_64"
mkdir "$work/oracle"
"$driver" --dynamic-shared-object "$fixtures/owned_dynamic_cross_dso_library.c" -o "$work/libcross-initial.so"
"$driver" --dynamic-shared-object "$fixtures/owned_dynamic_cross_dso_plugin.c" \
    --application-dso "$work/libcross-initial.so" -o "$work/libcross-plugin.so"
"$oracle_cc" -fPIC -shared "$fixtures/owned_dynamic_cross_dso_library.c" \
    -Wl,-z,now,-soname,libcross-initial.so -o "$work/oracle/libcross-initial.so"
"$oracle_cc" -fPIC -shared "$fixtures/owned_dynamic_cross_dso_plugin.c" \
    -L"$work/oracle" -l:libcross-initial.so -Wl,-z,now,-soname,libcross-plugin.so -o "$work/oracle/libcross-plugin.so"
# The dependency must really be an initial-exec object: DF_STATIC_TLS plus
# TPOFF64 relocations, and the executable reaches it through its own TPOFF64.
readelf -dW "$work/libcross-initial.so" >"$work/libcross-initial.dynamic"
grep -Eq '\(FLAGS\).*STATIC_TLS' "$work/libcross-initial.dynamic"
readelf -rW "$work/libcross-initial.so" >"$work/libcross-initial.relocations"
grep -q 'R_X86_64_TPOFF64' "$work/libcross-initial.relocations"
cp -a "$installed" "$work/execution-root"
cp "$work/libcross-initial.so" "$work/libcross-plugin.so" "$work/execution-root/usr/lib/"
for mode in --dynamic-pie --dynamic-non-pie; do
    name="consumer${mode#--dynamic}"
    case "$mode" in --dynamic-pie) oracle_flags=(-fPIE -pie) ;; *) oracle_flags=(-fno-pie -no-pie) ;; esac
    "$driver" "$mode" "$fixtures/owned_dynamic_cross_dso_consumer.c" \
        --application-dso "$work/libcross-initial.so" -o "$work/$name"
    "$oracle_cc" "${oracle_flags[@]}" "$fixtures/owned_dynamic_cross_dso_consumer.c" \
        -L"$work/oracle" -l:libcross-initial.so -Wl,-rpath,"$work/oracle" -o "$work/oracle/$name"
    readelf -rW "$work/$name" >"$work/$name.relocations"
    grep -Eq 'R_X86_64_TPOFF64 .* cross_ie_value' "$work/$name.relocations"
    cp "$work/$name" "$work/execution-root/$name"
    # A regular-file stdout makes stdio fully buffered: exit must flush it
    # after every atexit handler and destructor has written.
    candidate=0 oracle=0
    timeout 30 chroot "$work/execution-root" "/$name" >"$work/$name.candidate.stdout" \
        2>"$work/$name.candidate.stderr" || candidate=$?
    LD_LIBRARY_PATH="$work/oracle" timeout 30 "$work/oracle/$name" >"$work/$name.oracle.stdout" \
        2>"$work/$name.oracle.stderr" || oracle=$?
    if [ "$candidate" -ne 0 ] || [ "$oracle" -ne 0 ] ||
        ! cmp -s "$work/$name.oracle.stdout" "$work/$name.candidate.stdout"; then
        printf 'owned dynamic cross-DSO %s: candidate=%s oracle=%s\n' "$mode" "$candidate" "$oracle" >&2
        cat "$work/$name.candidate.stderr" "$work/$name.oracle.stderr" >&2
        diff -u "$work/$name.oracle.stdout" "$work/$name.candidate.stdout" >&2 || true
        false
    fi
    [ ! -s "$work/$name.candidate.stderr" ]
    grep -Fxq 'exit: returning from main' "$work/$name.candidate.stdout"
done
printf 'owned dynamic cross-DSO: PASS (musl differential, PIE and non-PIE: initial IE TLS and reopen, plugin GD TLS, allocation/errno/stdio/TSD/signal/exit across modules); evidence: %s\n' "$work"
