#!/usr/bin/env bash
# Compare a source-built two-generation dlopen TLS workload with pinned musl.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { printf 'usage: %s DYNAMIC-SYSROOT\n' "$0" >&2; exit 2; }
readonly installed="$1"
python3 -B - "$ROOT" "${TMPDIR:-}" "$installed" <<'PY'
from pathlib import Path
import sys
root, temporary, installed = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('runtime TLS TMPDIR must be a physical checkout .work directory')
if not installed.is_dir() or installed.resolve() != installed or not installed.is_relative_to(root / '.work'):
    raise SystemExit('runtime TLS product must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-loader-runtime-tls.XXXXXX")"
readonly work
chmod 0755 "$work"
trap 'printf "owned loader runtime TLS: FAIL; evidence: %s\n" "$work" >&2' ERR
readonly driver="$installed/bin/crabc-cc-dynamic"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly source="$ROOT/compat/x86_64"
mkdir "$work/oracle"
for row in 'one 101' 'two 202'; do
    read -r name seed <<<"$row"
    "$driver" --dynamic-shared-object -DTLS_SEED="$seed" \
        "$source/owned_loader_runtime_tls_plugin.c" -o "$work/libowned-runtime-tls-$name.so"
    "$oracle_cc" -fPIC -shared -DTLS_SEED="$seed" \
        "$source/owned_loader_runtime_tls_plugin.c" \
        -Wl,-z,now,-soname,"libowned-runtime-tls-$name.so" \
        -o "$work/oracle/libowned-runtime-tls-$name.so"
    readelf -rW "$work/libowned-runtime-tls-$name.so" >"$work/$name.relocations"
    grep -Eq 'R_X86_64_(DTPMOD64|DTPOFF64|TLSGD)' "$work/$name.relocations"
    readelf -lW "$work/libowned-runtime-tls-$name.so" >"$work/$name.segments"
    grep -Eq ' TLS ' "$work/$name.segments"
done
cp -a "$installed" "$work/execution-root"
cp "$work"/libowned-runtime-tls-*.so "$work/execution-root/usr/lib/"
for mode in --dynamic-pie --dynamic-non-pie; do
    name="consumer${mode#--dynamic}"
    case "$mode" in --dynamic-pie) oracle_flags=(-fPIE -pie) ;; *) oracle_flags=(-fno-pie -no-pie) ;; esac
    "$driver" "$mode" "$source/owned_loader_runtime_tls_main.c" -o "$work/$name"
    "$oracle_cc" "${oracle_flags[@]}" "$source/owned_loader_runtime_tls_main.c" \
        -ldl -pthread -o "$work/oracle/$name"
    readelf -lW "$work/$name" >"$work/$name.segments"
    grep -Fq '/lib/ld-crabc-x86_64.so.1' "$work/$name.segments"
    cp "$work/$name" "$work/execution-root/$name"
    candidate=0 oracle=0
    timeout 30 chroot "$work/execution-root" "/$name" >"$work/$name.candidate.stdout" \
        2>"$work/$name.candidate.stderr" || candidate=$?
    LD_LIBRARY_PATH="$work/oracle" timeout 30 "$work/oracle/$name" \
        >"$work/$name.oracle.stdout" 2>"$work/$name.oracle.stderr" || oracle=$?
    if [ "$candidate" -ne 0 ] || [ "$oracle" -ne 0 ] ||
       ! cmp -s "$work/$name.oracle.stdout" "$work/$name.candidate.stdout" ||
       [ -s "$work/$name.candidate.stderr" ]; then
        printf 'runtime TLS %s: candidate=%s oracle=%s\n' "$mode" "$candidate" "$oracle" >&2
        cat "$work/$name.candidate.stderr" "$work/$name.oracle.stderr" >&2
        diff -u "$work/$name.oracle.stdout" "$work/$name.candidate.stdout" >&2 || true
        false
    fi
done
printf 'owned loader runtime TLS: PASS (musl differential, PIE and non-PIE); evidence: %s\n' "$work"
