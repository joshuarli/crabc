#!/usr/bin/env bash
# Source-faithful owned filesystem mechanisms through each installed product.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_filesystem_mechanisms_probe.c"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product_argument = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned filesystem mechanisms TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned filesystem mechanisms product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-filesystem-mechanisms.XXXXXX")"
chmod a+rx "$work"
printf 'owned filesystem mechanisms evidence: %s\n' "$work"

mounted_root=''
cleanup() {
    local status=$?
    trap - EXIT
    if [ -n "$mounted_root" ]; then
        umount "$mounted_root/proc" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_in_root() {
    local root="$1" output="$2"
    shift 2
    mkdir -p "$root/tmp" "$root/proc"
    mount -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"
    mounted_root="$root"
    timeout 30 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr"
    umount "$root/proc"
    mounted_root=''
}

assert_static_symbols() {
    local archive="$1" requested="$2" table symbol
    table="$work/static-symbols.txt"
    nm -g --defined-only "$archive" >"$table"
    for symbol in $requested; do
        [ "$(awk -v symbol="$symbol" '$3 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned filesystem mechanisms: static symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_symbols() {
    local shared="$1" requested="$2" table symbol
    table="$work/dynamic-symbols.txt"
    readelf --dyn-syms -W "$shared" >"$table"
    for symbol in $requested; do
        [ "$(awk -v symbol="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned filesystem mechanisms: dynamic symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"
readonly owned_symbols='fchmodat fchown fchownat mknod mknodat renameat symlinkat statx fallocate lockf preadv2 pwritev2 lchmod'

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
mkdir -p "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer
grep -qx owned-filesystem-mechanisms-ok "$work/oracle.stdout"

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    assert_static_symbols "$work/static-product/usr/lib/libc.a" "$owned_symbols"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/consumer-$mode"
        mkdir -p "$work/$mode-root"
        cp "$work/consumer-$mode" "$work/$mode-root/consumer"
        run_in_root "$work/$mode-root" "$work/$mode.stdout" /consumer
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so" "$owned_symbols"
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    for entry in kernel direct; do
        root="$work/$mode-$entry-root"
        cp -a "$installed" "$root"
        cp "$work/consumer-$mode" "$root/consumer"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "$work/$mode-$entry.stdout" /lib/ld-crabc-x86_64.so.1 /consumer
        else
            run_in_root "$root" "$work/$mode-$entry.stdout" /consumer
        fi
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done

printf 'owned filesystem mechanisms: PASS (same workload object, pinned musl, static/static-PIE/dynamic PIE/non-PIE kernel/direct chroots, procfd fallbacks, relative dirfds, symlinks, ownership, statx, allocation, locks, and vectored current-offset semantics); evidence: %s\n' "$work"
