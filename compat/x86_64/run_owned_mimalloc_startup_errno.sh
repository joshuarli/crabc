#!/usr/bin/env bash
# Prove the owned same-image mimalloc callback preserves application errno.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROBE="$ROOT/compat/x86_64/owned_mimalloc_startup_errno_probe.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly CHROOT="$(command -v chroot)"

usage() {
    printf 'usage: %s [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

provided_static=''
provided_dynamic=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --static-sysroot)
            [ "$#" -ge 2 ] && [ -z "$provided_static" ] && [ -n "$2" ] || usage
            provided_static="$2"
            shift 2
            ;;
        -*) usage ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
[ -z "$provided_static" ] || [ -n "$provided_dynamic" ] || usage
if [ -n "$provided_static" ]; then
    provided_static="$(realpath -e "$provided_static")"
fi
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_static" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root, temporary, static, dynamic = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned mimalloc startup errno TMPDIR must be a physical checkout .work directory')
for product, description in ((static, 'static product'), (dynamic, 'dynamic product')):
    if str(product) != '.' and (not product.is_dir() or not product.is_relative_to(root / '.work')):
        raise SystemExit(f'owned mimalloc startup errno {description} must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-mimalloc-startup-errno.XXXXXX")"
chmod a+rx "$work"
printf 'owned mimalloc startup errno evidence: %s\n' "$work"

assert_owned_lifecycle_entries() {
    local library="$1" symbols="$2"

    nm -a "$library" >"$symbols"
    for symbol in __crabc_x86_owned_mimalloc_process_initializer \
        __crabc_x86_owned_mimalloc_process_finalizer; do
        awk -v symbol="$symbol" '
            $3 == symbol { all += 1; if ($2 == "d") local_data += 1 }
            END { exit all == 1 && local_data == 1 ? 0 : 1 }
        ' "$symbols" || {
            printf 'owned mimalloc startup errno: libc lacks one local-data %s entry\n' "$symbol" >&2
            return 1
        }
    done
    if awk '$3 == "mi_process_attach" || $3 == "mi_process_detach" { found = 1 } END { exit found ? 0 : 1 }' "$symbols"; then
        printf 'owned mimalloc startup errno: libc retains a C implicit attach/detach hook\n' >&2
        return 1
    fi
}

run_captured() {
    local label="$1" status=0
    shift

    timeout 20 "$@" >"$work/$label.stdout" 2>"$work/$label.stderr" || status=$?
    printf '%s\n' "$status" >"$work/$label.status"
    [ "$status" -eq 0 ]
    [ ! -s "$work/$label.stdout" ]
    [ ! -s "$work/$label.stderr" ]
}

run_in_root() {
    local root="$1" label="$2"
    shift 2

    run_captured "$label" env -i PATH=/usr/bin:/bin "$CHROOT" "$root" "$@"
}

run_static_mode() {
    local product="$1" mode="$2" candidate="$work/static-$mode" root="$work/static-$mode-root"

    (cd "$work" && "$product/bin/crabc-cc" "-$mode" \
        --link-receipt "static-$mode.crabc-link.json" "$work/workload.o" -o "$candidate")
    mkdir -p "$root/work"
    cp "$candidate" "$root/work/probe"
    run_in_root "$root" "static-$mode" /work/probe
}

run_dynamic_mode() {
    local product="$1" mode="$2" candidate="$work/dynamic-$mode" entry root

    (cd "$work" && "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        --link-receipt "dynamic-$mode.crabc-link.json" "$work/workload.o" -o "$candidate")
    for entry in kernel direct; do
        root="$work/dynamic-$mode-$entry-root"
        mkdir -p "$root/lib" "$root/usr/lib" "$root/work"
        cp "$product/lib/ld-crabc-x86_64.so.1" "$root/lib/ld-crabc-x86_64.so.1"
        cp "$product/usr/lib/libc.so" "$root/usr/lib/libc.so"
        cp "$candidate" "$root/work/probe"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "dynamic-$mode-$entry" "$INTERPRETER" /work/probe
        else
            run_in_root "$root" "dynamic-$mode-$entry" /work/probe
        fi
    done
}

"$ORACLE_CC" -DCRABC_MIMALLOC_STARTUP_ERRNO_ORACLE "$PROBE" -o "$work/oracle-dynamic"
"$ORACLE_CC" -static -fno-pie -no-pie -DCRABC_MIMALLOC_STARTUP_ERRNO_ORACLE "$PROBE" \
    -o "$work/oracle-static"
run_captured oracle-dynamic "$work/oracle-dynamic"
run_captured oracle-static "$work/oracle-static"

if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-product" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    provided_static="$work/static-product"
fi

# The sealed product drivers link caller-owned ELF objects. Compile one
# installed-header object through the supplied dynamic driver, then retain
# that same object across both static and dynamic lifecycle link modes.
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
readelf -hW "$work/workload.o" >"$work/workload.header"
readelf -rW "$work/workload.o" >"$work/workload.relocations"

if [ -n "$provided_static" ]; then
    for mode in static static-pie; do
        run_static_mode "$provided_static" "$mode"
    done
fi

assert_owned_lifecycle_entries "$provided_dynamic/usr/lib/libc.so" "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    run_dynamic_mode "$provided_dynamic" "$mode"
done

printf 'owned mimalloc startup errno: PASS (musl reference; preinit allocation and sentinel; user constructor and main allocations; supplied static ET_EXEC/static-PIE when present; dynamic PIE/non-PIE through kernel and direct loader entry in isolated chroots; retained stdout/stderr/status evidence); evidence: %s\n' "$work"
