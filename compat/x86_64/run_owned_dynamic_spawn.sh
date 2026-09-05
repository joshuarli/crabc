#!/usr/bin/env bash
# The existing spawn workload through installed dynamic entry and optional static replay.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
            [ "$#" -ge 2 ] || usage
            [ -z "$provided_static" ] || usage
            [ -n "$2" ] && [[ "$2" != -* ]] || usage
            provided_static="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            [ -z "$provided_dynamic" ] && [ -n "$1" ] || usage
            provided_dynamic="$1"
            shift
            ;;
    esac
done
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" "$provided_static" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic spawn TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('dynamic spawn product must be a checkout .work directory')
if sys.argv[4]:
    product = Path(sys.argv[4]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('static spawn product must be a checkout .work directory')
    sys.path.insert(0, str(root / 'compat/x86_64'))
    from owned_static_sysroot_package import source_entries, validate_installed_tree
    validate_installed_tree(product, source_entries(product))
PY
if [ -n "$provided_static" ]; then
    provided_static="$(realpath "$provided_static")"
fi
readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-spawn.XXXXXX")"
chmod a+rx "$work"
printf 'dynamic spawn evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_spawn_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc

run_in_root() {
    local root="$1" output="$2" status=0
    shift 2
    timeout 40 env -i PATH="$PATH" "$CHROOT" "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr" || status=$?
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

compare_oracle() {
    local label="$1" suffix
    for suffix in stdout stderr status; do
        cmp "$work/oracle.$suffix" "$work/$label.$suffix"
    done
}

# The common validator owns both sealed receipt schemas and actual ELF checks.
# Preserve its exact returned product/object/output identity for each linkage.
validate_sealed_link() {
    local product="$1" consumer="$2" receipt="$3" linkage="$4"
    python3 -B - "$ROOT" "$product" "$work/workload.o" "$consumer" "$receipt" "$linkage" \
        >"$work/$linkage.link-identity.json" <<'PY_LINK'
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1]) / 'compat/x86_64'))
from owned_posix_product_evidence import validate_link
identity = validate_link(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6])
json.dump(identity, sys.stdout, sort_keys=True, separators=(',', ':'))
sys.stdout.write('\n')
PY_LINK
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/build.json"
fi
readonly installed="$(realpath "$provided_dynamic")"
mkdir "$work/oracle-root"
# One application object is linked by the pinned oracle and each installed
# entry. A fixed owned path permits exec from chdir actions without mounting
# host procfs inside the isolated execution roots.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    '-DCRABC_SPAWN_EXECUTABLE="/consumer"' -c "$probe" -o "$work/workload.o"
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle-root/consumer"
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer /spawn-state
grep -qx owned-spawn-ok "$work/oracle.stdout"

# Static replay is opt-in: no static producer is selected by this leaf.
if [ -n "$provided_static" ]; then
    for mode in static static-pie; do
        consumer="$work/consumer-$mode"
        receipt="$work/consumer-$mode.receipt.json"
        (
            cd "$work"
            "$provided_static/bin/crabc-cc" "-$mode" --link-receipt "$(basename "$receipt")" \
                "$work/workload.o" -o "$consumer"
        )
        validate_sealed_link "$provided_static" "$consumer" "$receipt" "$mode"
        mkdir "$work/$mode-root"
        cp "$consumer" "$work/$mode-root/consumer"
        run_in_root "$work/$mode-root" "$work/$mode.stdout" /consumer /spawn-state
        compare_oracle "$mode"
    done
fi
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    validate_sealed_link "$installed" "$work/consumer-$mode" "$work/consumer-$mode.crabc-link.json" "$mode"
    readelf -hW "$work/consumer-$mode" >"$work/consumer-$mode.header"
    readelf -lW "$work/consumer-$mode" >"$work/consumer-$mode.segments"
    readelf -dW "$work/consumer-$mode" >"$work/consumer-$mode.dynamic"
    cp -a "$installed" "$work/$mode-root"
    cp "$work/consumer-$mode" "$work/$mode-root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 /consumer); fi
        run_in_root "$work/$mode-root" "$work/$mode-$entry.stdout" "${command[@]}" /spawn-state
        compare_oracle "$mode-$entry"
    done
done
printf 'owned dynamic spawn: PASS (same workload object, musl, optional supplied static/static-PIE, PIE/non-PIE kernel/direct entry, sealed link identities and raw status/stdout/stderr, attributes, file actions, PATH, worker spawn and failure rollback); evidence: %s\n' "$work"
