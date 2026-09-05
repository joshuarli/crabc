#!/usr/bin/env bash
# Pinned-musl/installed-product nftw relative FTW.base regression.
#
# One object is translated by the supplied installed dynamic driver, then
# linked unchanged with pinned musl and with owned dynamic PIE/non-PIE modes.
# Each execution root supplies the exact relative nftw(".") fixture below its
# own /work, and the candidate uses both kernel and direct interpreter entry.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_nftw_relative_base_probe.c"
readonly AUDITOR="$ROOT/compat/x86_64/owned_posix_filesystem_audit.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

[ "$#" -le 1 ] || usage
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
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned nftw relative base TMPDIR must be a physical checkout .work directory')
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned nftw relative base product must be a physical checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-nftw-relative-base.XXXXXX")"
chmod a+rx "$work"
printf 'owned nftw relative-base evidence: %s\n' "$work"

prepare_root() {
    local root="$1"
    mkdir -p "$root/work/ftw"
    : >"$root/work/ftw/nftw"
    chmod 755 "$root" "$root/work" "$root/work/ftw"
    chmod 644 "$root/work/ftw/nftw"
}

run_in_root() {
    local root="$1" output="$2" status
    shift 2
    if timeout 20 env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin chroot "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
}

require_success() {
    local label="$1" output="$2"
    if [ "$(cat "${output%.stdout}.status")" != 0 ]; then
        printf 'owned nftw relative base %s exited nonzero\n' "$label" >&2
        cat "${output%.stdout}.stderr" >&2
        return 1
    fi
    grep -qx 'nftw-relative-base-ok' "$output"
}

assert_nftw_provider() {
    local table="$work/dynamic-symbols.txt"
    readelf --dyn-syms --wide "$installed/usr/lib/libc.so" >"$table"
    [ "$(awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "nftw" { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
        printf 'owned nftw relative base: shared libc lacks one global nftw provider\n' >&2
        return 1
    }
}

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"
python3 -B "$AUDITOR" validate-dynamic-product "$installed"
assert_nftw_provider

"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
readelf --symbols --wide "$work/workload.o" >"$work/workload-symbols.txt"
grep -Eq '[[:space:]]UND[[:space:]].*nftw$' "$work/workload-symbols.txt"
readonly workload_sha256="$(sha256sum "$work/workload.o" | awk '{ print $1 }')"

mkdir "$work/oracle-root"
prepare_root "$work/oracle-root"
"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/oracle-root/consumer"
[ "$workload_sha256" = "$(sha256sum "$work/workload.o" | awk '{ print $1 }')" ]
run_in_root "$work/oracle-root" "$work/oracle.stdout" /consumer
require_success oracle "$work/oracle.stdout"

for mode in pie non-pie; do
    candidate="$work/consumer-$mode"
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
    [ "$workload_sha256" = "$(sha256sum "$work/workload.o" | awk '{ print $1 }')" ]
    python3 -B "$AUDITOR" audit-dynamic "$installed" "$mode" "$work/workload.o" \
        "$candidate" "$candidate.crabc-link.json"
    for entry in kernel direct; do
        root="$work/dynamic-$mode-$entry-root"
        mkdir "$root"
        cp -a "$installed/." "$root/"
        prepare_root "$root"
        cp "$candidate" "$root/consumer"
        output="$work/dynamic-$mode-$entry.stdout"
        if [ "$entry" = direct ]; then
            run_in_root "$root" "$output" "$INTERPRETER" /consumer
        else
            run_in_root "$root" "$output" /consumer
        fi
        require_success "dynamic-$mode-$entry" "$output"
        cmp "$work/oracle.stdout" "$output"
        cmp "$work/oracle.stderr" "${output%.stdout}.stderr"
        cmp "$work/oracle.status" "${output%.stdout}.status"
    done
done

printf 'owned nftw relative base: PASS (same installed object, pinned musl, exact nftw(".") callback paths, dynamic PIE/non-PIE kernel/direct entries); evidence: %s\n' "$work"
