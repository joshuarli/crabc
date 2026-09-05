#!/usr/bin/env bash
# Exercise the dynamic FILE allocator boundary against pinned musl.
#
# The consumer defines malloc/realloc/free in its main executable, marks each
# freed allocation with a sentinel, and uses libc-test's flockfile-list order.
# A FILE allocation or release that bypasses the executable's public C
# allocator corrupts or bypasses that ownership record.  The same installed
# header object is linked to musl and to each installed dynamic entry mode.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_stdio_allocator_interposition_probe.c"
readonly CRABC_INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly MUSL_INTERPRETER=/lib/ld-musl-x86_64.so.1

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
[ "$(uname -sm)" = 'Linux x86_64' ]

provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned stdio allocator interposition TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned stdio allocator interposition product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-stdio-allocator-interposition.XXXXXX")"
chmod a+rx "$work"
printf 'owned stdio allocator interposition evidence: %s\n' "$work"

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/installed" >"$work/dynamic-build.json"
    provided_dynamic="$work/installed"
fi
readonly installed="$provided_dynamic"

# Compile exactly once through the installed product.  -rdynamic belongs only
# to the final executable links, where it exposes the consumer's malloc family
# to libc.so's ordinary ELF lookup.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
readelf -hW "$work/workload.o" >"$work/workload.header"
readelf -rW "$work/workload.o" >"$work/workload.relocations"

assert_exported_interposer() {
    local executable="$1" symbols="$2" name matches

    readelf --dyn-syms -W "$executable" >"$symbols"
    for name in malloc realloc free; do
        matches="$(awk -v name="$name" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")"
        [ "$matches" -eq 1 ] || {
            printf 'owned stdio allocator interposition: executable does not export %s\n' "$name" >&2
            return 1
        }
    done
}

prepare_oracle_root() {
    local root="$1" executable="$2"

    mkdir -p "$root/lib" "$root/tmp"
    chmod 1777 "$root/tmp"
    cp "$executable" "$root/consumer"
    cp /opt/musl-1.2.6/lib/libc.so "$root$MUSL_INTERPRETER"
    ln -s ld-musl-x86_64.so.1 "$root/lib/libc.so"
}

prepare_candidate_root() {
    local root="$1" executable="$2"

    cp -a "$installed" "$root"
    mkdir -p "$root/tmp"
    chmod 1777 "$root/tmp"
    cp "$executable" "$root/consumer"
}

run_in_root() {
    local root="$1" prefix="$2" status
    shift 2

    if timeout 25 env -i PATH="$PATH" chroot "$root" "$@" \
        >"$prefix.stdout" 2>"$prefix.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"$prefix.status"
    [ "$status" -eq 0 ]
}

for mode in pie non-pie; do
    if [ "$mode" = pie ]; then
        oracle_flags=(-fPIE -pie)
        candidate_mode=--dynamic-pie
    else
        oracle_flags=(-fno-pie -no-pie)
        candidate_mode=--dynamic-non-pie
    fi

    "$ORACLE_CC" -std=c11 "${oracle_flags[@]}" -rdynamic "$work/workload.o" \
        -Wl,--dynamic-linker,"$MUSL_INTERPRETER" -o "$work/oracle-$mode"
    "$installed/bin/crabc-cc-dynamic" "$candidate_mode" -rdynamic "$work/workload.o" \
        -o "$work/candidate-$mode"
    assert_exported_interposer "$work/oracle-$mode" "$work/oracle-$mode.symbols"
    assert_exported_interposer "$work/candidate-$mode" "$work/candidate-$mode.symbols"

    for entry in kernel direct; do
        oracle_root="$work/oracle-$mode-$entry-root"
        candidate_root="$work/candidate-$mode-$entry-root"
        oracle_prefix="$work/oracle-$mode-$entry"
        candidate_prefix="$work/candidate-$mode-$entry"
        prepare_oracle_root "$oracle_root" "$work/oracle-$mode"
        prepare_candidate_root "$candidate_root" "$work/candidate-$mode"

        if [ "$entry" = direct ]; then
            run_in_root "$oracle_root" "$oracle_prefix" "$MUSL_INTERPRETER" /consumer
            run_in_root "$candidate_root" "$candidate_prefix" "$CRABC_INTERPRETER" /consumer
        else
            run_in_root "$oracle_root" "$oracle_prefix" /consumer
            run_in_root "$candidate_root" "$candidate_prefix" /consumer
        fi
        cmp "$oracle_prefix.status" "$candidate_prefix.status"
        cmp "$oracle_prefix.stdout" "$candidate_prefix.stdout"
        cmp "$oracle_prefix.stderr" "$candidate_prefix.stderr"
    done
done

printf '%s\n' \
    "owned stdio allocator interposition: PASS (same installed-header object; pinned musl and installed PIE/non-PIE kernel/direct roots; executable malloc/realloc/free interposition, FILE close ownership, and flockfile-list stale-link sentinel); evidence: $work"
