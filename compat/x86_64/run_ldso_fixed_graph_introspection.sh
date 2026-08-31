#!/usr/bin/env bash
# Native evidence for copied introspection over one immutable x86 loader graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_introspection_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_introspection_main.c"
readonly ORACLE_MAIN="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_introspection_oracle.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: fixed-graph introspection evidence requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$ORACLE_CC" ] || [ ! -x "$MUSL_LOADER" ]; then
    printf '%s\n' 'ERROR: the pinned musl 1.2.6 compiler and loader are required' >&2
    exit 2
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
if [ "${CRABC_LDSO_FIXED_GRAPH_INTROSPECTION_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained fixed-graph introspection work directory: $work_dir" >&2
else
    trap 'rm -rf "$work_dir"' EXIT
fi

build_interpreter() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib --cfg crabc_fixed_graph_introspection "$@" \
        -C panic=abort -C relocation-model=pic "$SOURCE_ROOT" -o "$work_dir/libfixed_graph_introspection.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/libfixed_graph_introspection.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_interpreter "$work_dir/ld-crabc-x86_64-fixed-graph-introspection.so"
build_interpreter "$work_dir/ld-crabc-x86_64-fixed-graph-introspection-malformed.so" \
    --cfg crabc_fixed_graph_introspection_malformed

for interpreter in "$work_dir/ld-crabc-x86_64-fixed-graph-introspection.so" \
    "$work_dir/ld-crabc-x86_64-fixed-graph-introspection-malformed.so"; do
    test "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN
    if readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)|\(RELR\)'; then
        printf '%s\n' "ERROR: introspection interpreter selected an ambient or widened runtime: $interpreter" >&2
        exit 1
    fi
    if readelf -lW "$interpreter" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: introspection interpreter selected PT_TLS: $interpreter" >&2
        exit 1
    fi
    if ! readelf -lW "$interpreter" | grep -q GNU_RELRO; then
        printf '%s\n' "ERROR: introspection interpreter lacks PT_GNU_RELRO: $interpreter" >&2
        exit 1
    fi
    if ! readelf -Ws "$interpreter" | awk '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_fixed_graph_introspection_v1" && $3 == 40 { found = 1 } END { exit found ? 0 : 1 }'; then
        printf '%s\n' "ERROR: interpreter lacks the exact 40-byte introspection record: $interpreter" >&2
        exit 1
    fi
done

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs \
    -Wl,-soname,libleaf-introspection.so "$LEAF" -o "$work_dir/libleaf-introspection.so"
cc -DCRABC_FIXED_GRAPH_INTROSPECTION=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-introspection.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-introspection.so \
    -o "$work_dir/libmid-introspection.so"

build_candidate_main() {
    local interpreter="$1"
    local output="$2"
    cc -nostdlib -fPIE -pie -fno-builtin -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "$START" "$MAIN" -L"$work_dir" -Wl,--no-as-needed \
        -l:libmid-introspection.so -o "$output"
}

build_candidate_main "$work_dir/ld-crabc-x86_64-fixed-graph-introspection.so" \
    "$work_dir/main-fixed-graph-introspection"
build_candidate_main "$work_dir/ld-crabc-x86_64-fixed-graph-introspection-malformed.so" \
    "$work_dir/main-fixed-graph-introspection-malformed"

"$ORACLE_CC" -D_GNU_SOURCE -fPIE -pie -Wl,--dynamic-linker,"$MUSL_LOADER" \
    -Wl,-rpath,"$work_dir" "$ORACLE_MAIN" -L"$work_dir" -Wl,--no-as-needed \
    -l:libmid-introspection.so -ldl -o "$work_dir/main-musl-introspection"

for binary in "$work_dir/main-fixed-graph-introspection" \
    "$work_dir/main-fixed-graph-introspection-malformed" \
    "$work_dir/libmid-introspection.so" "$work_dir/libleaf-introspection.so"; do
    if readelf -dW "$binary" | grep -Eq '\(NEEDED\).*(libc|libgcc|ld-linux)'; then
        printf '%s\n' "ERROR: candidate graph selected an ambient runtime: $binary" >&2
        exit 1
    fi
    if readelf -lW "$binary" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: candidate graph selected PT_TLS: $binary" >&2
        exit 1
    fi
done

if ! readelf -Ws "$work_dir/main-fixed-graph-introspection" | awk '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_introspection_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'ERROR: candidate main lost its weak introspection record import' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/main-fixed-graph-introspection" | grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_introspection_v1'; then
    printf '%s\n' 'ERROR: candidate main lacks the exact weak GLOB_DAT record relocation' >&2
    exit 1
fi

require_needed() {
    local binary="$1"
    local expected="$2"
    local actual
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    if [ "$actual" != "$expected" ]; then
        printf '%s\n' "ERROR: fixed introspection graph dependency drifted: $binary" >&2
        readelf -dW "$binary" >&2
        exit 1
    fi
}
require_needed "$work_dir/main-fixed-graph-introspection" libmid-introspection.so
require_needed "$work_dir/libmid-introspection.so" libleaf-introspection.so
require_needed "$work_dir/libleaf-introspection.so" ''

run_clean() {
    local binary="$1"
    env -i PATH=/usr/bin:/bin "$binary"
}

(cd "$work_dir" && run_clean "$work_dir/main-musl-introspection")
(cd "$work_dir" && run_clean "$work_dir/main-fixed-graph-introspection")

set +e
(cd "$work_dir" && run_clean "$work_dir/main-fixed-graph-introspection-malformed") >/dev/null 2>&1
malformed_status=$?
set -e
if [ "$malformed_status" -ne 127 ]; then
    printf '%s\n' "ERROR: malformed introspection record did not fail closed with status 127 (got $malformed_status)" >&2
    exit 1
fi

printf '%s\n' 'x86 fixed-graph loader introspection snapshot/address/information: PASS'
