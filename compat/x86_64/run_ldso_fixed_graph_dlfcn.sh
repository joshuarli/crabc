#!/usr/bin/env bash
# Native evidence for loader-owned handles over one immutable x86 graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_dlfcn_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_dlfcn_main.c"
readonly ORACLE_MAIN="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_dlfcn_oracle.c"
readonly LINK_PROVIDER="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_dlfcn_link_provider.c"
readonly DSO_IMPORT="$ROOT_DIR/compat/x86_64/ldso_fixed_graph_dlfcn_dso_import.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: fixed-graph dlfcn evidence requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$ORACLE_CC" ] || [ ! -x "$MUSL_LOADER" ]; then
    printf '%s\n' 'ERROR: the pinned musl 1.2.6 compiler and loader are required' >&2
    exit 2
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
if [ "${CRABC_LDSO_FIXED_GRAPH_DLFCN_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained fixed-graph dlfcn work directory: $work_dir" >&2
else
    trap 'rm -rf "$work_dir"' EXIT
fi

build_interpreter() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib --cfg crabc_fixed_graph_dlfcn "$@" \
        -C panic=abort -C relocation-model=pic "$SOURCE_ROOT" -o "$work_dir/libfixed_graph_dlfcn.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/libfixed_graph_dlfcn.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_interpreter "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn.so"
build_interpreter "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn-malformed.so" \
    --cfg crabc_fixed_graph_dlfcn_malformed

for interpreter in "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn.so" \
    "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn-malformed.so"; do
    test "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN
    if readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)|\(RELR\)'; then
        printf '%s\n' "ERROR: fixed-graph dlfcn interpreter selected an ambient runtime: $interpreter" >&2
        exit 1
    fi
    if readelf -lW "$interpreter" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: fixed-graph dlfcn interpreter selected PT_TLS: $interpreter" >&2
        exit 1
    fi
    if ! readelf -lW "$interpreter" | grep -q GNU_RELRO; then
        printf '%s\n' "ERROR: fixed-graph dlfcn interpreter lacks PT_GNU_RELRO: $interpreter" >&2
        exit 1
    fi
    if ! readelf -Ws "$interpreter" | awk '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" && $3 == 64 { found = 1 } END { exit found ? 0 : 1 }'; then
        printf '%s\n' "ERROR: interpreter lacks the exact 64-byte fixed-graph dlfcn record: $interpreter" >&2
        exit 1
    fi
    if readelf -Ws "$interpreter" | awk '$7 != "UND" && $8 ~ /^(dlopen|dlsym|dlclose|dlerror|dladdr|dl_iterate_phdr)$/ { found = 1 } END { exit found ? 0 : 1 }'; then
        printf '%s\n' "ERROR: private interpreter accidentally published a public dlfcn symbol: $interpreter" >&2
        exit 1
    fi
done

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs \
    -Wl,-soname,libleaf-dlfcn.so "$LEAF" -o "$work_dir/libleaf-dlfcn.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-dlfcn.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-dlfcn.so \
    -o "$work_dir/libmid-dlfcn.so"
mkdir -p "$work_dir/link-provider"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-dlfcn.so -Wl,-rpath,"$work_dir" "$MID" "$LINK_PROVIDER" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-dlfcn.so \
    -o "$work_dir/link-provider/libmid-dlfcn.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-dlfcn-dso-import.so -Wl,-rpath,"$work_dir" "$MID" "$DSO_IMPORT" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-dlfcn.so \
    -o "$work_dir/libmid-dlfcn-dso-import.so"

build_candidate_main() {
    local interpreter="$1"
    local output="$2"
    shift 2
    cc "$@" -nostdlib -fPIE -pie -fno-builtin -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "$START" "$MAIN" -L"$work_dir" -Wl,--no-as-needed \
        -l:libmid-dlfcn.so -o "$output"
}

build_candidate_main "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn.so" \
    "$work_dir/main-fixed-graph-dlfcn"
build_candidate_main "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn-malformed.so" \
    "$work_dir/main-fixed-graph-dlfcn-malformed"
build_candidate_main "$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn.so" \
    "$work_dir/main-fixed-graph-dlfcn-strong-import" \
    -DCRABC_FIXED_GRAPH_DLFCN_STRONG_IMPORT=1 -L"$work_dir/link-provider"
cc -nostdlib -fPIE -pie -fno-builtin -fno-stack-protector -ffreestanding \
    -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,--dynamic-linker,"$work_dir/ld-crabc-x86_64-fixed-graph-dlfcn.so" \
    -Wl,-rpath,"$work_dir" "$START" "$MAIN" -L"$work_dir" -Wl,--no-as-needed \
    -l:libmid-dlfcn-dso-import.so -o "$work_dir/main-fixed-graph-dlfcn-dso-import"

"$ORACLE_CC" -fPIE -pie -Wl,--dynamic-linker,"$MUSL_LOADER" \
    -Wl,-rpath,"$work_dir" "$ORACLE_MAIN" -L"$work_dir" -Wl,--no-as-needed \
    -l:libmid-dlfcn.so -ldl -o "$work_dir/main-musl-dlfcn"

for binary in "$work_dir/main-fixed-graph-dlfcn" \
    "$work_dir/main-fixed-graph-dlfcn-malformed" \
    "$work_dir/main-fixed-graph-dlfcn-strong-import" \
    "$work_dir/main-fixed-graph-dlfcn-dso-import" \
    "$work_dir/libmid-dlfcn-dso-import.so" \
    "$work_dir/libmid-dlfcn.so" "$work_dir/libleaf-dlfcn.so"; do
    if readelf -dW "$binary" | grep -Eq '\(NEEDED\).*(libc|libgcc|ld-linux)'; then
        printf '%s\n' "ERROR: fixed-graph dlfcn candidate selected an ambient runtime: $binary" >&2
        exit 1
    fi
    if readelf -lW "$binary" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: fixed-graph dlfcn candidate selected PT_TLS: $binary" >&2
        exit 1
    fi
done

if ! readelf -Ws "$work_dir/main-fixed-graph-dlfcn" | awk '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'ERROR: candidate main lost its weak fixed-graph dlfcn record import' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/main-fixed-graph-dlfcn" | grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1'; then
    printf '%s\n' 'ERROR: candidate main lacks the exact weak GLOB_DAT record relocation' >&2
    exit 1
fi
if ! readelf -Ws "$work_dir/main-fixed-graph-dlfcn-strong-import" | awk '$5 == "GLOBAL" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'ERROR: strong-import negative fixture did not retain a global undefined record' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/main-fixed-graph-dlfcn-strong-import" | grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1'; then
    printf '%s\n' 'ERROR: strong-import negative fixture lacks its record GLOB_DAT' >&2
    exit 1
fi
if ! readelf -Ws "$work_dir/libmid-dlfcn-dso-import.so" | awk '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'ERROR: DSO-import negative fixture did not retain a weak undefined record' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/libmid-dlfcn-dso-import.so" | grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1'; then
    printf '%s\n' 'ERROR: DSO-import negative fixture lacks its record GLOB_DAT' >&2
    exit 1
fi

require_needed() {
    local binary="$1"
    local expected="$2"
    local actual
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    if [ "$actual" != "$expected" ]; then
        printf '%s\n' "ERROR: fixed-graph dlfcn dependency drifted: $binary" >&2
        readelf -dW "$binary" >&2
        exit 1
    fi
}
require_needed "$work_dir/main-fixed-graph-dlfcn" libmid-dlfcn.so
require_needed "$work_dir/main-fixed-graph-dlfcn-strong-import" libmid-dlfcn.so
require_needed "$work_dir/main-fixed-graph-dlfcn-dso-import" libmid-dlfcn-dso-import.so
require_needed "$work_dir/libmid-dlfcn.so" libleaf-dlfcn.so
require_needed "$work_dir/libmid-dlfcn-dso-import.so" libleaf-dlfcn.so
require_needed "$work_dir/libleaf-dlfcn.so" ''

run_clean() {
    local binary="$1"
    env -i PATH=/usr/bin:/bin "$binary"
}

(cd "$work_dir" && run_clean "$work_dir/main-musl-dlfcn")
(cd "$work_dir" && run_clean "$work_dir/main-fixed-graph-dlfcn")

for rejected in "$work_dir/main-fixed-graph-dlfcn-malformed" \
    "$work_dir/main-fixed-graph-dlfcn-strong-import" \
    "$work_dir/main-fixed-graph-dlfcn-dso-import"; do
    set +e
    (cd "$work_dir" && run_clean "$rejected") >/dev/null 2>&1
    rejected_status=$?
    set -e
    if [ "$rejected_status" -ne 127 ]; then
        printf '%s\n' "ERROR: rejected fixed-graph dlfcn contract did not exit 127: $rejected (got $rejected_status)" >&2
        exit 1
    fi
done

printf '%s\n' 'x86 fixed-graph loader handles/symbols/address/snapshot/information: PASS'
