#!/usr/bin/env bash
# Native musl differential for finite dynamic-symbol dladdr metadata.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly BRIDGE_SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_public_dlfcn_start.S"
readonly PROBE="$ROOT_DIR/compat/x86_64/ldso_dladdr_symbol_bounds_probe.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_dladdr_symbol_bounds_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_dladdr_symbol_bounds_dso.c"
readonly EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

fail() { printf 'ERROR: x86 dladdr symbol bounds: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
for tool in ar awk cargo cc cmp grep nm readelf rustc sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl 1.2.6 compiler'
[ -x "$MUSL_LOADER" ] || fail 'missing pinned musl 1.2.6 loader'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-dladdr-symbol-bounds.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
static_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
archive="$work_dir/libcrabc-dladdr-symbol-bounds.a"

build_interpreter() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib --cfg crabc_fixed_graph_dlfcn "$@" \
        -C panic=abort -C relocation-model=pic "$SOURCE" -o "$work_dir/libdladdr-symbol-bounds-ldso.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/libdladdr-symbol-bounds-ldso.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_interpreter "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds.so"
build_interpreter "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds-malformed.so" \
    --cfg crabc_fixed_graph_dlfcn_malformed

for interpreter in "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds.so" \
    "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds-malformed.so"; do
    [ "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "interpreter is not ET_DYN: $interpreter"
    ! readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)|\(RELR\)' ||
        fail "interpreter selected an ambient runtime: $interpreter"
    ! readelf -lW "$interpreter" | grep -q ' TLS ' ||
        fail "interpreter selected PT_TLS: $interpreter"
    readelf -lW "$interpreter" | grep -q GNU_RELRO ||
        fail "interpreter lacks GNU_RELRO: $interpreter"
    readelf -Ws "$interpreter" | awk \
        '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" && $3 == 64 { found=1 } END { exit found ? 0 : 1 }' ||
        fail "interpreter lacks exact 64-byte loader record: $interpreter"
done

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs \
    -Wl,-soname,libleaf-dladdr-symbol-bounds.so "$LEAF" \
    -o "$work_dir/libleaf-dladdr-symbol-bounds.so"
cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-dladdr-symbol-bounds.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-dladdr-symbol-bounds.so \
    -o "$work_dir/libmid-dladdr-symbol-bounds.so"
! readelf -dW "$work_dir/libleaf-dladdr-symbol-bounds.so" | grep -Eq '\(NEEDED\)|\(GNU_HASH\)|\(RUNPATH\)' ||
    fail 'dladdr leaf selected a widened dynamic dependency or tag'
readelf -dW "$work_dir/libleaf-dladdr-symbol-bounds.so" | grep -q '(RELR)' ||
    fail 'dladdr leaf lost its required packed RELR stream'
! readelf -lW "$work_dir/libleaf-dladdr-symbol-bounds.so" | grep -q ' TLS ' ||
    fail 'dladdr leaf selected PT_TLS'
readelf --dyn-syms -W "$work_dir/libleaf-dladdr-symbol-bounds.so" | awk \
    '$4 == "OBJECT" && $5 == "GLOBAL" && $8 == "dladdr_bounded_data" && $3 == 4 { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'dladdr fixture lost its exact four-byte public dynamic object'

"$ORACLE_CC" -std=c11 -fPIE -pie -fno-builtin \
    -Wl,--dynamic-linker,"$MUSL_LOADER" -Wl,-rpath,"$work_dir" \
    "$PROBE" -L"$work_dir" -Wl,--no-as-needed -l:libmid-dladdr-symbol-bounds.so \
    -ldl -o "$work_dir/main-musl-dladdr-symbol-bounds"

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$static_archive" ] || fail 'cargo did not emit staged static x86 libc.a'

members_dir="$work_dir/members"
mkdir "$members_dir"
mapfile -t members < <(ar t "$static_archive" | grep -E '^c\..+\.rcgu\.o$')
[ "${#members[@]}" -gt 0 ] || fail 'archive has no crabc-libc members'
(
    cd "$members_dir"
    ar x "$static_archive" "${members[@]}"
    nm -g --defined-only --format=posix "${members[@]}"
) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
    sort -u >"$work_dir/actual-exports"
grep -Ev '^(#|$)' "$EXPORTS" | LC_ALL=C sort -u >"$work_dir/expected-exports"
cmp "$work_dir/expected-exports" "$work_dir/actual-exports" ||
    fail 'staged static C ABI export surface drifted'
for symbol in dl_iterate_phdr dladdr dlclose dlerror dlinfo dlopen dlsym; do
    grep -Fxq "$symbol" "$work_dir/actual-exports" || fail "archive lacks $symbol"
done

rustc --edition=2021 --crate-type staticlib -C relocation-model=pic \
    -C code-model=small -C panic=abort "$BRIDGE_SOURCE" -o "$archive"
[ -f "$archive" ] || fail 'rustc did not emit isolated PIC public dlfcn bridge'

build_main() {
    local interpreter="$1"
    local output="$2"
    shift 2
    "$ORACLE_CC" -std=c11 -DCRABC_DLADDR_SYMBOL_BOUNDS_FREESTANDING=1 "$@" \
        -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
        -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
        -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
        -Wl,-rpath,"$work_dir" "$START" "$PROBE" "$archive" \
        -L"$work_dir" -Wl,--no-as-needed -l:libmid-dladdr-symbol-bounds.so -o "$output"
}

build_main "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds.so" \
    "$work_dir/main-crabc-dladdr-symbol-bounds"
build_main "$work_dir/ld-crabc-x86_64-dladdr-symbol-bounds-malformed.so" \
    "$work_dir/main-crabc-dladdr-symbol-bounds-malformed" \
    -DCRABC_DLADDR_SYMBOL_BOUNDS_UNAVAILABLE=1
build_main "$MUSL_LOADER" "$work_dir/main-crabc-dladdr-symbol-bounds-absent" \
    -DCRABC_DLADDR_SYMBOL_BOUNDS_UNAVAILABLE=1

for candidate in "$work_dir/main-crabc-dladdr-symbol-bounds" \
    "$work_dir/main-crabc-dladdr-symbol-bounds-malformed"; do
    [ "$(readelf -h "$candidate" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "candidate is not ET_DYN: $candidate"
    ! readelf -dW "$candidate" | grep -Eq '\(NEEDED\).*(libc|libgcc|ld-linux)' ||
        fail "candidate selected an ambient runtime: $candidate"
    ! readelf -lW "$candidate" | grep -q ' TLS ' ||
        fail "candidate selected PT_TLS: $candidate"
    readelf -Ws "$candidate" | awk \
        '$7 != "UND" && $8 == "dladdr" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "candidate lacks defined dladdr: $candidate"
done
readelf -Ws "$work_dir/main-crabc-dladdr-symbol-bounds" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'candidate lost weak loader-record import'
readelf -rW "$work_dir/main-crabc-dladdr-symbol-bounds" |
    grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1' ||
    fail 'candidate lacks loader-record GLOB_DAT'

require_needed() {
    local binary="$1" expected="$2" actual
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    [ "$actual" = "$expected" ] || fail "DT_NEEDED drifted for $binary: $actual"
}
require_needed "$work_dir/main-crabc-dladdr-symbol-bounds" libmid-dladdr-symbol-bounds.so
require_needed "$work_dir/main-crabc-dladdr-symbol-bounds-malformed" libmid-dladdr-symbol-bounds.so
require_needed "$work_dir/libmid-dladdr-symbol-bounds.so" libleaf-dladdr-symbol-bounds.so
require_needed "$work_dir/libleaf-dladdr-symbol-bounds.so" ''

run_clean() { env -i PATH=/usr/bin:/bin "$1"; }
set +e
(cd "$work_dir" && run_clean "$work_dir/main-musl-dladdr-symbol-bounds")
status=$?
set -e
if [ "$status" -ne 0 ]; then
    fail "pinned-musl finite-symbol dladdr differential failed with status $status"
fi
set +e
(cd "$work_dir" && run_clean "$work_dir/main-crabc-dladdr-symbol-bounds")
status=$?
set -e
if [ "$status" -ne 0 ]; then
    fail "crabc finite-symbol dladdr behavior failed with status $status"
fi
set +e
(cd "$work_dir" && run_clean "$work_dir/main-crabc-dladdr-symbol-bounds-malformed")
status=$?
set -e
if [ "$status" -ne 0 ]; then
    fail "malformed loader record did not fail closed through dladdr with status $status"
fi
set +e
(cd "$work_dir" && run_clean "$work_dir/main-crabc-dladdr-symbol-bounds-absent")
status=$?
set -e
if [ "$status" -ne 0 ]; then
    fail "absent loader record fell back to ambient dladdr with status $status"
fi

printf '%s\n' 'x86 fixed-graph dladdr finite-symbol bounds: PASS'
