#!/usr/bin/env bash
# Native public-C bridge evidence over the loader-owned immutable x86 graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly BRIDGE_SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/fixed_graph_dlfcn_runtime.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_public_dlfcn_start.S"
readonly PROBE="$ROOT_DIR/compat/x86_64/ldso_public_dlfcn_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/ldso_public_dlfcn_header_probe.cpp"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

fail() { printf 'ERROR: x86 public fixed-graph dlfcn: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
for tool in ar awk cargo c++ cc cmp grep nm readelf rustc sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl 1.2.6 compiler'
[ -x "$MUSL_LOADER" ] || fail 'missing pinned musl 1.2.6 loader'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-public-dlfcn.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
static_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
archive="$work_dir/libcrabc-public-dlfcn.a"

build_interpreter() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib --cfg crabc_fixed_graph_dlfcn "$@" \
        -C panic=abort -C relocation-model=pic "$SOURCE" -o "$work_dir/libpublic-dlfcn-ldso.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/libpublic-dlfcn-ldso.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_interpreter "$work_dir/ld-crabc-x86_64-public-dlfcn.so"
build_interpreter "$work_dir/ld-crabc-x86_64-public-dlfcn-malformed.so" \
    --cfg crabc_fixed_graph_dlfcn_malformed

for interpreter in "$work_dir/ld-crabc-x86_64-public-dlfcn.so" \
    "$work_dir/ld-crabc-x86_64-public-dlfcn-malformed.so"; do
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
    if readelf -Ws "$interpreter" | awk \
        '$7 != "UND" && $8 ~ /^(dlopen|dlsym|dlclose|dlerror|dladdr|dlinfo|dl_iterate_phdr)$/ { found=1 } END { exit found ? 0 : 1 }'; then
        fail "interpreter published a public dlfcn symbol: $interpreter"
    fi
done

cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now -Wl,-z,pack-relative-relocs \
    -Wl,-soname,libleaf-public-dlfcn.so "$LEAF" -o "$work_dir/libleaf-public-dlfcn.so"
cc -DCRABC_FIXED_GRAPH_DLFCN=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv \
    -Wl,-z,now -Wl,-soname,libmid-public-dlfcn.so -Wl,-rpath,"$work_dir" \
    "$MID" -L"$work_dir" -Wl,--no-as-needed -l:libleaf-public-dlfcn.so \
    -o "$work_dir/libmid-public-dlfcn.so"

"$ORACLE_CC" -std=c11 -fPIE -pie -fno-builtin \
    -Wl,--dynamic-linker,"$MUSL_LOADER" -Wl,-rpath,"$work_dir" \
    "$PROBE" -L"$work_dir" -Wl,--no-as-needed -l:libmid-public-dlfcn.so \
    -pthread -ldl -o "$work_dir/main-musl-public-dlfcn"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    "$PROBE" >/dev/null 2>"$work_dir/header-trace"
for header in dlfcn.h link.h elf.h stddef.h stdint.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$work_dir/header-trace" ||
        fail "public fixture did not use project $header"
done
c++ -std=c++17 -I"$ROOT_DIR/include" -ffreestanding -fno-exceptions \
    -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit -nostdinc++ \
    -c "$CXX_PROBE" -o "$work_dir/public-dlfcn-header-cxx.o"
nm --undefined-only "$work_dir/public-dlfcn-header-cxx.o" | awk '{print $NF}' \
    >"$work_dir/public-dlfcn-header-cxx-undefined"
for symbol in dl_iterate_phdr dladdr dlclose dlerror dlinfo dlopen dlsym; do
    grep -Fxq "$symbol" "$work_dir/public-dlfcn-header-cxx-undefined" ||
        fail "C++ header probe lost C linkage for $symbol"
done

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
for symbol in __crabc_x86_fixed_graph_dlfcn_record dl_iterate_phdr dladdr dlclose \
    dlerror dlinfo dlopen dlsym; do
    grep -Fxq "$symbol" "$work_dir/actual-exports" || fail "archive lacks $symbol"
done
readelf -Ws "$members_dir"/*.o | awk \
    '$4 == "FUNC" && $5 == "WEAK" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'staged static archive lost musl weak dl_iterate_phdr binding'
if readelf -Ws "$members_dir"/*.o | awk \
    '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }'; then
    fail 'staged static archive made dl_iterate_phdr strong'
fi
readelf -Ws "$members_dir"/*.o | awk \
    '$4 == "FUNC" && $5 == "WEAK" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'staged static archive lost musl weak dlopen binding'
if readelf -Ws "$members_dir"/*.o | awk \
    '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }'; then
    fail 'staged static archive made dlopen strong'
fi

rustc --edition=2021 --crate-type staticlib -C relocation-model=pic \
    -C code-model=small -C panic=abort "$BRIDGE_SOURCE" -o "$archive"
[ -f "$archive" ] || fail 'rustc did not emit isolated PIC public dlfcn bridge'

build_main() {
    local interpreter="$1"
    local output="$2"
    shift 2
    "$ORACLE_CC" -std=c11 -DCRABC_PUBLIC_DLFCN_FREESTANDING=1 "$@" \
        -I"$ROOT_DIR/include" -nostdlib -fPIE -pie -ffreestanding -fno-builtin \
        -fno-stack-protector -fno-asynchronous-unwind-tables -Wl,--hash-style=sysv \
        -Wl,-z,now -Wl,--no-undefined -Wl,--dynamic-linker,"$interpreter" \
        -Wl,-rpath,"$work_dir" "$START" "$PROBE" "$archive" \
        -L"$work_dir" -Wl,--no-as-needed -l:libmid-public-dlfcn.so -o "$output"
}

build_main "$work_dir/ld-crabc-x86_64-public-dlfcn.so" \
    "$work_dir/main-crabc-public-dlfcn"
build_main "$work_dir/ld-crabc-x86_64-public-dlfcn-malformed.so" \
    "$work_dir/main-crabc-public-dlfcn-malformed" -DCRABC_PUBLIC_DLFCN_MALFORMED=1
build_main "$MUSL_LOADER" "$work_dir/main-crabc-public-dlfcn-absent" \
    -DCRABC_PUBLIC_DLFCN_MALFORMED=1
build_main "$work_dir/ld-crabc-x86_64-public-dlfcn.so" \
    "$work_dir/main-crabc-public-dlfcn-override" -DCRABC_PUBLIC_DLFCN_OVERRIDE_ITERATE=1
build_main "$work_dir/ld-crabc-x86_64-public-dlfcn.so" \
    "$work_dir/main-crabc-public-dlfcn-override-open" -DCRABC_PUBLIC_DLFCN_OVERRIDE_OPEN=1

for candidate in "$work_dir/main-crabc-public-dlfcn" \
    "$work_dir/main-crabc-public-dlfcn-malformed" \
    "$work_dir/main-crabc-public-dlfcn-override" \
    "$work_dir/main-crabc-public-dlfcn-override-open"; do
    [ "$(readelf -h "$candidate" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "public candidate is not ET_DYN: $candidate"
    ! readelf -dW "$candidate" | grep -Eq '\(NEEDED\).*(libc|libgcc|ld-linux)' ||
        fail "public candidate selected an ambient runtime: $candidate"
    if readelf -lW "$candidate" | grep -q ' TLS '; then
        readelf -Ws "$candidate" | awk '$4 == "TLS" { print }' >&2
        fail "public candidate selected PT_TLS: $candidate"
    fi
    for symbol in dl_iterate_phdr dladdr dlclose dlerror dlinfo dlopen dlsym; do
        readelf -Ws "$candidate" | awk -v symbol="$symbol" \
            '$7 != "UND" && $8 == symbol { found=1 } END { exit found ? 0 : 1 }' ||
            fail "public candidate lacks defined $symbol"
    done
done
for candidate in "$work_dir/main-crabc-public-dlfcn" \
    "$work_dir/main-crabc-public-dlfcn-malformed"; do
    readelf -Ws "$candidate" | awk \
        '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "public candidate lost musl weak dl_iterate_phdr binding: $candidate"
    if readelf -Ws "$candidate" | awk \
        '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }'; then
        fail "public candidate made dl_iterate_phdr strong: $candidate"
    fi
    readelf -Ws "$candidate" | awk \
        '$4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "public candidate lost musl weak dlopen binding: $candidate"
    if readelf -Ws "$candidate" | awk \
        '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }'; then
        fail "public candidate made dlopen strong: $candidate"
    fi
done
readelf -Ws "$work_dir/main-crabc-public-dlfcn-override" | awk \
    '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'caller strong dl_iterate_phdr did not override the archive weak binding'
if readelf -Ws "$work_dir/main-crabc-public-dlfcn-override" | awk \
    '$4 == "FUNC" && $5 == "WEAK" && $7 != "UND" && $8 == "dl_iterate_phdr" { found=1 } END { exit found ? 0 : 1 }'; then
    fail 'caller override retained the archive weak dl_iterate_phdr binding'
fi
readelf -Ws "$work_dir/main-crabc-public-dlfcn-override-open" | awk \
    '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'caller strong dlopen did not override the archive weak binding'
if readelf -Ws "$work_dir/main-crabc-public-dlfcn-override-open" | awk \
    '$4 == "FUNC" && $5 == "WEAK" && $7 != "UND" && $8 == "dlopen" { found=1 } END { exit found ? 0 : 1 }'; then
    fail 'caller override retained the archive weak dlopen binding'
fi
readelf -Ws "$work_dir/main-crabc-public-dlfcn" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_fixed_graph_dlfcn_v1" { found=1 } END { exit found ? 0 : 1 }' ||
    fail 'public candidate lost weak loader-record import'
readelf -rW "$work_dir/main-crabc-public-dlfcn" |
    grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_fixed_graph_dlfcn_v1' ||
    fail 'public candidate lacks loader-record GLOB_DAT'

require_needed() {
    local binary="$1" expected="$2" actual
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    [ "$actual" = "$expected" ] || fail "DT_NEEDED drifted for $binary: $actual"
}
require_needed "$work_dir/main-crabc-public-dlfcn" libmid-public-dlfcn.so
require_needed "$work_dir/main-crabc-public-dlfcn-malformed" libmid-public-dlfcn.so
require_needed "$work_dir/libmid-public-dlfcn.so" libleaf-public-dlfcn.so
require_needed "$work_dir/libleaf-public-dlfcn.so" ''

run_clean() { env -i PATH=/usr/bin:/bin "$1"; }
(cd "$work_dir" && run_clean "$work_dir/main-musl-public-dlfcn") ||
    fail 'pinned-musl public dlfcn differential failed'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-public-dlfcn") ||
    fail 'crabc public fixed-graph dlfcn behavior failed'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-public-dlfcn-malformed") ||
    fail 'malformed loader record did not fail closed through public dlfcn'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-public-dlfcn-absent") ||
    fail 'absent loader record fell back to the ambient musl loader'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-public-dlfcn-override") ||
    fail 'caller strong dl_iterate_phdr did not override the archive weak binding'
(cd "$work_dir" && run_clean "$work_dir/main-crabc-public-dlfcn-override-open") ||
    fail 'caller strong dlopen did not override the archive weak binding'

printf '%s\n' 'x86 public C fixed-graph dlfcn ABI/diagnostics/introspection: PASS'
