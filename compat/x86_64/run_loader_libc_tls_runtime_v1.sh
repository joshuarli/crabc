#!/usr/bin/env bash
# Native evidence for the first private x86 loader/libc TLS RuntimeV1 wire.
#
# This is one initial-TLS fixed-graph handoff, not an installed dynamic
# product.  It proves that a freestanding libc consumer rejects a missing or
# malformed loader record before TLS access, then accepts one loader-owned
# initial graph after `%fs` and its bounded DTV are installed.  Runtime DSO
# TLS, DTV growth, pthread worker materialization, unload, and general CRT
# integration remain deliberately outside this artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly LOADER_SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_initial_graph_source_root.rs"
readonly CONSUMER_SOURCE_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly MAIN="$ROOT_DIR/compat/x86_64/loader_libc_tls_runtime_v1_main.c"
readonly STATIC_MAIN="$ROOT_DIR/compat/x86_64/loader_libc_tls_runtime_v1_static_main.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_tls_mid.c"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_tls_leaf.c"
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

fail() {
    printf 'ERROR: x86 loader/libc TLS RuntimeV1: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
for tool in cc grep readelf rustc; do require_tool "$tool"; done
[ -x "$MUSL_LOADER" ] || fail 'requires the pinned musl 1.2.6 loader'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-loader-libc-tls-runtime-v1.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

build_loader() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        --cfg crabc_initial_tls_graph --cfg crabc_loader_libc_tls_runtime_v1 "$@" \
        "$LOADER_SOURCE_ROOT" -o "$work_dir/loader.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/loader.a" -Wl,--no-whole-archive -o "$output"
}

build_consumer() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic "$@" \
        "$CONSUMER_SOURCE_ROOT" -o "$output"
}

build_loader "$work_dir/ld-runtime-v1.so"
for malformed in magic version abi_size mode owner generation; do
    build_loader "$work_dir/ld-runtime-v1-bad-$malformed.so" \
        --cfg "crabc_loader_libc_tls_runtime_v1_bad_$malformed"
done
build_loader "$work_dir/ld-runtime-v1-poisoned-dtv.so" \
    --cfg crabc_loader_libc_tls_runtime_v1_poisoned_dtv
build_consumer "$work_dir/libconsumer.a"
build_consumer "$work_dir/libconsumer-static.a" --cfg crabc_loader_libc_tls_runtime_v1_static_mode

for interpreter in "$work_dir"/ld-runtime-v1*.so; do
    [ "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "interpreter is not ET_DYN: $interpreter"
    ! readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)' ||
        fail "interpreter selected an ambient runtime: $interpreter"
    ! readelf -lW "$interpreter" | grep -q ' TLS ' ||
        fail "interpreter selected its own PT_TLS: $interpreter"
done
readelf --syms -W "$work_dir/ld-runtime-v1.so" | awk \
    '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" && $3 == 72 { found = 1 } END { exit found ? 0 : 1 }' ||
    fail 'valid interpreter lacks the exact 72-byte private RuntimeV1 TLS record'
if readelf --dyn-syms -W "$work_dir/ld-runtime-v1.so" | awk \
    '$8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'private RuntimeV1 TLS record leaked into the interpreter dynamic symbol table'
fi

cc -fPIC -shared -nostdlib -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf-runtime-v1.so "$LEAF" \
    -o "$work_dir/libleaf-runtime-v1.so"
cc -fPIC -shared -nostdlib -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-runtime-v1.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-runtime-v1.so \
    -o "$work_dir/libmid-runtime-v1.so"

build_dynamic_main() {
    local interpreter="$1"
    local output="$2"
    local mode="$3"
    local -a defines=()
    if [ "$mode" = reject ]; then
        defines+=(-DCRABC_RUNTIME_V1_REJECT=1)
    fi
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -mtls-dialect=gnu -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,--allow-shlib-undefined -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "${defines[@]}" "$START" "$MAIN" "$work_dir/libconsumer.a" -L"$work_dir" \
        -Wl,--no-as-needed -l:libmid-runtime-v1.so -o "$output"
}

build_dynamic_main "$work_dir/ld-runtime-v1.so" "$work_dir/main-valid" accept
for malformed in magic version abi_size mode owner generation; do
    build_dynamic_main "$work_dir/ld-runtime-v1-bad-$malformed.so" \
        "$work_dir/main-bad-$malformed" reject
done
build_dynamic_main "$work_dir/ld-runtime-v1-poisoned-dtv.so" \
    "$work_dir/main-poisoned-dtv" reject

if ! readelf -Ws "$work_dir/main-valid" | awk \
    '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'dynamic libc consumer lost its exact weak loader record import'
fi
if ! readelf -rW "$work_dir/main-valid" | grep -Eq \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_loader_tls_runtime_v1'; then
    fail 'dynamic libc consumer lacks the checked RuntimeV1 record GOT relocation'
fi

env -i PATH=/usr/bin:/bin "$work_dir/main-valid"
for malformed in magic version abi_size mode owner generation; do
    env -i PATH=/usr/bin:/bin "$work_dir/main-bad-$malformed"
done
env -i PATH=/usr/bin:/bin "$work_dir/main-poisoned-dtv"

# A no-PT_INTERP executable cannot acquire a loader-owned descriptor.  Its
# separately compiled consumer stub returns rejection without a weak loader
# import or an FS access path, preserving Static Initial TLS v1 ownership.
cc -nostdlib -no-pie -fno-stack-protector -ffreestanding -fno-asynchronous-unwind-tables \
    -Wl,-e,_start "$START" "$STATIC_MAIN" "$work_dir/libconsumer-static.a" \
    -o "$work_dir/main-static"
if readelf -lW "$work_dir/main-static" | grep -q 'Requesting program interpreter'; then
    fail 'static-mode negative fixture unexpectedly gained PT_INTERP'
fi
if readelf -dW "$work_dir/main-static" | grep -Eq '\(NEEDED\)|\(INTERP\)'; then
    fail 'static-mode negative fixture selected a dynamic runtime'
fi
if readelf -Ws "$work_dir/main-static" | awk \
    '$7 == "UND" && $8 == "__crabc_x86_64_loader_tls_runtime_v1" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'static-mode consumer retained a loader record import'
fi
env -i PATH=/usr/bin:/bin "$work_dir/main-static"

printf '%s\n' 'x86 loader/libc TLS RuntimeV1 private descriptor handoff: PASS'
