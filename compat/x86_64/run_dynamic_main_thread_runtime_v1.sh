#!/usr/bin/env bash
# Native evidence for the private x86 dynamic main-thread RuntimeV1 bridge.
#
# One real Rust-produced Scrt1.o attaches the main-resident RuntimeV1 consumer
# before one private dynamic libc receives __libc_start_main.  This is not an
# installed interpreter/libc product, an owned-CRT carrier, loader-owned
# finalization, dependency-lifecycle handoff, dlopen/unload, worker TLS, or
# DTV-growth implementation.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly LOADER_SOURCE_ROOT="$ROOT_DIR/ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs"
readonly CONSUMER_SOURCE_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs"
readonly DYNAMIC_LIBC_SOURCE_ROOT="$ROOT_DIR/libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs"
readonly CRT_BUILD="$ROOT_DIR/crt/build_x86_64.py"
readonly MAIN="$ROOT_DIR/compat/x86_64/dynamic_main_thread_runtime_v1_main.c"
readonly VERSION_SCRIPT="$ROOT_DIR/compat/x86_64/dynamic_main_thread_runtime_v1.map"
readonly STRONG_MAIN_RECORD="$ROOT_DIR/compat/x86_64/dynamic_main_thread_runtime_v1_strong_owned_crt_record.c"
readonly WEAK_DSO_RECORD="$ROOT_DIR/compat/x86_64/dynamic_main_thread_runtime_v1_weak_dso_owned_crt_record.c"
readonly DEFINITION_DSO="$ROOT_DIR/compat/x86_64/dynamic_main_thread_runtime_v1_owned_crt_record_definition.c"
readonly TRACE="$ROOT_DIR/compat/x86_64/ldso_general_initial_tls_trace.c"

fail() {
    printf 'ERROR: x86 dynamic main-thread RuntimeV1: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

if [ "$(uname -s)" != Linux ]; then
    fail 'requires native Linux'
fi
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail 'requires native x86-64' ;;
esac
for tool in awk cc cargo grep python3 readelf rustc rustup; do
    require_tool "$tool"
done

# Keep the pinned musl oracle and prior arbitrary-general RuntimeV1 graph as
# independent prerequisites. Neither describes this private Scrt1/libc seam.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_loader_libc_general_tls_runtime_v1.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-dynamic-main-thread-runtime-v1.XXXXXX)"
if [ "${CRABC_DYNAMIC_MAIN_THREAD_RUNTIME_V1_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained dynamic main-thread RuntimeV1 work directory: $work_dir" >&2
else
    trap 'rm -rf -- "$work_dir"' EXIT
fi

build_source_loader() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        --cfg crabc_general_initial_graph \
        --cfg crabc_general_initial_tls_materialization_v1 \
        --cfg crabc_general_loader_libc_tls_runtime_v1 \
        --cfg crabc_dynamic_main_thread_runtime_v1 \
        "$@" "$LOADER_SOURCE_ROOT" -o "$work_dir/loader.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/loader.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_cargo_loader() {
    local output="$1"
    local target_dir="$work_dir/ldso-target"
    CARGO_TARGET_DIR="$target_dir" \
    RUSTFLAGS='-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic' \
        cargo build --locked --target x86_64-unknown-linux-musl -p crabc-ldso \
            --no-default-features \
            --features x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter
    cp "$target_dir/x86_64-unknown-linux-musl/debug/libldso.so" "$output"
}

build_consumer() {
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        "$CONSUMER_SOURCE_ROOT" -o "$work_dir/main-consumer.a"
}

build_dynamic_libc() {
    rustc --edition=2021 --crate-type staticlib -C panic=abort -C relocation-model=pic \
        "$DYNAMIC_LIBC_SOURCE_ROOT" -o "$work_dir/dynamic-libc.a"
    cc -nostdlib -shared -Wl,--version-script,"$VERSION_SCRIPT" \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,-soname,libcrabc-dynamic-main-thread-runtime-v1.so \
        -Wl,--whole-archive "$work_dir/dynamic-libc.a" -Wl,--no-whole-archive \
        -o "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so"
}

build_definition_dso() {
    cc -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
        -Wl,-soname,libowned-crt-record-definition.so "$DEFINITION_DSO" \
        -o "$work_dir/libowned-crt-record-definition.so"
}

case "${CRABC_DYNAMIC_MAIN_THREAD_RUNTIME_V1_LOADER_ROOT:-source}" in
    source)
        build_source_loader "$work_dir/ld-dynamic-main-thread-runtime-v1.so"
        ;;
    crabc-target)
        build_cargo_loader "$work_dir/ld-dynamic-main-thread-runtime-v1.so"
        ;;
    *)
        fail 'unsupported dynamic main-thread RuntimeV1 root selection'
        ;;
esac

# Direct source-root variants isolate the private consumer's malformed-record
# checks. The target-root command proves Cargo's positive root independently.
for malformed in magic version abi_size mode owner generation; do
    build_source_loader "$work_dir/ld-dynamic-main-thread-runtime-v1-bad-$malformed.so" \
        --cfg "crabc_general_loader_libc_tls_runtime_v1_bad_$malformed"
done
build_source_loader "$work_dir/ld-dynamic-main-thread-runtime-v1-poisoned-dtv.so" \
    --cfg crabc_general_loader_libc_tls_runtime_v1_poisoned_dtv
build_consumer
build_dynamic_libc
build_definition_dso

if command -v llvm-objdump >/dev/null 2>&1; then
    llvm_objdump="$(command -v llvm-objdump)"
else
    rust_sysroot="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
    llvm_objdump="$rust_sysroot/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump"
fi
[ -x "$llvm_objdump" ] || fail 'requires the pinned Rust llvm-objdump'
python3 "$CRT_BUILD" --dynamic-main-thread-runtime-v1 --out-dir "$work_dir/crt" \
    --llvm-objdump "$llvm_objdump" >"$work_dir/crt.json"

cc -fPIC -fno-stack-protector -ffreestanding -fno-asynchronous-unwind-tables \
    -c "$STRONG_MAIN_RECORD" -o "$work_dir/strong-main-owned-record.o"
cc -fPIC -shared -nostdlib -Wl,--version-script,"$VERSION_SCRIPT" \
    -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
    -Wl,-soname,libcrabc-dynamic-main-thread-runtime-v1.so \
    "$WEAK_DSO_RECORD" -Wl,--whole-archive "$work_dir/dynamic-libc.a" \
    -Wl,--no-whole-archive \
    -o "$work_dir/libcrabc-dynamic-main-thread-runtime-v1-weak-owned-record.so"

build_main() {
    local interpreter="$1"
    local output="$2"
    local main_record="$3"
    local definition="$4"
    local -a record_objects=()
    local -a dynamic_exports=(
        -Wl,--export-dynamic-symbol=__crabc_dynamic_main_thread_runtime_v1_fini_state
    )
    local -a dso_arguments=(
        -L"$work_dir" -Wl,--no-as-needed
        -l:libcrabc-dynamic-main-thread-runtime-v1.so
    )
    if [ "$main_record" = strong ]; then
        record_objects+=("$work_dir/strong-main-owned-record.o")
        dynamic_exports+=(
            -Wl,--export-dynamic-symbol=__crabc_x86_64_owned_crt_handoff
        )
    fi
    if [ "$definition" = present ]; then
        dso_arguments+=( -l:libowned-crt-record-definition.so )
    fi
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding \
        -fno-asynchronous-unwind-tables -ftls-model=global-dynamic -mtls-dialect=gnu \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--allow-shlib-undefined \
        -Wl,--unresolved-symbols=ignore-all "${dynamic_exports[@]}" \
        -Wl,--dynamic-linker,"$interpreter" -Wl,-rpath,"$work_dir" \
        "$work_dir/crt/Scrt1.o" "$work_dir/crt/crti.o" "$MAIN" "${record_objects[@]}" \
        -Wl,--whole-archive "$work_dir/main-consumer.a" -Wl,--no-whole-archive \
        "${dso_arguments[@]}" "$work_dir/crt/crtn.o" -o "$output"
}

build_main "$work_dir/ld-dynamic-main-thread-runtime-v1.so" \
    "$work_dir/main-valid" ordinary absent
for malformed in magic version abi_size mode owner generation; do
    build_main "$work_dir/ld-dynamic-main-thread-runtime-v1-bad-$malformed.so" \
        "$work_dir/main-bad-$malformed" ordinary absent
done
build_main "$work_dir/ld-dynamic-main-thread-runtime-v1-poisoned-dtv.so" \
    "$work_dir/main-poisoned-dtv" ordinary absent
build_main "$work_dir/ld-dynamic-main-thread-runtime-v1.so" \
    "$work_dir/main-strong-owned-record" strong absent
build_main "$work_dir/ld-dynamic-main-thread-runtime-v1.so" \
    "$work_dir/main-owned-record-definition" ordinary present

require_needed_names() {
    local binary="$1"
    shift
    local actual expected=''
    actual="$(readelf -dW "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
    for name in "$@"; do
        if [ -n "$expected" ]; then expected+=$'\n'; fi
        expected+="$name"
    done
    if [ "$actual" != "$expected" ]; then
        fail "unexpected DT_NEEDED graph in $binary"
    fi
}

require_weak_main_got_import() {
    local binary="$1"
    local symbol="$2"
    if ! readelf -Ws "$binary" | awk -v symbol="$symbol" \
        '$5 == "WEAK" && $7 == "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "missing exact weak undefined main-image import: $symbol"
    fi
    if ! readelf -rW "$binary" | grep -Eq "R_X86_64_GLOB_DAT.*${symbol}"; then
        fail "missing exact main-image GLOB_DAT relocation: $symbol"
    fi
}

for interpreter in "$work_dir"/ld-dynamic-main-thread-runtime-v1*.so; do
    [ "$(readelf -h "$interpreter" | awk '/Type:/{print $2}')" = DYN ] ||
        fail "interpreter is not ET_DYN: $interpreter"
    ! readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)' ||
        fail "interpreter selected an ambient runtime: $interpreter"
    ! readelf -lW "$interpreter" | grep -q ' TLS ' ||
        fail "interpreter selected its own PT_TLS: $interpreter"
done

require_needed_names "$work_dir/main-valid" libcrabc-dynamic-main-thread-runtime-v1.so
require_needed_names "$work_dir/main-owned-record-definition" \
    libcrabc-dynamic-main-thread-runtime-v1.so libowned-crt-record-definition.so
for main in "$work_dir/main-valid" "$work_dir/main-owned-record-definition"; do
    readelf -lW "$main" | grep -q 'Requesting program interpreter' ||
        fail "main lacks PT_INTERP: $main"
    readelf -lW "$main" | grep -q ' TLS ' || fail "main lacks PT_TLS: $main"
    for tag in INIT FINI PREINIT_ARRAY PREINIT_ARRAYSZ INIT_ARRAY INIT_ARRAYSZ FINI_ARRAY FINI_ARRAYSZ; do
        readelf -dW "$main" | grep -q "($tag)" ||
            fail "real Scrt1 main lost DT_$tag: $main"
    done
    require_weak_main_got_import "$main" __crabc_x86_64_owned_crt_handoff
    require_weak_main_got_import "$main" __crabc_x86_64_loader_tls_runtime_v1
done
if ! readelf -Ws "$work_dir/main-strong-owned-record" | awk \
    '$5 == "GLOBAL" && $7 == "UND" && $8 == "__crabc_x86_64_owned_crt_handoff" { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'strong owned-CRT main import was not retained'
fi
if ! readelf -rW "$work_dir/main-strong-owned-record" | grep -Eq \
    'R_X86_64_GLOB_DAT.*__crabc_x86_64_owned_crt_handoff'; then
    fail 'strong owned-CRT main import lacks its GLOB_DAT relocation'
fi

require_needed_names "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so"
readelf -lW "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" | grep -q ' TLS ' ||
    fail 'private dynamic libc lacks PT_TLS errno'
! readelf -dW "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" | grep -Eq \
    '\(SYMBOLIC\)|\(GNU_HASH\)|\(INIT\)|\(FINI\)|\(PREINIT_ARRAY\)|\(INIT_ARRAY\)|\(FINI_ARRAY\)' ||
    fail 'private dynamic libc selected unsupported lookup or lifecycle tags'
for symbol in __errno_location __libc_start_main; do
    if ! readelf --dyn-syms -W "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" | awk \
        -v symbol="$symbol" '$5 == "GLOBAL" && $7 != "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "private dynamic libc lost exported startup boundary: $symbol"
    fi
done
for symbol in __tls_get_addr __crabc_dynamic_main_thread_runtime_v1_fini_state; do
    if ! readelf --dyn-syms -W "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" | awk \
        -v symbol="$symbol" '$7 == "UND" && $8 == symbol { found = 1 } END { exit found ? 0 : 1 }'; then
        fail "private dynamic libc lost required undefined import: $symbol"
    fi
done
if ! readelf -rW "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" | awk '
    $3 ~ /^R_X86_64_/ {
        saw = 1
        if ($3 != "R_X86_64_RELATIVE" && $3 != "R_X86_64_GLOB_DAT" \
            && $3 != "R_X86_64_JUMP_SLOT" && $3 != "R_X86_64_DTPMOD64" \
            && $3 != "R_X86_64_DTPOFF64") bad = 1
    }
    END { exit saw && !bad ? 0 : 1 }
'; then
    fail 'private dynamic libc has an unsupported relocation vocabulary'
fi
if ! readelf -Ws "$work_dir/libowned-crt-record-definition.so" | awk \
    '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_owned_crt_handoff" && $3 == 32 { found = 1 } END { exit found ? 0 : 1 }'; then
    fail 'non-promotion DSO lost its recognizable owned-CRT record definition'
fi

run_clean() {
    local binary="$1"
    env -i PATH=/usr/bin:/bin "$binary"
}

valid_output="$(cd "$work_dir" && run_clean "$work_dir/main-valid")"
if [ "$valid_output" != PIMFL ]; then
    fail "dynamic main-thread lifecycle/TLS/errno result drifted: $valid_output"
fi

# A DSO definition of the exact optional owned-CRT name must not interpose.
# If it did, the dynamic libc's required-null rtld_fini check would reject.
definition_output="$(cd "$work_dir" && run_clean "$work_dir/main-owned-record-definition")"
if [ "$definition_output" != PIMFL ]; then
    fail "owned-CRT definition escaped the null Scrt1 handoff path: $definition_output"
fi

expect_empty_status_127() {
    local binary="$1"
    local label="$2"
    local output status
    set +e
    output="$(cd "$work_dir" && run_clean "$binary" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 127 ] || [ -n "$output" ]; then
        fail "$label did not reject before callbacks with empty output (status $status; output: $output)"
    fi
}

for malformed in magic version abi_size mode owner generation; do
    expect_empty_status_127 "$work_dir/main-bad-$malformed" "malformed RuntimeV1 $malformed"
done
expect_empty_status_127 "$work_dir/main-poisoned-dtv" 'poisoned RuntimeV1 DTV'

cc -D_GNU_SOURCE -std=c11 "$TRACE" -o "$work_dir/no-arch-set-fs-trace"
expect_rejection_before_fs() {
    local binary="$1"
    local label="$2"
    local output status
    set +e
    output="$(cd "$work_dir" && env -i PATH=/usr/bin:/bin \
        "$work_dir/no-arch-set-fs-trace" "$binary" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        fail "$label did not reject before ARCH_SET_FS: $output"
    fi
}

expect_rejection_before_fs "$work_dir/main-strong-owned-record" \
    'strong main owned-CRT record import'
mv "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" \
    "$work_dir/libcrabc-dynamic-main-thread-runtime-v1-normal.so"
mv "$work_dir/libcrabc-dynamic-main-thread-runtime-v1-weak-owned-record.so" \
    "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so"
expect_rejection_before_fs "$work_dir/main-valid" 'weak DSO owned-CRT record import'
mv "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so" \
    "$work_dir/libcrabc-dynamic-main-thread-runtime-v1-weak-owned-record.so"
mv "$work_dir/libcrabc-dynamic-main-thread-runtime-v1-normal.so" \
    "$work_dir/libcrabc-dynamic-main-thread-runtime-v1.so"

printf '%s\n' 'x86 dynamic main-thread RuntimeV1: PASS (real Scrt1 attach; null owned handoff; dynamic TLS errno)'
