#!/usr/bin/env bash
# Native evidence for the one private x86 ldso-to-Scrt1 owned-CRT handoff.
#
# The artifact is intentionally a cfg-gated sibling of the older initial
# graph.  It adds no ambient libc, no `%rdx` transport, and no generic loader
# root: one Rust-produced Scrt1.o main has one weak GOT record import and one
# main -> mid -> leaf dependency graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_graph.rs"
readonly START="$ROOT_DIR/compat/x86_64/ldso_initial_graph_start.S"
readonly LEAF="$ROOT_DIR/compat/x86_64/ldso_initial_graph_leaf.c"
readonly MID="$ROOT_DIR/compat/x86_64/ldso_initial_graph_mid.c"
readonly MAIN="$ROOT_DIR/compat/x86_64/ldso_owned_crt_handoff_main.c"
readonly CRT_BUILD="$ROOT_DIR/crt/build_x86_64.py"
readonly MUSL_LOADER="/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1"

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    printf '%s\n' 'ERROR: owned-CRT handoff evidence requires native Linux/x86-64' >&2
    exit 2
fi
if [ ! -x "$MUSL_LOADER" ]; then
    printf '%s\n' 'ERROR: the pinned musl 1.2.6 loader is required' >&2
    exit 2
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"

work_dir="$(mktemp -d)"
if [ "${CRABC_LDSO_OWNED_CRT_HANDOFF_KEEP_WORK:-0}" = 1 ]; then
    printf '%s\n' "retained owned-CRT handoff work directory: $work_dir" >&2
else
    trap 'rm -rf "$work_dir"' EXIT
fi

build_interpreter() {
    local output="$1"
    shift
    rustc --edition=2021 --crate-type staticlib --cfg crabc_owned_crt_handoff "$@" \
        -C panic=abort -C relocation-model=pic "$SOURCE" -o "$work_dir/libowned_crt_handoff.a"
    cc -nostdlib -shared -Wl,-e,_start -Wl,-Bsymbolic -Wl,-z,now -Wl,--no-undefined \
        -Wl,--whole-archive "$work_dir/libowned_crt_handoff.a" -Wl,--no-whole-archive \
        -o "$output"
}

build_interpreter "$work_dir/ld-crabc-x86_64-owned-crt-handoff.so"
build_interpreter "$work_dir/ld-crabc-x86_64-owned-crt-handoff-malformed.so" --cfg crabc_owned_crt_handoff_malformed

for interpreter in "$work_dir/ld-crabc-x86_64-owned-crt-handoff.so" \
    "$work_dir/ld-crabc-x86_64-owned-crt-handoff-malformed.so"; do
    if readelf -dW "$interpreter" | grep -Eq '\(NEEDED\)|\(INTERP\)'; then
        printf '%s\n' "ERROR: interpreter selected an ambient runtime: $interpreter" >&2
        exit 1
    fi
    if readelf -lW "$interpreter" | grep -q ' TLS '; then
        printf '%s\n' "ERROR: interpreter selected PT_TLS: $interpreter" >&2
        exit 1
    fi
    if ! readelf -lW "$interpreter" | grep -q 'GNU_RELRO'; then
        printf '%s\n' "ERROR: interpreter lacks PT_GNU_RELRO: $interpreter" >&2
        exit 1
    fi
    if ! readelf -Ws "$interpreter" | awk '$4 == "OBJECT" && $7 != "UND" && $8 == "__crabc_x86_64_owned_crt_handoff" && $3 == 32 { found = 1 } END { exit found ? 0 : 1 }'; then
        printf '%s\n' "ERROR: interpreter does not export the exact v1 owned-CRT record: $interpreter" >&2
        exit 1
    fi
done

# Preserve the known no-TLS RELA/RELR graph; only the two constructor bodies
# gain fixture-local event records in this artifact.
cc -DCRABC_OWNED_CRT_HANDOFF=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-z,pack-relative-relocs -Wl,-soname,libleaf-owned-crt.so "$LEAF" \
    -o "$work_dir/libleaf-owned-crt.so"
cc -DCRABC_OWNED_CRT_HANDOFF=1 -fPIC -shared -nostdlib -Wl,--hash-style=sysv -Wl,-z,now \
    -Wl,-soname,libmid-owned-crt.so -Wl,-rpath,"$work_dir" "$MID" \
    -L"$work_dir" -Wl,--no-as-needed -l:libleaf-owned-crt.so \
    -o "$work_dir/libmid-owned-crt.so"

if command -v llvm-objdump >/dev/null 2>&1; then
    llvm_objdump="$(command -v llvm-objdump)"
else
    rust_sysroot="$(rustup run nightly-2026-07-24 rustc --print sysroot)"
    llvm_objdump="$rust_sysroot/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump"
fi
if [ ! -x "$llvm_objdump" ]; then
    printf '%s\n' 'ERROR: pinned Rust llvm-objdump is required for the Rust-produced Scrt1.o audit' >&2
    exit 2
fi
python3 "$CRT_BUILD" --out-dir "$work_dir/crt" --llvm-objdump "$llvm_objdump" >"$work_dir/crt.json"

build_main() {
    local interpreter="$1"
    local output="$2"
    local mode="$3"
    local -a cflags=()
    if [ "$mode" = early-fini ]; then
        cflags+=(-DCRABC_OWNED_CRT_EARLY_FINI=1)
    fi
    cc -nostdlib -fPIE -pie -fno-stack-protector -ffreestanding -fno-asynchronous-unwind-tables \
        -Wl,--hash-style=sysv -Wl,-z,now -Wl,--dynamic-linker,"$interpreter" \
        -Wl,-rpath,"$work_dir" "$work_dir/crt/Scrt1.o" "$work_dir/crt/crti.o" \
        "${cflags[@]}" "$MAIN" -L"$work_dir" -Wl,--no-as-needed \
        -l:libmid-owned-crt.so "$work_dir/crt/crtn.o" -o "$output"
}

build_main "$work_dir/ld-crabc-x86_64-owned-crt-handoff.so" "$work_dir/main-owned" owned
build_main "$MUSL_LOADER" "$work_dir/main-musl" foreign
build_main "$work_dir/ld-crabc-x86_64-owned-crt-handoff-malformed.so" "$work_dir/main-malformed" owned
build_main "$work_dir/ld-crabc-x86_64-owned-crt-handoff.so" "$work_dir/main-early-fini" early-fini

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
        printf '%s\n' "ERROR: unexpected DT_NEEDED graph in $binary" >&2
        readelf -dW "$binary" >&2
        exit 1
    fi
}

for binary in "$work_dir/main-owned" "$work_dir/main-musl" "$work_dir/main-malformed" "$work_dir/main-early-fini"; do
    require_needed_names "$binary" libmid-owned-crt.so
    if ! readelf -lW "$binary" | grep -q 'GNU_RELRO'; then
        printf '%s\n' "ERROR: main lacks PT_GNU_RELRO: $binary" >&2
        exit 1
    fi
done
require_needed_names "$work_dir/libmid-owned-crt.so" libleaf-owned-crt.so
require_needed_names "$work_dir/libleaf-owned-crt.so"

if ! readelf -Ws "$work_dir/main-owned" | awk '$5 == "WEAK" && $7 == "UND" && $8 == "__crabc_x86_64_owned_crt_handoff" { found = 1 } END { exit found ? 0 : 1 }'; then
    printf '%s\n' 'ERROR: Scrt1-owned main lost its weak owned-CRT record import' >&2
    exit 1
fi
if ! readelf -rW "$work_dir/main-owned" | grep -Eq 'R_X86_64_GLOB_DAT.*__crabc_x86_64_owned_crt_handoff'; then
    printf '%s\n' 'ERROR: Scrt1-owned main lacks the checked GOT record relocation' >&2
    exit 1
fi
for binary in "$work_dir/main-owned" "$work_dir/main-musl" "$work_dir/main-malformed" "$work_dir/main-early-fini" \
    "$work_dir/libmid-owned-crt.so" "$work_dir/libleaf-owned-crt.so"; do
    # A libc DT_NEEDED edge would invalidate this private fixture's explicit
    # local six-argument boundary and reintroduce ambient lifecycle state.
    if readelf -dW "$binary" | grep -Eq '\(NEEDED\).*(libc|libgcc|ld-linux)'; then
        printf '%s\n' "ERROR: owned-CRT fixture selected an ambient libc/runtime: $binary" >&2
        exit 1
    fi
done

run_clean() {
    local binary="$1"
    env -i PATH=/usr/bin:/bin "$binary"
}

owned_output="$(cd "$work_dir" && run_clean "$work_dir/main-owned")"
if [ "$owned_output" != 'PDdIMFL' ]; then
    printf '%s\n' "ERROR: owned handoff order drifted: $owned_output" >&2
    exit 1
fi

# A foreign pinned-musl interpreter leaves the weak record absent.  Its only
# allowed observable path is the explicit null-finalizer observation above.
foreign_output="$(cd "$work_dir" && run_clean "$work_dir/main-musl")"
if [ "$foreign_output" != 'A' ]; then
    printf '%s\n' "ERROR: foreign loader did not retain the absent-record path: $foreign_output" >&2
    exit 1
fi

expect_status_127() {
    local binary="$1"
    local label="$2"
    local status
    set +e
    (cd "$work_dir" && run_clean "$binary") >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -ne 127 ]; then
        printf '%s\n' "ERROR: $label did not fail closed with status 127 (got $status)" >&2
        exit 1
    fi
}

# The malformed interpreter still resolves the weak GOT slot, so this reaches
# Rust-produced Scrt1 and verifies that its v1 decoder rejects the bad wire
# before the local libc boundary can run.
expect_status_127 "$work_dir/main-malformed" 'malformed owned-CRT record'
# This is an ordering negative rather than a second lifecycle feature: the
# process finalizer callback is one-shot and cannot precede dependency init.
expect_status_127 "$work_dir/main-early-fini" 'early owned process finalizer'

printf '%s\n' 'x86 owned ldso-to-Scrt1 CRT handoff: PASS'
