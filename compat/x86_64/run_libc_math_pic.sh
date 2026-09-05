#!/usr/bin/env bash
# Native Linux/x86-64 PIC closure audit for generated musl math assembly.
#
# Each checked assembly file is an independently renamed musl source closure.
# The installed dynamic libc can select all of them in one Rust codegen unit,
# so a static-only link cannot prove their table addressing is safe.  Assemble
# every closure with the pinned musl GCC, link it as a hardened shared object,
# and reject both link-time text relocations and remaining absolute 32-bit
# relocations before the installed dynamic-product producer combines them.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PINNED_TOOLCHAIN=nightly-2026-07-24
readonly EXPECTED_ASSEMBLY_COUNT=27

fail() { printf 'ERROR: x86 generated math PIC closure: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in grep mktemp readelf rustup wc; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

readonly WORK_ROOT="${CRABC_WORK_DIR:-$ROOT_DIR/.work/x86_64}"
[ -d "$WORK_ROOT" ] && [ ! -L "$WORK_ROOT" ] ||
    fail "work root must be an existing non-symlink directory: $WORK_ROOT"
readonly PHYSICAL_WORK_ROOT="$(cd -P "$WORK_ROOT" && pwd)"
case "$PHYSICAL_WORK_ROOT" in
    "$ROOT_DIR/.work"|"$ROOT_DIR/.work/"*) ;;
    *) fail "work root escapes this checkout's physical .work tree: $PHYSICAL_WORK_ROOT" ;;
esac

work_dir="$(mktemp -d "$PHYSICAL_WORK_ROOT/generated-math-pic.XXXXXX")"
completed=0
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [ "$completed" -eq 1 ]; then
        rm -rf -- "$work_dir"
    else
        printf 'x86 generated math PIC closure: retained failure artifacts at %s\n' "$work_dir" >&2
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

rust_sysroot="$(rustup run "$PINNED_TOOLCHAIN" rustc --print sysroot)"
readonly LLD="$rust_sysroot/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
[ -x "$LLD" ] || fail "missing pinned target ld.lld: $LLD"

shopt -s nullglob
assemblies=("$ROOT_DIR"/libc/src/c_abi/x86_64/math_*_musl_x86_64.S)
[ "${#assemblies[@]}" -eq "$EXPECTED_ASSEMBLY_COUNT" ] ||
    fail "generated math closure roster changed: expected $EXPECTED_ASSEMBLY_COUNT, found ${#assemblies[@]}"

for assembly in "${assemblies[@]}"; do
    [ -f "$assembly" ] && [ ! -L "$assembly" ] || fail "unsafe generated assembly input: $assembly"
    name="${assembly##*/}"
    name="${name%.S}"
    object="$work_dir/$name.o"
    shared="$work_dir/$name.so"
    object_relocations="$work_dir/$name.object.relocations"
    shared_relocations="$work_dir/$name.shared.relocations"
    shared_dynamic="$work_dir/$name.shared.dynamic"

    "$ORACLE_CC" -c "$assembly" -o "$object"
    readelf --relocs --wide "$object" >"$object_relocations"
    if grep -Eq 'R_X86_64_(32S|32)([[:space:]]|$)' "$object_relocations"; then
        fail "$name retains an absolute 32-bit object relocation"
    fi

    "$LLD" -shared --hash-style=sysv -soname "$name.so" \
        -z text -z relro -z now -z noexecstack -o "$shared" "$object"
    readelf --dynamic --wide "$shared" >"$shared_dynamic"
    readelf --relocs --wide "$shared" >"$shared_relocations"
    if grep -Eq 'TEXTREL|R_X86_64_(32S|32)([[:space:]]|$)' \
        "$shared_dynamic" "$shared_relocations"; then
        fail "$name retains a shared-library text or absolute 32-bit relocation"
    fi
done

completed=1
printf 'x86 generated math PIC closure: PASS (%s closures)\n' "${#assemblies[@]}"
