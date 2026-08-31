#!/usr/bin/env bash
# Native Linux/x86-64 bounded static pthread_getconcurrency evidence.
#
# The project-header fixture first runs through pinned musl 1.2.6, then as a
# true `-nostdlib -static` executable linked only with the selected crabc
# object. It proves exactly musl's fixed zero result. It does not select a
# stored concurrency setting, pthread_setconcurrency, thread creation,
# scheduler policy, attributes, synchronization, cancellation, TLS, CRT,
# loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static pthread_getconcurrency: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        sort -u
}

assert_selected_c_abi_surface() {
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_direct_query_path() {
    local disassembly="$work_dir/pthread-getconcurrency-disassembly"

    objdump -d --disassemble=pthread_getconcurrency "$candidate" >"$disassembly"
    if grep -Eq '[[:space:]](syscall|call)([[:space:]]|$)|%fs:' "$disassembly"; then
        fail "pthread_getconcurrency must remain a direct TLS-free, syscall-free query leaf"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-getconcurrency.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-getconcurrency-reference"
candidate="$work_dir/crabc-static-pthread-getconcurrency-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-pthread-getconcurrency.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
object_undefined="$work_dir/pthread-getconcurrency-undefined"
object_relocations="$work_dir/pthread-getconcurrency-relocations"
object_disassembly="$work_dir/pthread-getconcurrency-object-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_getconcurrency_probe.c >/dev/null 2>"$header_trace"
for header in pthread.h bits/alltypes.h features.h errno.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_getconcurrency_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    status=$?
    fail "pinned-musl pthread_getconcurrency fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]pthread_getconcurrency$' "$archive_symbols" ||
    fail "archive does not define pthread_getconcurrency"

mapfile -t members < <(archive_member_for_symbol "$archive" pthread_getconcurrency)
[ "${#members[@]}" -eq 1 ] ||
    fail "pthread_getconcurrency must have exactly one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${members[0]}"
    ar crs "$selected_archive" "${members[0]}"
)
object="$work_dir/owner/${members[0]}"

mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "pthread_getconcurrency" ]; then
    printf 'expected: %s\nactual:   %s\n' "pthread_getconcurrency" "${exports[*]}" >&2
    fail "pthread_getconcurrency object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    cat "$object_undefined" >&2
    fail "pthread_getconcurrency object unexpectedly depends on another symbol"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:' "$object_disassembly"; then
    fail "pthread_getconcurrency object unexpectedly calls, syscalls, or uses TLS"
fi
for marker in 'src/thread/pthread_getconcurrency.c::pthread_getconcurrency' \
    'zero directly' 'pthread_setconcurrency' 'private selected static artifact'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/pthread_getconcurrency.rs ||
        fail "pthread_getconcurrency source lacks ${marker}"
done
if grep -Eq 'use super|raw_syscall::|static_tls::|pthread_(identity|create_join|affinity|cpuclock|name|mutex|cond|rwlock|tsd|cancel|atfork|setconcurrency)::|atomic::' \
    libc/src/c_abi/x86_64/pthread_getconcurrency.rs; then
    fail "pthread_getconcurrency source must not import a runtime seam"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_PTHREAD_GETCONCURRENCY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_pthread_getconcurrency_probe.c \
    compat/x86_64/libc_pthread_getconcurrency_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "pthread_getconcurrency" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks global pthread_getconcurrency"
for unselected in pthread_setconcurrency pthread_create pthread_detach pthread_join \
    pthread_getschedparam pthread_setschedparam pthread_setschedprio \
    pthread_attr_init pthread_attr_destroy pthread_mutex_init pthread_mutex_lock \
    pthread_cond_init pthread_rwlock_init pthread_setname_np pthread_getname_np; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally exports unselected ${unselected}"
    fi
done
for unselected in __errno_location __crabc_x86_static_tls_bootstrap; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate pulled unselected ${unselected}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate must remain TLS-free"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|rand|random' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

assert_direct_query_path

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding pthread_getconcurrency fixture exited ${status}"
fi

printf 'x86 static crabc-libc pthread_getconcurrency: PASS\n'
