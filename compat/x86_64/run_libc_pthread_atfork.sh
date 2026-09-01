#!/usr/bin/env bash
# Native Linux/x86-64 bounded static pthread_atfork/fork/exit-hook evidence.
#
# The same project-header C body runs first against pinned musl 1.2.6 and then
# against a true dependency-free `-nostdlib -static` selected crabc archive.
# It admits one single-threaded hook registry and a child-only ordinary-exit
# callback composition; it does not establish a general process or pthread
# runtime.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() { printf 'ERROR: x86 static libc pthread_atfork: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fork_weak_aio_atfork_owner() {
    local archive_path="$1"
    local members_path="$work_dir/fork-aio-atfork-members"
    local fork_member
    local -a members fork_members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
    )
    mapfile -t fork_members < <(
        (
            cd "$members_path"
            nm -A -g --defined-only --format=posix "${members[@]}"
        ) | awk '$2 == "fork" && $3 ~ /^[TW]$/ { name = $1; sub(/:$/, "", name); print name }' | sort -u
    )
    [ "${#fork_members[@]}" = 1 ] ||
        fail "archive does not retain one fork owner: ${fork_members[*]:-(none)}"
    fork_member="${fork_members[0]}"
    nm -g --defined-only --format=posix "$members_path/$fork_member" |
        awk '$1 == "__aio_atfork" && $2 == "W" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "archive fork member lost musl weak __aio_atfork binding"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-atfork.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-atfork-reference"
candidate="$work_dir/crabc-static-pthread-atfork-candidate"
candidate_loader_hook="$work_dir/crabc-static-pthread-atfork-loader-hook-candidate"
candidate_aio_hook="$work_dir/crabc-static-pthread-atfork-aio-hook-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
fork_disassembly="$work_dir/fork-disassembly"
exit_disassembly="$work_dir/exit-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_atfork_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h stdatomic.h stdint.h stdlib.h sys/prctl.h sys/syscall.h sys/types.h sys/wait.h unistd.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_atfork_probe.c -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    reference_status=$?
    fail "pinned-musl reference exited ${reference_status}"
fi
CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
assert_fork_weak_aio_atfork_owner "$archive"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap __fork_handler \
    pthread_atfork fork atexit exit __funcs_on_exit pthread_create pthread_join waitpid; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'FUNC +WEAK +DEFAULT +.*__ldso_atfork$' "$archive_elf_symbols" ||
    fail 'archive lost musl weak __ldso_atfork binding'
grep -Eq 'FUNC +WEAK +DEFAULT +.*__aio_atfork$' "$archive_elf_symbols" ||
    fail 'archive lost musl weak __aio_atfork binding'
for unselected in _Fork vfork clone execve posix_spawn malloc free calloc realloc \
    aio_read aio_write aio_fsync aio_return aio_cancel lio_listio aio_suspend; do
    ! grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols" ||
        fail "archive exports unselected ${unselected}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ATFORK_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections -Wl,-u,__ldso_atfork -Wl,-u,__aio_atfork \
    compat/x86_64/libc_pthread_atfork_probe.c \
    compat/x86_64/libc_pthread_atfork_start.S "$archive" -o "$candidate"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ATFORK_FREESTANDING \
    -DCRABC_ATFORK_LOADER_HOOK_OVERRIDE -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__ldso_atfork -Wl,-u,__aio_atfork \
    compat/x86_64/libc_pthread_atfork_probe.c \
    compat/x86_64/libc_pthread_atfork_start.S "$archive" -o "$candidate_loader_hook"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ATFORK_FREESTANDING \
    -DCRABC_ATFORK_AIO_HOOK_OVERRIDE -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    -Wl,-u,__ldso_atfork -Wl,-u,__aio_atfork \
    compat/x86_64/libc_pthread_atfork_probe.c \
    compat/x86_64/libc_pthread_atfork_start.S "$archive" -o "$candidate_aio_hook"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap __fork_handler \
    pthread_atfork fork atexit exit __funcs_on_exit pthread_create pthread_join \
    waitpid; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
grep -Eq 'FUNC +WEAK +DEFAULT +.*__ldso_atfork$' "$candidate_symbols" ||
    fail 'candidate lost musl weak __ldso_atfork binding'
grep -Eq 'FUNC +WEAK +DEFAULT +.*__aio_atfork$' "$candidate_symbols" ||
    fail 'candidate lost musl weak __aio_atfork binding'
readelf --symbols --wide "$candidate_loader_hook" >"$work_dir/candidate-loader-hook-symbols"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "fork" { found=1 } END { exit found ? 0 : 1 }' \
    "$work_dir/candidate-loader-hook-symbols" ||
    fail 'caller override did not extract the archive fork member'
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__ldso_atfork$' "$work_dir/candidate-loader-hook-symbols" ||
    fail 'caller strong __ldso_atfork did not override the archive weak binding'
if grep -Eq 'FUNC +WEAK +DEFAULT +.*__ldso_atfork$' "$work_dir/candidate-loader-hook-symbols"; then
    fail 'caller override retained the archive weak __ldso_atfork binding'
fi
readelf --symbols --wide "$candidate_aio_hook" >"$work_dir/candidate-aio-hook-symbols"
for symbols_path in "$candidate_symbols" \
    "$work_dir/candidate-loader-hook-symbols" \
    "$work_dir/candidate-aio-hook-symbols"; do
    for unselected in wait3 wait4; do
        if grep -Eq "[[:space:]]${unselected}$" "$symbols_path"; then
            fail "candidate unexpectedly pulls unrelated wait extension ${unselected}"
        fi
    done
done
awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "fork" { found=1 } END { exit found ? 0 : 1 }' \
    "$work_dir/candidate-aio-hook-symbols" ||
    fail 'AIO-atfork caller override did not extract the archive fork member'
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__aio_atfork$' "$work_dir/candidate-aio-hook-symbols" ||
    fail 'caller strong __aio_atfork did not override the archive weak binding'
if grep -Eq 'FUNC +WEAK +DEFAULT +.*__aio_atfork$' "$work_dir/candidate-aio-hook-symbols"; then
    fail 'caller override retained the archive weak __aio_atfork binding'
fi
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
! grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    fail "candidate selected dynamic interpreter"
! grep -Eq 'NEEDED|JMPREL|PLTGOT' "$candidate_dynamic" ||
    fail "candidate selected dynamic dependency"
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks initial TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects dynamic TLS or unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno lacks direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_pthread_atfork_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pthread_atfork_start.S; then
    fail "fixture start must not install a private FS base"
fi

objdump -d --disassemble=fork "$candidate" >"$fork_disassembly"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$fork_disassembly" ||
    fail "fork lacks raw Linux syscall"
grep -Eq '\$0x39,%eax|\$0x39,%rax|\$0x0000000000000039,%rax' "$fork_disassembly" ||
    fail "fork lacks Linux fork=57"
grep -Eq 'call.*__fork_handler' "$fork_disassembly" ||
    fail "fork does not route through the private atfork dispatcher"
objdump -d --disassemble=exit "$candidate" >"$exit_disassembly"
grep -Eq 'call.*__funcs_on_exit' "$exit_disassembly" ||
    fail "exit does not route through the bounded ordinary-exit dispatcher"

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "static candidate exited ${candidate_status}"
fi
if timeout "$EXECUTION_TIMEOUT" "$candidate_loader_hook"; then
    :
else
    candidate_status=$?
    fail "static loader-hook override candidate exited ${candidate_status}"
fi
if timeout "$EXECUTION_TIMEOUT" "$candidate_aio_hook"; then
    :
else
    candidate_status=$?
    fail "static AIO-atfork override candidate exited ${candidate_status}"
fi
printf 'x86 static crabc-libc pthread_atfork/fork/exit hooks: PASS\n'
