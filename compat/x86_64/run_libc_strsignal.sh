#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc strsignal evidence.
#
# An isolated project-header fixture first runs through pinned musl 1.2.6,
# then through a true `-nostdlib -static` candidate. The exact fixed signal
# description domain is compared without selecting locale translation, error
# strings, diagnostics, signal delivery, or process termination. A second
# executable provides fixture-local initial TLS solely to observe errno.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc strsignal: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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

assert_strong_function() {
    local symbols_path="$1" symbol="$2" label="$3"
    awk -v name="$symbol" \
        '$8 == name && $4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" { found = 1 } END { exit !found }' \
        "$symbols_path" || fail "$label lacks strong function $symbol"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo chmod chown cmp cp diff git grep mkdir nm objdump readelf rustup sha256sum sort stat; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_strsignal_header_abi.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/libc-strsignal.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/pinned-musl-strsignal-reference"
candidate="$work_dir/crabc-static-strsignal-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
reference_stdout="$work_dir/reference-stdout"
reference_stderr="$work_dir/reference-stderr"
candidate_stdout="$work_dir/candidate-stdout"
candidate_stderr="$work_dir/candidate-stderr"
errno_reference="$work_dir/pinned-musl-strsignal-errno-reference"
errno_candidate="$work_dir/crabc-static-strsignal-errno-candidate"
errno_start="$work_dir/strsignal-errno-start.S"
errno_headers="$work_dir/errno-candidate-program-headers"
errno_dynamic="$work_dir/errno-candidate-dynamic"
errno_symbols="$work_dir/errno-candidate-symbols"
errno_header_trace="$work_dir/errno-header-trace"
errno_reference_stdout="$work_dir/errno-reference-stdout"
errno_reference_stderr="$work_dir/errno-reference-stderr"
errno_candidate_stdout="$work_dir/errno-candidate-stdout"
errno_candidate_stderr="$work_dir/errno-candidate-stderr"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -E -H compat/x86_64/libc_strsignal_probe.c >/dev/null 2>"$header_trace"
for header in string.h features.h bits/alltypes.h stdint.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header> header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_strsignal_probe.c -o "$reference"
if env -i "$reference" >"$reference_stdout" 2>"$reference_stderr"; then :; else
    status=$?
    fail "pinned-musl strsignal fixture exited $status"
fi
[ ! -s "$reference_stderr" ] || fail "pinned-musl fixture wrote stderr"

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]strsignal$' "$archive_symbols" ||
    fail "archive does not define strong strsignal"

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_STRSIGNAL_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_strsignal_probe.c \
    compat/x86_64/libc_strsignal_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
    <(readelf --file-header --wide "$candidate") || fail "candidate is not ET_EXEC"
assert_strong_function "$candidate_symbols" strsignal candidate
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep . >/dev/null; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers"; then
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'strerror(_r|_l)?|__strerror_l|psignal|perror|abort|malloc|calloc|realloc|free|syscall|crabc_core|mimalloc|sha_crypt|__libc_current_sigrt' \
    "$candidate_symbols"; then
    fail "candidate selects error strings, diagnostics, termination, allocator, or runtime state"
fi

if env -i "$candidate" >"$candidate_stdout" 2>"$candidate_stderr"; then :; else
    status=$?
    fail "freestanding strsignal fixture exited $status"
fi
[ ! -s "$candidate_stderr" ] || fail "candidate wrote stderr"
if ! cmp -s "$reference_stdout" "$candidate_stdout"; then
    diff -u "$reference_stdout" "$candidate_stdout" >&2 || true
    fail "candidate output differs from pinned musl"
fi
grep -Eq '^strsignal-domain-fnv1a64=[0-9a-f]{16}$' "$candidate_stdout" ||
    fail "candidate lacks the complete strsignal-domain digest"

# The primary executable still proves the lookup needs no TLS. This separate
# fixture installs one zero-initialized initial-TLS region so that C errno can
# be observed without adding an errno dependency to the lookup itself.
cat >"$errno_start" <<'EOF'
    .section .bss
    .balign 64
strsignal_errno_initial_tls:
    .zero 4096
strsignal_errno_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    lea strsignal_errno_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js 1f
    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_strsignal_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
1:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
EOF

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_STRSIGNAL_ERRNO_PROBE -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_strsignal_probe.c >/dev/null 2>"$errno_header_trace"
grep -Fq "$ROOT_DIR/include/errno.h" "$errno_header_trace" ||
    fail "errno fixture did not use the project <errno.h> header"

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_STRSIGNAL_ERRNO_PROBE -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_strsignal_probe.c -o "$errno_reference"
if env -i "$errno_reference" >"$errno_reference_stdout" 2>"$errno_reference_stderr"; then :; else
    status=$?
    fail "pinned-musl errno fixture exited $status"
fi
[ ! -s "$errno_reference_stderr" ] || fail "pinned-musl errno fixture wrote stderr"

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_STRSIGNAL_ERRNO_PROBE -DCRABC_STRSIGNAL_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_strsignal_probe.c \
    "$errno_start" "$archive" -o "$errno_candidate"
readelf --program-headers --wide "$errno_candidate" >"$errno_headers"
readelf --dynamic --wide "$errno_candidate" >"$errno_dynamic" || true
readelf --symbols --wide "$errno_candidate" >"$errno_symbols"
read -r tls_filesz tls_memsz tls_alignment < <(
    awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$errno_headers"
) || fail "errno fixture lacks a parsable initial TLS segment"
[ -n "${tls_filesz:-}" ] || fail "errno fixture lacks initial TLS"
(( tls_filesz == 0 && tls_memsz > 0 && tls_memsz <= 4096 &&
   tls_alignment > 0 && tls_alignment <= 64 && 64 % tls_alignment == 0 )) ||
    fail "errno fixture TLS exceeds its aligned scratch region"
for symbol in __errno_location strsignal; do
    assert_strong_function "$errno_symbols" "$symbol" "errno candidate"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$errno_symbols" | grep . >/dev/null; then
    fail "errno candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$errno_headers" "$errno_dynamic"; then
    fail "errno candidate selects a dynamic dependency"
fi
if env -i "$errno_candidate" >"$errno_candidate_stdout" 2>"$errno_candidate_stderr"; then :; else
    status=$?
    fail "freestanding errno fixture exited $status"
fi
[ ! -s "$errno_candidate_stderr" ] || fail "freestanding errno fixture wrote stderr"
if ! cmp -s "$errno_reference_stdout" "$errno_candidate_stdout"; then
    diff -u "$errno_reference_stdout" "$errno_candidate_stdout" >&2 || true
    fail "errno fixture output differs from pinned musl"
fi

mkdir -p "$ROOT_DIR/.work/x86_64/reports"
receipt_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/reports/libc-strsignal.XXXXXX")"
cp "$reference" "$receipt_dir/oracle-base.elf"
cp "$candidate" "$receipt_dir/candidate-base.elf"
cp "$errno_reference" "$receipt_dir/oracle-errno.elf"
cp "$errno_candidate" "$receipt_dir/candidate-errno.elf"
cp "$reference_stdout" "$receipt_dir/oracle-base.stdout"
cp "$reference_stderr" "$receipt_dir/oracle-base.stderr"
cp "$candidate_stdout" "$receipt_dir/candidate-base.stdout"
cp "$candidate_stderr" "$receipt_dir/candidate-base.stderr"
cp "$errno_reference_stdout" "$receipt_dir/oracle-errno.stdout"
cp "$errno_reference_stderr" "$receipt_dir/oracle-errno.stderr"
cp "$errno_candidate_stdout" "$receipt_dir/candidate-errno.stdout"
cp "$errno_candidate_stderr" "$receipt_dir/candidate-errno.stderr"
{
    printf 'source_commit\t%s\n' "$(git rev-parse HEAD)"
    printf 'command\t./scripts/dev-x86_64.sh libc-strsignal\n'
    printf 'oracle-base\t0\n'
    printf 'candidate-base\t0\n'
    printf 'oracle-errno\t0\n'
    printf 'candidate-errno\t0\n'
} >"$receipt_dir/statuses.tsv"
(
    cd "$receipt_dir"
    sha256sum ./*.elf ./*.stdout ./*.stderr statuses.tsv >SHA256SUMS
    chmod 755 ./*.elf
    chmod 644 ./*.stdout ./*.stderr statuses.tsv SHA256SUMS
)
chmod 755 "$receipt_dir"
receipt_owner="$(stat -c '%u:%g' "$ROOT_DIR")"
chown "$receipt_owner" "$ROOT_DIR/.work/x86_64/reports"
chown -R "$receipt_owner" "$receipt_dir"

printf 'x86 static crabc-libc strsignal: PASS\n'
printf 'receipt: %s\n' "$receipt_dir"
