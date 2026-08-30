#!/usr/bin/env bash
# Native Linux/x86-64 Static Initial TLS v1 evidence.
#
# A project-header C fixture first runs through pinned musl 1.2.6, then as a
# true static `-nostdlib` executable linked only to crabc-libc.  The candidate
# entry shim gives the untouched Linux stack to libc's hidden bootstrap; the
# same retained final-executable PT_TLS template then supplies both the main
# thread and bounded pthread workers.  This is not dynamic TLS, a general
# pthread runtime, CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly ELF64_E_IDENT_VERSION_OFFSET=6
readonly ELF64_PROGRAM_HEADER_TABLE_OFFSET=64
readonly ELF64_PROGRAM_HEADER_SIZE=56
readonly ELF64_PROGRAM_HEADER_COUNT_OFFSET=56
readonly ELF64_P_FILESZ_OFFSET=32

fail() {
    printf 'ERROR: x86 Static Initial TLS v1: %s\n' "$*" >&2
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_final_tls_template() {
    local tls_count
    local tls_filesz
    local tls_memsz
    local tls_alignment

    tls_count="$(awk '$1 == "TLS" { count += 1 } END { print count + 0 }' "$candidate_program_headers")"
    [ "$tls_count" = 1 ] || fail "candidate must have exactly one PT_TLS segment"
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate PT_TLS line is not parseable"
    if (( tls_filesz == 0 )); then
        fail "candidate PT_TLS lacks initialized static TLS data"
    fi
    if (( tls_memsz <= tls_filesz )); then
        fail "candidate PT_TLS lacks a distinct zeroed TBSS tail"
    fi
    if (( tls_alignment < 4096 || (tls_alignment & (tls_alignment - 1)) != 0 )); then
        fail "candidate PT_TLS does not preserve the fixture's 4096-byte alignment"
    fi
}

assert_controlled_static_exec_without_pt_phdr() {
    grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
        "$candidate_file_header" ||
        fail "candidate must exercise the ET_EXEC no-PT_PHDR fallback"
    grep -Eq 'Start of program headers:[[:space:]]+64 \(bytes into file\)' \
        "$candidate_file_header" ||
        fail "candidate does not use the audited ELF64 header placement"
    if awk '$1 == "PHDR" { found = 1 } END { exit !found }' \
        "$candidate_program_headers"; then
        fail "candidate must exercise the no-PT_PHDR static-executable path"
    fi
}

expect_bootstrap_rejection() {
    local malformed_candidate="$1"
    local label="$2"
    local candidate_status

    if "$malformed_candidate"; then
        fail "${label} malformed candidate unexpectedly completed"
    else
        candidate_status=$?
    fi
    [ "$candidate_status" = 127 ] ||
        fail "${label} malformed candidate exited ${candidate_status}, not bootstrap failure 127"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp cp dd diff grep mkdir nm objdump od readelf rustup sort tr; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-static-tls-v1.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-static-tls-v1-reference"
candidate="$work_dir/crabc-static-tls-v1-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_file_header="$work_dir/candidate-file-header"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
bootstrap_disassembly="$work_dir/static-tls-bootstrap-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
bad_fallback_version="$work_dir/candidate-bad-fallback-version"
bad_tls_filesz="$work_dir/candidate-bad-tls-filesz"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_static_tls_v1_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h stdint.h bits/alltypes.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_static_tls_v1_probe.c \
    compat/x86_64/libc_static_tls_v1_peer.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_exit pthread_join; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "Static Initial TLS v1 bootstrap is not hidden"
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" ||
    fail "private pthread clone seam is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive lacks direct initial-TLS TPOFF relocations"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_STATIC_TLS_V1_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_static_tls_v1_probe.c \
    compat/x86_64/libc_static_tls_v1_peer.c \
    compat/x86_64/libc_static_tls_v1_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --file-header --wide "$candidate" >"$candidate_file_header"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_exit pthread_join crabc_x86_64_static_tls_v1_probe; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$candidate_symbols" ||
    fail "candidate bootstrap visibility drifted"
for tls_symbol in initial_tls_value tbss high_alignment_initialized \
    peer_initial_tls_value peer_tbss peer_high_alignment_tbss; do
    grep -Eq "TLS +GLOBAL +.*${tls_symbol}$" "$candidate_symbols" ||
        fail "candidate lacks TLS symbol ${tls_symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
assert_final_tls_template
assert_controlled_static_exec_without_pt_phdr
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model or unowned runtime dependency"
fi
for unselected in clone __clone \
    pthread_cancel pthread_key_create pthread_mutex_init malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate unexpectedly selects ${unselected}"
    fi
done
objdump -d --disassemble=__crabc_x86_static_tls_bootstrap "$candidate" >"$bootstrap_disassembly"
# The public hidden hook is intentionally a thin no-TLS wrapper. Its private
# plan/materialization helpers may remain out of line, so inspect the closed
# candidate path rather than imposing an inlining decision on Rust codegen.
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$candidate_disassembly" ||
    fail "Static Initial TLS v1 path lacks raw Linux syscalls"
grep -Eq '\$0x9e(,|[[:space:]]|$)' "$candidate_disassembly" ||
    fail "Static Initial TLS v1 path lacks arch_prctl syscall 158"
grep -Eq '\$0x9(,|[[:space:]]|$)' "$candidate_disassembly" ||
    fail "Static Initial TLS v1 path lacks mmap syscall 9"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct x86 initial TLS"
grep -Eq '%fs:0x0|%fs:-' "$candidate_disassembly" ||
    fail "candidate C TLS variables do not use direct x86 initial TLS"
if grep -Eqi 'arch_prctl|mov[[:space:]]+\$0x?9e|mov[[:space:]]+\$158|%fs:0' \
    compat/x86_64/libc_static_tls_v1_start.S; then
    fail "fixture start must delegate FS installation to libc"
fi

if "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

# The actual static candidate deliberately has no PT_PHDR.  Mutate only ELF
# header data the kernel does not need to reach _start, then require our
# controlled fallback to stop at the entry shim's distinct status 127.
cp "$candidate" "$bad_fallback_version"
printf '\000' | dd of="$bad_fallback_version" bs=1 \
    seek="$ELF64_E_IDENT_VERSION_OFFSET" conv=notrunc status=none
[ "$(od -An -tu1 -j "$ELF64_E_IDENT_VERSION_OFFSET" -N 1 "$bad_fallback_version" | tr -d '[:space:]')" = 0 ] ||
    fail "fallback ELF version mutation did not take effect"
expect_bootstrap_rejection "$bad_fallback_version" "fallback ELF version"

# PT_TLS is metadata for this static kernel entry, so an overlarge p_filesz
# reaches the hook and proves it rejects the template before any %fs install.
candidate_phnum="$(od -An -tu2 -j "$ELF64_PROGRAM_HEADER_COUNT_OFFSET" -N 2 "$candidate" | tr -d '[:space:]')"
if [ -z "$candidate_phnum" ] || (( candidate_phnum == 0 || candidate_phnum > 128 )); then
    fail "candidate has an invalid ELF64 program-header count"
fi
tls_header_index=""
for ((header_index = 0; header_index < candidate_phnum; header_index += 1)); do
    header_offset=$((ELF64_PROGRAM_HEADER_TABLE_OFFSET + header_index * ELF64_PROGRAM_HEADER_SIZE))
    header_type="$(od -An -tu4 -j "$header_offset" -N 4 "$candidate" | tr -d '[:space:]')"
    if [ "$header_type" = 7 ]; then
        tls_header_index="$header_index"
        break
    fi
done
[ -n "$tls_header_index" ] || fail "candidate has no PT_TLS program header to mutate"
tls_filesz_offset=$((ELF64_PROGRAM_HEADER_TABLE_OFFSET + tls_header_index * ELF64_PROGRAM_HEADER_SIZE + ELF64_P_FILESZ_OFFSET))
cp "$candidate" "$bad_tls_filesz"
printf '\377\377\377\377\377\377\377\377' | dd of="$bad_tls_filesz" bs=1 \
    seek="$tls_filesz_offset" conv=notrunc status=none
[ "$(od -An -tx1 -j "$tls_filesz_offset" -N 8 "$bad_tls_filesz" | tr -d '[:space:]')" = ffffffffffffffff ] ||
    fail "PT_TLS p_filesz mutation did not take effect"
expect_bootstrap_rejection "$bad_tls_filesz" "PT_TLS p_filesz"

printf 'x86 Static Initial TLS v1: PASS\n'
