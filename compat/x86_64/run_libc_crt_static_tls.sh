#!/usr/bin/env bash
# Native Linux/x86-64 real rcrt1 -> libc Static Initial TLS v1 composition.
#
# A shared C lifecycle body first executes with pinned musl, then a true
# static PIE links exact pinned-rustc rcrt1.o/crti.o/crtn.o source objects and
# the selected crabc-libc archive. The archive owns both the narrow
# __libc_start_main lifecycle and PT_TLS materialization, then retains the
# selected worker template.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly ELF64_PROGRAM_HEADER_SIZE=56
readonly ELF64_PROGRAM_HEADER_COUNT_OFFSET=56
readonly ELF64_PROGRAM_HEADER_OFFSET=32
readonly ELF64_P_FILESZ_OFFSET=32

fail() {
    printf 'ERROR: x86 rcrt1 -> libc Static Initial TLS v1: %s\n' "$*" >&2
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

assert_static_startup_weak_fallback_owner() {
    local archive_path="$1"
    local members_path="$work_dir/static-startup-fallback-members"
    local startup_member
    local -a members startup_members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
    )
    mapfile -t startup_members < <(
        (
            cd "$members_path"
            nm -A -g --defined-only --format=posix "${members[@]}"
        ) | awk '$2 == "__libc_start_main" && $3 ~ /^[TW]$/ { name = $1; sub(/:$/, "", name); print name }' | sort -u
    )
    [ "${#startup_members[@]}" = 1 ] ||
        fail "archive does not retain one static-startup owner for __libc_start_main: ${startup_members[*]:-(none)}"
    startup_member="${startup_members[0]}"
    nm -g --defined-only --format=posix "$members_path/$startup_member" |
        awk '$1 == "__init_ssp" && $2 == "W" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "archive static-startup member lost musl weak __init_ssp binding"
    nm -g --defined-only --format=posix "$members_path/$startup_member" |
        awk '$1 == "__stdio_exit" && $2 == "W" { found=1 } END { exit found ? 0 : 1 }' ||
        fail "archive static-startup member lost musl weak __stdio_exit binding"
}

assert_final_static_pie() {
    local tls_count tls_filesz tls_memsz tls_alignment

    grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
        "$candidate_file_header" || fail "candidate is not ET_DYN static PIE"
    awk '$1 == "PHDR" { found = 1 } END { exit !found }' "$candidate_program_headers" ||
        fail "candidate lacks PT_PHDR required by the libc handoff"
    if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$candidate_dynamic"; then
        fail "candidate selects an interpreter, dynamic dependency, or PLT"
    fi
    tls_count="$(awk '$1 == "TLS" { count += 1 } END { print count + 0 }' "$candidate_program_headers")"
    [ "$tls_count" = 1 ] || fail "candidate must have exactly one PT_TLS segment"
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate PT_TLS line is not parseable"
    if (( tls_filesz == 0 || tls_memsz <= tls_filesz )); then
        fail "candidate TLS lacks initialized and TBSS content"
    fi
    if (( tls_alignment < 4096 || (tls_alignment & (tls_alignment - 1)) != 0 )); then
        fail "candidate TLS lost the fixture's 4096-byte alignment"
    fi
}

expect_bootstrap_rejection() {
    local malformed_candidate="$1"
    local candidate_status

    if "$malformed_candidate"; then
        fail "malformed candidate unexpectedly completed"
    else
        candidate_status=$?
    fi
    [ "$candidate_status" = 127 ] ||
        fail "malformed candidate exited ${candidate_status}, not handoff failure 127"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp cp dd diff grep mkdir nm objdump od readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_rustc="$(rustup which rustc)"
    toolchain_root="$(dirname "$(dirname "$toolchain_rustc")")"
    bundled_lld="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    if [ -x "$bundled_lld" ]; then
        link_editor="$bundled_lld"
    elif command -v ld >/dev/null 2>&1; then
        link_editor=ld
    else
        fail "requires a native x86-64 linker"
    fi
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-crt-static-tls.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
crt_dir="$work_dir/crt"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-crt-static-tls-reference"
candidate="$work_dir/crabc-crt-static-tls-candidate"
candidate_ssp_override="$work_dir/crabc-crt-static-tls-ssp-override-candidate"
candidate_stdio_exit_override="$work_dir/crabc-crt-static-tls-stdio-exit-override-candidate"
candidate_without_archive="$work_dir/crabc-crt-static-tls-without-archive"
without_archive_log="$work_dir/without-archive-link.log"
probe_object="$work_dir/probe.o"
ssp_override_probe_object="$work_dir/ssp-override-probe.o"
stdio_exit_override_probe_object="$work_dir/stdio-exit-override-probe.o"
peer_object="$work_dir/peer.o"
header_trace="$work_dir/header-trace"
rcrt_symbols="$work_dir/rcrt-symbols"
rcrt_disassembly="$work_dir/rcrt-disassembly"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_ssp_override_symbols="$work_dir/candidate-ssp-override-symbols"
candidate_stdio_exit_override_symbols="$work_dir/candidate-stdio-exit-override-symbols"
candidate_file_header="$work_dir/candidate-file-header"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_startup_disassembly="$work_dir/candidate-startup-disassembly"
errno_disassembly="$work_dir/candidate-errno-disassembly"
bad_tls_filesz="$work_dir/candidate-bad-tls-filesz"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_crt_static_tls_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h stdint.h stdlib.h bits/alltypes.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project ${header}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_MUSL_REFERENCE \
    -pthread -fno-builtin -fno-stack-protector \
    -ftls-model=local-exec -I"$ROOT_DIR/include" \
    compat/x86_64/libc_crt_static_tls_probe.c \
    compat/x86_64/libc_crt_static_tls_peer.c -o "$reference"
if reference_output="$($reference)"; then
    :
else
    reference_status=$?
    fail "pinned-musl reference exited ${reference_status} with output ${reference_output@Q}"
fi
[ "$reference_output" = PIMBCAF ] ||
    fail "pinned-musl reference lifecycle output is ${reference_output@Q}, not PIMBCAF"

mkdir "$crt_dir"
for object in rcrt1 crti crtn; do
    case "$object" in
        rcrt1) source_path=crt/src/x86_64_rcrt1.rs ;;
        crti) source_path=crt/src/x86_64_crti.rs ;;
        crtn) source_path=crt/src/x86_64_crtn.rs ;;
    esac
    rustup run nightly-2026-07-24 rustc --edition=2021 --crate-type=lib --emit=obj \
        --target x86_64-unknown-linux-musl -C panic=abort -C force-unwind-tables=no \
        -C debuginfo=0 -C opt-level=2 -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=pic -C code-model=small -C link-dead-code=no \
        --remap-path-prefix "$ROOT_DIR=/crabc" \
        --crate-name "crabc_x86_64_${object}" "$source_path" -o "$crt_dir/${object}.o"
done
readelf --symbols --wide "$crt_dir/rcrt1.o" >"$rcrt_symbols"
objdump -dr "$crt_dir/rcrt1.o" >"$rcrt_disassembly"
grep -Eq 'GLOBAL +HIDDEN +.*UND +__crabc_x86_static_tls_bootstrap$' "$rcrt_symbols" ||
    fail "rcrt1.o lacks the hidden libc TLS-bootstrap boundary"
grep -Eq 'R_X86_64_(PLT32|PC32|GOTPCREL).*__crabc_x86_static_tls_bootstrap' "$rcrt_disassembly" ||
    fail "rcrt1.o lacks the libc TLS-bootstrap handoff relocation"
if grep -Eq 'x86_64_static_tls|install_initial_static_tls|arch_set_fs' "$rcrt_symbols" "$rcrt_disassembly"; then
    fail "rcrt1.o retains a duplicate TLS materializer"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=pic -C code-model=small -C panic=abort -Ztls-model=initial-exec
[ -f "$archive" ] || fail "cargo did not emit the PIC x86 libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
assert_static_startup_weak_fallback_owner "$archive"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap __libc_start_main \
    _exit exit atexit __cxa_atexit __cxa_finalize __funcs_on_exit pthread_create pthread_join; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'FUNC +WEAK +DEFAULT +.*__init_ssp$' "$archive_elf_symbols" ||
    fail 'archive lost musl weak __init_ssp binding'
grep -Eq 'FUNC +WEAK +DEFAULT +.*__stdio_exit$' "$archive_elf_symbols" ||
    fail 'archive lost musl weak __stdio_exit binding'
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "libc TLS bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
if ! grep -Eq 'R_X86_64_(GOTTPOFF|TPOFF(32|64)?)' "$archive_relocations"; then
    tls_relocations="$(grep -E 'R_X86_64_.*(TLS|TPOFF)' "$archive_relocations" | sed -n '1,16p' || true)"
    fail "PIC archive lacks an initial static-TLS relocation form: ${tls_relocations@Q}"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    archive_violation="$(grep -E 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
        "$archive_relocations" "$archive_disassembly" | sed -n '1,16p' || true)"
    fail "PIC archive selects a resolver TLS path or unowned runtime dependency: ${archive_violation@Q}"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_CANDIDATE \
    -fPIE -ffreestanding -fno-builtin -fno-stack-protector \
    -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_crt_static_tls_probe.c -o "$probe_object"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_CANDIDATE \
    -DCRABC_STATIC_SSP_OVERRIDE -fPIE -ffreestanding -fno-builtin \
    -fno-stack-protector -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_crt_static_tls_probe.c -o "$ssp_override_probe_object"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_CRT_STATIC_TLS_CANDIDATE \
    -DCRABC_STATIC_STDIO_EXIT_OVERRIDE -fPIE -ffreestanding -fno-builtin \
    -fno-stack-protector -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_crt_static_tls_probe.c -o "$stdio_exit_override_probe_object"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fPIE -ffreestanding -fno-builtin \
    -fno-stack-protector -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_crt_static_tls_peer.c -o "$peer_object"

if "$link_editor" -pie -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    "$crt_dir/rcrt1.o" "$crt_dir/crti.o" "$probe_object" "$peer_object" \
    "$crt_dir/crtn.o" -o "$candidate_without_archive" >"$without_archive_log" 2>&1; then
    fail "rcrt1 static PIE linked without the required libc archive"
fi
grep -Fq '__crabc_x86_static_tls_bootstrap' "$without_archive_log" ||
    fail "no-archive link did not fail at the libc TLS-bootstrap boundary"
grep -Fq '__libc_start_main' "$without_archive_log" ||
    fail "no-archive link did not fail at the libc startup boundary"

"$link_editor" -pie -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    "$crt_dir/rcrt1.o" "$crt_dir/crti.o" "$probe_object" "$peer_object" \
    "$archive" "$crt_dir/crtn.o" -o "$candidate"
"$link_editor" -pie -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    "$crt_dir/rcrt1.o" "$crt_dir/crti.o" "$ssp_override_probe_object" "$peer_object" \
    "$archive" "$crt_dir/crtn.o" -o "$candidate_ssp_override"
"$link_editor" -pie -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    "$crt_dir/rcrt1.o" "$crt_dir/crti.o" "$stdio_exit_override_probe_object" "$peer_object" \
    "$archive" "$crt_dir/crtn.o" -o "$candidate_stdio_exit_override"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --symbols --wide "$candidate_ssp_override" >"$candidate_ssp_override_symbols"
readelf --symbols --wide "$candidate_stdio_exit_override" >"$candidate_stdio_exit_override_symbols"
readelf --file-header --wide "$candidate" >"$candidate_file_header"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=__crabc_x86_64_static_pie_start "$candidate" >"$candidate_startup_disassembly"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"

relative_slot_for_function() {
    local function_name="$1"
    local function_value function_addend
    local -a matching_slots

    function_value="$(awk -v function_name="$function_name" \
        '$4 == "FUNC" && $NF == function_name { print $2; exit }' "$candidate_symbols")"
    [ -n "$function_value" ] || fail "candidate has no function symbol for ${function_name}"
    function_addend="$(printf '%x' "0x${function_value}")"
    mapfile -t matching_slots < <(
        awk -v function_addend="$function_addend" \
            'tolower($3) == "r_x86_64_relative" && tolower($4) == tolower(function_addend) { print $1 }' \
            "$candidate_relocations"
    )
    [ "${#matching_slots[@]}" = 1 ] ||
        fail "candidate does not retain one RELATIVE call slot for ${function_name}"
    printf '%x\n' "0x${matching_slots[0]}"
}

bootstrap_slot="$(relative_slot_for_function __crabc_x86_static_tls_bootstrap)"
lifecycle_slot="$(relative_slot_for_function __libc_start_main)"
bootstrap_call_pattern="call.*# (0x)?0*${bootstrap_slot}([[:space:]]|<)"
lifecycle_call_pattern="call.*# (0x)?0*${lifecycle_slot}([[:space:]]|<)"
grep -Eq "$bootstrap_call_pattern" "$candidate_startup_disassembly" ||
    fail "CRT startup does not call libc through its RELATIVE TLS-bootstrap slot"
grep -Eq "$lifecycle_call_pattern" "$candidate_startup_disassembly" ||
    fail "CRT startup does not enter libc startup through its RELATIVE slot"
bootstrap_line="$(grep -nE "$bootstrap_call_pattern" "$candidate_startup_disassembly" | head -n 1 | cut -d: -f1)"
lifecycle_line="$(grep -nE "$lifecycle_call_pattern" "$candidate_startup_disassembly" | head -n 1 | cut -d: -f1)"
if [ -z "$bootstrap_line" ] || [ -z "$lifecycle_line" ] ||
    (( bootstrap_line >= lifecycle_line )); then
    fail "CRT enters libc startup before it installs initial TLS"
fi

for symbol in __crabc_x86_static_tls_bootstrap __crabc_x86_64_static_pie_start \
    __libc_start_main _exit exit atexit __cxa_atexit __cxa_finalize __funcs_on_exit \
    pthread_create pthread_join main; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
grep -Eq 'FUNC +WEAK +DEFAULT +.*__init_ssp$' "$candidate_symbols" ||
    fail 'candidate lost musl weak __init_ssp binding'
grep -Eq 'FUNC +WEAK +DEFAULT +.*__stdio_exit$' "$candidate_symbols" ||
    fail 'candidate lost musl weak __stdio_exit binding'
awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "__libc_start_main" { found=1 } END { exit found ? 0 : 1 }' \
    "$candidate_ssp_override_symbols" ||
    fail 'caller override did not extract the archive static-startup member'
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__init_ssp$' "$candidate_ssp_override_symbols" ||
    fail 'caller strong __init_ssp did not override the archive weak binding'
if grep -Eq 'FUNC +WEAK +DEFAULT +.*__init_ssp$' "$candidate_ssp_override_symbols"; then
    fail 'caller override retained the archive weak __init_ssp binding'
fi
awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "__libc_start_main" { found=1 } END { exit found ? 0 : 1 }' \
    "$candidate_stdio_exit_override_symbols" ||
    fail 'stdio-exit caller override did not extract the archive static-startup member'
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__stdio_exit$' "$candidate_stdio_exit_override_symbols" ||
    fail 'caller strong __stdio_exit did not override the archive weak binding'
if grep -Eq 'FUNC +WEAK +DEFAULT +.*__stdio_exit$' "$candidate_stdio_exit_override_symbols"; then
    fail 'caller override retained the archive weak __stdio_exit binding'
fi
if grep -Eq 'GLOBAL +DEFAULT +.*__crabc_x86_static_tls_bootstrap$' "$candidate_symbols"; then
    fail "candidate exposes a preemptible TLS-bootstrap boundary"
fi
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
assert_final_static_pie
if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT)' "$candidate_relocations"; then
    fail "candidate retains a non-relative dynamic relocation"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct x86 initial TLS"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$candidate_disassembly" ||
    fail "candidate lacks raw static-TLS syscalls"
grep -Eq '\$0x9e(,|[[:space:]]|$)' "$candidate_disassembly" ||
    fail "candidate lacks arch_prctl syscall 158"

if candidate_output="$($candidate)"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi
[ "$candidate_output" = PIMBCAF ] ||
    fail "candidate lifecycle output is ${candidate_output@Q}, not PIMBCAF"
if candidate_ssp_override_output="$($candidate_ssp_override)"; then
    :
else
    candidate_status=$?
    fail "static SSP-override candidate execution exited ${candidate_status}"
fi
[ "$candidate_ssp_override_output" = PIMBCAF ] ||
    fail "static SSP-override candidate lifecycle output is ${candidate_ssp_override_output@Q}, not PIMBCAF"
if candidate_stdio_exit_override_output="$($candidate_stdio_exit_override)"; then
    :
else
    candidate_status=$?
    fail "static stdio-exit-override candidate exited ${candidate_status}"
fi
[ "$candidate_stdio_exit_override_output" = PIMBCAF ] ||
    fail "static stdio-exit-override candidate lifecycle output is ${candidate_stdio_exit_override_output@Q}, not PIMBCAF"

candidate_phoff="$(od -An -tu8 -j "$ELF64_PROGRAM_HEADER_OFFSET" -N 8 "$candidate" | tr -d '[:space:]')"
candidate_phnum="$(od -An -tu2 -j "$ELF64_PROGRAM_HEADER_COUNT_OFFSET" -N 2 "$candidate" | tr -d '[:space:]')"
if [ -z "$candidate_phoff" ] || [ -z "$candidate_phnum" ] ||
    (( candidate_phnum == 0 || candidate_phnum > 128 )); then
    fail "candidate has invalid ELF64 program-header metadata"
fi
tls_header_index=""
for ((header_index = 0; header_index < candidate_phnum; header_index += 1)); do
    header_offset=$((candidate_phoff + header_index * ELF64_PROGRAM_HEADER_SIZE))
    header_type="$(od -An -tu4 -j "$header_offset" -N 4 "$candidate" | tr -d '[:space:]')"
    if [ "$header_type" = 7 ]; then
        tls_header_index="$header_index"
        break
    fi
done
[ -n "$tls_header_index" ] || fail "candidate has no PT_TLS program header to mutate"
tls_filesz_offset=$((candidate_phoff + tls_header_index * ELF64_PROGRAM_HEADER_SIZE + ELF64_P_FILESZ_OFFSET))
cp "$candidate" "$bad_tls_filesz"
printf '\377\377\377\377\377\377\377\377' | dd of="$bad_tls_filesz" bs=1 \
    seek="$tls_filesz_offset" conv=notrunc status=none
expect_bootstrap_rejection "$bad_tls_filesz"

printf 'x86 real rcrt1 -> libc Static Initial TLS v1: PASS\n'
